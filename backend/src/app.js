require("dotenv").config();
const path = require("path");
const fs = require("fs");
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");

const limiter = require("./layers/rateLimiter");
const { detectEncoding } = require("./layers/encodingDetector");
const { checkBlacklist } = require("./layers/keywordBlacklist");
const { validateAST } = require("./astGuard");
const { scrubRows } = require("./layers/piiScrubber");
const { normalizeQuery } = require("./layers/queryNormalizer");
const { recordBlock, recordPass, getTier, getShadowResponse, getPenaltyDelayMs } = require("./layers/behaviorGuard");
const { issueToken, validateToken } = require("./layers/challengeToken");
const { initDB, logAttempt, getAuditLogs, runSafeQuery } = require("./db");
const {
  initTelemetryDB,
  registerHacker,
  isRegisteredHacker,
  getHackerBySession,
  getHackerByHandle,
  logAttemptRecord,
  getHallOfFame,
  getLiveFeed,
  getCTFStats,
  getAdminHackersList,
  getAdminHackerDetail,
  getAdminGlobalStats,
  exportAttemptsToCsv
} = require("./telemetryDb");

const app = express();

// Trust reverse proxy headers (Render, Railway, Fly.io, Cloudflare)
app.set("trust proxy", true);

// ─── Startup Configuration ───────────────────────────────────────────────────
const CTF_FLAG = (process.env.CTF_FLAG || "ADMINZERO_CTF{AST_1s_th3_l4st_W4ll_y0u_w1ll_3v3r_s33}").trim();
if (!process.env.CTF_FLAG) {
  console.warn("⚠️  [ADMINZERO] CTF_FLAG not set in env. Using default challenge flag.");
}

const ADMIN_SECRET = (process.env.ADMIN_SECRET || "adminzero_master_key_2026").trim();

// Init Databases (WAL mode enabled)
initDB();
initTelemetryDB();

// ─── Security Headers & CORS ─────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  hidePoweredBy: true,
  noSniff: true,
}));

// Robust CORS: Allow browser frontend from any origin (Vercel, custom domains, localhost)
app.use(cors({
  origin: true,
  credentials: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "X-Challenge-Token", "X-Session-ID", "X-Admin-Key", "Authorization"],
  exposedHeaders: ["X-Next-Token", "Content-Disposition"],
}));

app.use(express.json({ limit: "4kb" }));

// ─── Helpers ─────────────────────────────────────────────────────────────────
const isProd = process.env.NODE_ENV === "production";

function safeReason(reason) {
  if (isProd) return "QUERY_REJECTED";
  return reason;
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded && typeof forwarded === "string") {
    const clientIp = forwarded.split(",")[0].trim();
    if (clientIp) return clientIp;
  }
  return req.ip || req.socket?.remoteAddress || "127.0.0.1";
}

function jitter(minMs = 50, maxMs = 200) {
  return new Promise(resolve =>
    setTimeout(resolve, minMs + Math.floor(Math.random() * (maxMs - minMs)))
  );
}

function requireAdminAuth(req, res, next) {
  const token = (
    req.headers["x-admin-key"] ||
    req.headers["authorization"]?.replace(/^Bearer\s+/i, "") ||
    req.query.admin_key ||
    ""
  ).trim();

  if (!token || token !== ADMIN_SECRET) {
    return res.status(401).json({ error: "Unauthorized. Valid Admin Key required." });
  }
  next();
}

// ─── Frontend & Static Serving ────────────────────────────────────────────────
const FRONTEND_DIR = path.join(__dirname, "../../frontend");
if (fs.existsSync(FRONTEND_DIR)) {
  app.use(express.static(FRONTEND_DIR));
}

app.get("/admin", (req, res) => {
  const adminPath = path.join(FRONTEND_DIR, "admin.html");
  if (fs.existsSync(adminPath)) {
    return res.sendFile(adminPath);
  }
  res.status(404).json({ error: "Admin page not found" });
});

app.get("/about", (req, res) => {
  const aboutPath = path.join(FRONTEND_DIR, "about.html");
  if (fs.existsSync(aboutPath)) {
    return res.sendFile(aboutPath);
  }
  res.redirect("/");
});

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({
    name: "AdminZero CTF",
    version: "3.2.0",
    status: "ARMED",
    layers: 12,
    message: "POST your SQL to /v1/ctf/query. Good luck."
  });
});

app.get("/", (req, res) => {
  const indexPath = path.join(FRONTEND_DIR, "index.html");
  if (fs.existsSync(indexPath) && (!req.headers.accept || req.headers.accept.includes("text/html"))) {
    return res.sendFile(indexPath);
  }
  res.json({
    name: "AdminZero CTF",
    version: "3.2.0",
    status: "ARMED",
    layers: 12,
    message: "POST your SQL to /v1/ctf/query. Good luck."
  });
});

// ─── Core Query Controller ───────────────────────────────────────────────────
async function processQuery(req, res, { isCtfEndpoint = false } = {}) {
  const ip = getClientIp(req);
  const { query, hacker_alias, session_id } = req.body || {};
  const reqId = uuidv4().split("-")[0].toUpperCase();
  const challengeToken = req.headers["x-challenge-token"];
  const clientSessionId = req.headers["x-session-id"] || session_id || null;
  const alias = (typeof hacker_alias === "string" ? hacker_alias.trim().substring(0, 50) : null);

  // ─── Mandatory Enlistment Gate ──────────────────────────────────────────────
  // Challengers must register their identity before attacking the 12-layer wall
  const isRegistered = isRegisteredHacker(clientSessionId, alias);
  if (!isRegistered) {
    return res.status(401).json({
      blocked: true,
      registration_required: true,
      error: "REGISTRATION_REQUIRED",
      message: "Access Denied: You must register a hacker identity before attacking the 12-layer wall."
    });
  }

  // Helper to record attempt and respond with block
  const respondBlocked = async (status, layerTargeted, reason, detail) => {
    recordBlock(ip);
    logAttempt(ip, query || "", true, reason);

    const logResult = logAttemptRecord({
      handle: alias,
      session_id: clientSessionId,
      ip,
      layer_targeted: layerTargeted,
      payload: query,
      response_code: status,
      blocked: true,
      bypassed: false,
      captured_flag: false
    });

    await jitter();
    const nextToken = issueToken(ip, reqId);
    res.setHeader("X-Next-Token", nextToken);

    return res.status(status).json({
      blocked: true,
      reqId,
      nextToken,
      layer_targeted: layerTargeted,
      points_awarded: 0,
      reason: safeReason(reason),
      detail: isProd ? undefined : detail
    });
  };

  try {
    // ─── LAYER 10: Honey Canary & Behavioral Guard (Pre-check) ─────────────
    const tier = getTier(ip);

    if (tier >= 3) {
      return respondBlocked(403, "L10 Honey Canary & Behavioral Guard", "BEHAVIORAL_HARD_BAN");
    }

    if (tier >= 2) {
      await jitter(1500, 2000);
      logAttempt(ip, query || "[shadow]", false, "SHADOW_BAN_RESPONSE");

      logAttemptRecord({
        handle: alias,
        session_id: clientSessionId,
        ip,
        layer_targeted: "L10 Honey Canary & Behavioral Guard (Shadow Ban)",
        payload: query,
        response_code: 200,
        blocked: true,
        bypassed: false,
        captured_flag: false
      });

      const nextToken = issueToken(ip, reqId);
      res.setHeader("X-Next-Token", nextToken);
      const shadowData = getShadowResponse(ip, reqId);
      return res.status(200).json({ ...shadowData, nextToken, points_awarded: 0 });
    }

    // ─── LAYER 11: Challenge Token Chaining ─────────────────────────────────
    const challengeCheck = validateToken(ip, challengeToken);
    if (!challengeCheck.valid) {
      return respondBlocked(403, "L11 Challenge Token Chaining", challengeCheck.reason || "LAYER_11_CHALLENGE_FAILED");
    }

    // Fresh token for next query
    const nextToken = issueToken(ip, reqId);
    res.setHeader("X-Next-Token", nextToken);

    // ─── LAYER 4: Query Normalization & Pre-validation ──────────────────────
    if (!query || typeof query !== "string") {
      return respondBlocked(400, "L4 Query Normalizer", "LAYER_4_EMPTY: No query string provided.");
    }

    if (query.length > 500) {
      return respondBlocked(400, "L4 Query Normalizer", "LAYER_4_LENGTH: Query exceeds 500 characters limit.");
    }

    if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(query)) {
      return respondBlocked(400, "L4 Query Normalizer", "LAYER_4_CONTROL_CHARS: Query contains forbidden control characters.");
    }

    // Canonicalize whitespace, remove invisible zero-width chars and homoglyphs
    const normalizedQuery = normalizeQuery(query);

    // ─── LAYER 2: Encoding Obfuscation Detection ────────────────────────────
    const enc = detectEncoding(normalizedQuery);
    if (enc.detected) {
      return respondBlocked(400, "L2 Encoding Detect", enc.reason);
    }

    // ─── LAYER 3: Keyword & Injection Blacklist ──────────────────────────────
    const bl = checkBlacklist(normalizedQuery);
    if (bl.blocked) {
      return respondBlocked(403, "L3 Keyword Blacklist", bl.reason);
    }

    // ─── LAYERS 5, 6, 7, 8, 9: AST Analysis, Complexity & Semantic Guard ────
    let ast;
    try {
      ast = validateAST(normalizedQuery);
    } catch (parseErr) {
      return respondBlocked(403, "L5 AST Parse", "LAYER_5_PARSE_FAIL: Malformed query AST.", parseErr.message);
    }

    if (!ast.valid) {
      let layerName = "L7 Intent & Semantic";
      if (ast.reason && (ast.reason.includes("LAYER_4") || ast.reason.includes("Depth limit exceeded"))) {
        layerName = "L6 Complexity Scorer";
      } else if (ast.reason && ast.reason.includes("LAYER_5")) {
        layerName = "L5 AST Parse";
      } else if (ast.reason && ast.reason.includes("LAYER_6")) {
        layerName = "L7 Intent & Semantic";
      } else if (ast.reason && ast.reason.includes("LAYER_7")) {
        layerName = "L8 Query Reconstructor";
      } else if (ast.reason && ast.reason.includes("LAYER_9")) {
        layerName = "L9 Shannon Entropy & Tokenizer";
      }
      return respondBlocked(403, layerName, ast.reason);
    }

    // ─── Execution Phase (Reconstructed SQL Only & L12 PII Scrubbing) ────────
    const rawRows = runSafeQuery(ast.safeQuery);
    const rows = scrubRows(rawRows);

    // Flag capture verification
    const jsonResult = JSON.stringify(rows);
    const capturedFlag = jsonResult.includes(CTF_FLAG) || jsonResult.includes("AZ_FLAG{w3lc0m3_t0_th3_d4rk_s1d3}");
    const targetCategory = capturedFlag ? "FLAG_CAPTURED" : "FULL_BYPASS";

    logAttempt(ip, query, false, "PASSED_ALL_LAYERS");

    const attemptResult = logAttemptRecord({
      handle: alias,
      session_id: clientSessionId,
      ip,
      layer_targeted: targetCategory,
      payload: query,
      response_code: 200,
      blocked: false,
      bypassed: true,
      captured_flag: capturedFlag
    });

    // Behavioral forgiveness on legitimate requests
    recordPass(ip);

    const delay = getPenaltyDelayMs(tier);
    if (delay > 0) {
      await new Promise(r => setTimeout(r, delay));
    } else {
      await jitter(40, 150);
    }

    return res.json({
      blocked: false,
      bypassed: true,
      reqId,
      layers_passed: 12,
      tables: ast.tables,
      rows,
      nextToken,
      points_awarded: attemptResult.pointsAwarded,
      is_first_solver: attemptResult.isFirstSolver,
      first_solver_badge: attemptResult.firstSolverBadge,
      captured_flag: capturedFlag,
      message: capturedFlag
        ? "🏆 CONGRATULATIONS! YOU EXTRACTED THE FLAG AND BROKE THE WALL!"
        : "Query cleared all 12 AdminZero security layers."
    });

  } catch (err) {
    return respondBlocked(500, "EXEC_ERROR", "EXEC_ERROR", err.message);
  }
}

// ─── Endpoints ───────────────────────────────────────────────────────────────

// 1. Query Endpoints
app.post("/query", limiter, (req, res) => processQuery(req, res, { isCtfEndpoint: false }));
app.post("/v1/ctf/query", limiter, (req, res) => processQuery(req, res, { isCtfEndpoint: true }));

// 2. Registration Endpoint
app.post("/v1/ctf/register", (req, res) => {
  try {
    const { handle, real_name, email, role, country, github_url, linkedin_url } = req.body || {};
    const session_id = req.headers["x-session-id"] || req.body?.session_id;

    const result = registerHacker({ handle, real_name, email, role, country, github_url, linkedin_url, session_id });
    res.json({
      success: true,
      session_id: result.session_id,
      is_new: result.isNew,
      hacker: result.hacker,
      message: result.isNew
        ? `Welcome to AdminZero CTF, @${result.hacker.handle}!`
        : `Welcome back, @${result.hacker.handle}!`
    });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// 3. Hall of Fame Endpoint
app.get("/v1/ctf/hof", (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 100);
  res.json({ solvers: getHallOfFame(limit) });
});

// 4. Live Feed Endpoint (Last 20 attempts)
app.get("/v1/ctf/feed", (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 20, 50);
  res.json({ feed: getLiveFeed(limit) });
});

// 5. Global Stats Endpoint
app.get("/v1/ctf/stats", (req, res) => {
  res.json(getCTFStats());
});

// ─── Admin Endpoints (Auth Protected) ────────────────────────────────────────

// Verify Admin Key
app.post("/v1/ctf/admin/verify", (req, res) => {
  const token = (
    req.headers["x-admin-key"] ||
    req.headers["authorization"]?.replace(/^Bearer\s+/i, "") ||
    req.body?.admin_key ||
    ""
  ).trim();

  if (token && token === ADMIN_SECRET) {
    return res.json({ success: true, message: "Admin credentials verified." });
  }
  return res.status(401).json({ success: false, error: "Invalid Admin Key." });
});

// Hackers List
app.get("/v1/ctf/admin/hackers", requireAdminAuth, (req, res) => {
  const { search, date_from, date_to } = req.query;
  const hackers = getAdminHackersList({ search, date_from, date_to });
  res.json({ hackers });
});

// Hacker Detail & Full Timeline
app.get("/v1/ctf/admin/hackers/:id", requireAdminAuth, (req, res) => {
  const hackerId = parseInt(req.params.id, 10);
  if (isNaN(hackerId)) {
    return res.status(400).json({ error: "Invalid hacker ID" });
  }
  const detail = getAdminHackerDetail(hackerId);
  if (!detail) {
    return res.status(404).json({ error: "Hacker not found" });
  }
  res.json(detail);
});

// Global Admin Stats
app.get("/v1/ctf/admin/stats", requireAdminAuth, (req, res) => {
  res.json(getAdminGlobalStats());
});

// CSV Export
app.get("/v1/ctf/admin/export.csv", requireAdminAuth, (req, res) => {
  const csvData = exportAttemptsToCsv();
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", `attachment; filename="adminzero_ctf_attempts_${Date.now()}.csv"`);
  res.send(csvData);
});

// Legacy Audit Logs Endpoint
app.get("/v1/ctf/logs", (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
  res.json(getAuditLogs(limit));
});

// 404
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found." });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error("Unhandled Server Error:", err.message);
  res.status(500).json({ blocked: true, error: "Internal server error." });
});

module.exports = app;
