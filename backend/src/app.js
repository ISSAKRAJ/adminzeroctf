require("dotenv").config();
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
const { initTelemetryDB, logCTFAttempt, getCTFStats } = require("./telemetryDb");

const app = express();

// Trust reverse proxy headers (Render, Railway, Fly.io, Cloudflare)
app.set("trust proxy", true);

// ─── Startup Configuration ───────────────────────────────────────────────────
const CTF_FLAG = (process.env.CTF_FLAG || "ADMINZERO_CTF{AST_1s_th3_l4st_W4ll_y0u_w1ll_3v3r_s33}").trim();
if (!process.env.CTF_FLAG) {
  console.warn("⚠️  [ADMINZERO] CTF_FLAG not set in env. Using default challenge flag.");
}

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
  allowedHeaders: ["Content-Type", "X-Challenge-Token", "Authorization"],
  exposedHeaders: ["X-Next-Token"],
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

function jitter(minMs = 60, maxMs = 250) {
  return new Promise(resolve =>
    setTimeout(resolve, minMs + Math.floor(Math.random() * (maxMs - minMs)))
  );
}

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.json({
    name: "AdminZero CTF",
    version: "3.0.0",
    status: "ARMED",
    layers: 12,
    message: "POST your SQL to /v1/ctf/query. Good luck."
  });
});

// ─── Core Query Controller ───────────────────────────────────────────────────
async function processQuery(req, res, { isCtfEndpoint = false } = {}) {
  const ip = getClientIp(req);
  const { query, hacker_alias } = req.body || {};
  const reqId = uuidv4().split("-")[0].toUpperCase();
  const challengeToken = req.headers["x-challenge-token"];
  const alias = (typeof hacker_alias === "string" ? hacker_alias.trim().substring(0, 50) : "Anonymous");

  // Helper to respond with block and always attach a fresh token for recovery
  const respondBlocked = async (status, reason, detail) => {
    recordBlock(ip);
    logAttempt(ip, query || "", true, reason);
    if (isCtfEndpoint) {
      logCTFAttempt(alias, query || "", query || "", reason, false);
    }
    await jitter();
    const nextToken = issueToken(ip, reqId);
    res.setHeader("X-Next-Token", nextToken);
    return res.status(status).json({
      blocked: true,
      reqId,
      nextToken,
      reason: safeReason(reason),
      detail: isProd ? undefined : detail
    });
  };

  try {
    // ─── LAYER 10: Behavioral Guard (Pre-check) ─────────────────────────────
    const tier = getTier(ip);

    if (tier >= 3) {
      return respondBlocked(403, "BEHAVIORAL_HARD_BAN");
    }

    if (tier >= 2) {
      await jitter(1500, 2000);
      logAttempt(ip, query || "[shadow]", false, "SHADOW_BAN_RESPONSE");
      if (isCtfEndpoint) {
        logCTFAttempt(alias, query || "", query || "", "BLOCKED_BY_SHADOW_BAN", false);
      }
      const nextToken = issueToken(ip, reqId);
      res.setHeader("X-Next-Token", nextToken);
      const shadowData = getShadowResponse(ip, reqId);
      return res.status(200).json({ ...shadowData, nextToken });
    }

    // ─── LAYER 11: Challenge Token Validation (MUST run BEFORE issueToken) ──
    const challengeCheck = validateToken(ip, challengeToken);
    if (!challengeCheck.valid) {
      return respondBlocked(403, challengeCheck.reason || "LAYER_11_CHALLENGE_FAILED");
    }

    // Now issue the next challenge token for subsequent query
    const nextToken = issueToken(ip, reqId);
    res.setHeader("X-Next-Token", nextToken);

    // ─── LAYER 0: Input Sanitization ─────────────────────────────────────────
    if (!query || typeof query !== "string") {
      return respondBlocked(400, "LAYER_0: No query provided.");
    }

    if (query.length > 500) {
      return respondBlocked(400, "LAYER_0: Query exceeds 500 characters.");
    }

    if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(query)) {
      return respondBlocked(400, "LAYER_0: Query contains forbidden control characters.");
    }

    // ─── LAYER 12: Query Normalization ───────────────────────────────────────
    const normalizedQuery = normalizeQuery(query);

    // ─── LAYER 2: Encoding Obfuscation Detection ────────────────────────────
    const enc = detectEncoding(normalizedQuery);
    if (enc.detected) {
      return respondBlocked(400, enc.reason);
    }

    // ─── LAYER 3: Keyword & Injection Blacklist ──────────────────────────────
    const bl = checkBlacklist(normalizedQuery);
    if (bl.blocked) {
      return respondBlocked(403, bl.reason);
    }

    // ─── LAYERS 4, 5, 6, 7, 9: AST Guard ────────────────────────────────────
    let ast;
    try {
      ast = validateAST(normalizedQuery);
    } catch (parseErr) {
      return respondBlocked(403, "LAYER_5_PARSE_FAIL: Malformed query AST.", parseErr.message);
    }

    if (!ast.valid) {
      return respondBlocked(403, ast.reason);
    }

    // ─── Execution Phase (Reconstructed SQL Only) ────────────────────────────
    const rawRows = runSafeQuery(ast.safeQuery);
    const rows = scrubRows(rawRows);

    // Flag capture verification
    const jsonResult = JSON.stringify(rows);
    const capturedFlag = jsonResult.includes(CTF_FLAG) || jsonResult.includes("AZ_FLAG{w3lc0m3_t0_th3_d4rk_s1d3}");

    logAttempt(ip, query, false, "PASSED_ALL_LAYERS");
    if (isCtfEndpoint) {
      logCTFAttempt(alias, query, ast.safeQuery, "EXECUTED", capturedFlag);
    }

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
      reqId,
      layers_passed: 12,
      tables: ast.tables,
      rows,
      nextToken,
      message: "Query cleared all AdminZero security layers."
    });

  } catch (err) {
    return respondBlocked(500, "EXEC_ERROR", err.message);
  }
}

// ─── Endpoints ───────────────────────────────────────────────────────────────
app.post("/query", limiter, (req, res) => processQuery(req, res, { isCtfEndpoint: false }));
app.post("/v1/ctf/query", limiter, (req, res) => processQuery(req, res, { isCtfEndpoint: true }));

app.get("/v1/ctf/stats", (req, res) => {
  res.json(getCTFStats());
});

app.get("/v1/ctf/logs", (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
  res.json(getAuditLogs(limit));
});

// 404
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found." });
});

// Global Error Handler (Prevents HTML 500 crashes)
app.use((err, req, res, next) => {
  console.error("Unhandled Server Error:", err.message);
  res.status(500).json({ blocked: true, error: "Internal server error." });
});

module.exports = app;
