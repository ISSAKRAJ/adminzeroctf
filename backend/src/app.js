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

// ─── Startup Guard ────────────────────────────────────────────────────────────
if (!process.env.CTF_FLAG) {
  console.error("❌ [ADMINZERO] FATAL: CTF_FLAG environment variable is not set.");
  process.exit(1);
}

// Init DB
initDB();
initTelemetryDB();

// ─── Security Headers ─────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'none'"],
      frameSrc:   ["'none'"],
      objectSrc:  ["'none'"],
    },
  },
  hidePoweredBy: true,
  noSniff: true,
}));

const allowedOrigin = process.env.FRONTEND_URL;
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || process.env.NODE_ENV !== "production") return callback(null, true);
    if (allowedOrigin && origin === allowedOrigin) return callback(null, true);
    callback(new Error("CORS: Origin not allowed"));
  },
  methods: ["POST", "GET"],
  allowedHeaders: ["Content-Type", "X-Challenge-Token"],
  exposedHeaders: ["X-Next-Token"],
}));

app.use(express.json({ limit: "2kb" }));

// ─── Error Sanitizer ─────────────────────────────────────────────────────────
const isProd = process.env.NODE_ENV === "production";

function safeReason(reason) {
  if (isProd) return "QUERY_REJECTED";
  return reason;
}

// ─── Timing Jitter ────────────────────────────────────────────────────────────
// Adds a random delay to ALL responses (pass AND fail) to defeat timing attacks.
// Attackers cannot infer which layer rejected them from response time.
function jitter(minMs = 80, maxMs = 350) {
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
    message: "POST your SQL to /query. Include X-Challenge-Token from the previous response. Good luck."
  });
});

// ─── Main Challenge Endpoint ─────────────────────────────────────────────────
app.post("/query", limiter, async (req, res) => {
  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress;
  const { query } = req.body;
  const reqId = uuidv4().split("-")[0].toUpperCase();
  const challengeToken = req.headers["x-challenge-token"];

  // ─── LAYER 10: Behavioral tier check (pre-everything) ──────────────────────
  const tier = getTier(ip);

  // Hard ban — tier 3
  if (tier >= 3) {
    return res.status(403).json({ blocked: true, reqId, reason: "BEHAVIORAL_HARD_BAN" });
  }

  // Shadow ban — tier 2: return convincing fake data, log the attempt
  if (tier >= 2) {
    await jitter(2000, 2100);
    logAttempt(ip, query || "[shadow]", false, "SHADOW_BAN_RESPONSE");
    return res.status(200).json(getShadowResponse(ip, reqId));
  }

  // ─── LAYER 11: Challenge token validation ──────────────────────────────────
  const challengeCheck = validateToken(ip, challengeToken);
  if (!challengeCheck.valid) {
    await jitter();
    recordBlock(ip);
    logAttempt(ip, query || "", true, challengeCheck.reason);
    return res.status(403).json({ blocked: true, reqId, reason: safeReason(challengeCheck.reason) });
  }

  // ─── LAYER 0: Basic input validation ──────────────────────────────────────
  if (!query || typeof query !== "string") {
    await jitter();
    return res.status(400).json({ blocked: true, reqId, reason: safeReason("LAYER_0: No query provided.") });
  }

  if (query.length > 300) {
    logAttempt(ip, query, true, "QUERY_TOO_LONG");
    await jitter();
    recordBlock(ip);
    return res.status(400).json({ blocked: true, reqId, reason: safeReason("LAYER_0: Query too long.") });
  }

  // Control characters
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(query)) {
    logAttempt(ip, query, true, "CONTROL_CHARS");
    await jitter();
    recordBlock(ip);
    return res.status(400).json({ blocked: true, reqId, reason: safeReason("LAYER_0: Invalid characters.") });
  }

  // ─── LAYER 12: Query normalization ────────────────────────────────────────
  // Normalize FIRST — strip homoglyphs, zero-width chars, collapse whitespace.
  // All subsequent layers operate on the normalized form.
  const normalizedQuery = normalizeQuery(query);

  // ─── LAYER 2: Encoding detection (on normalized query) ────────────────────
  const enc = detectEncoding(normalizedQuery);
  if (enc.detected) {
    logAttempt(ip, query, true, enc.reason);
    await jitter();
    recordBlock(ip);
    return res.status(400).json({
      blocked: true,
      reqId,
      reason: "INPUT_OBFUSCATION_BLOCKED",
    });
  }

  // ─── LAYER 3: Keyword blacklist (on normalized query) ─────────────────────
  const bl = checkBlacklist(normalizedQuery);
  if (bl.blocked) {
    logAttempt(ip, query, true, bl.reason);
    await jitter();
    recordBlock(ip);
    return res.status(403).json({
      blocked: true,
      reqId,
      reason: "CRITICAL risk score",
    });
  }

  // ─── LAYERS 4/5/6/7/9: AST Guard ─────────────────────────────────────────
  // Passes normalized query — original user string is never used in DB
  const ast = validateAST(normalizedQuery);
  if (!ast.valid) {
    logAttempt(ip, query, true, ast.reason);
    await jitter();
    recordBlock(ip);
    return res.status(403).json({
      blocked: true,
      reqId,
      reason: ast.reason === "Depth limit exceeded" ? ast.reason : safeReason(ast.reason),
    });
  }

  // ─── All layers passed — execute the reconstructed query ──────────────────
  try {
    const rawRows = runSafeQuery(ast.safeQuery);

    // LAYER 8: PII Scrubber
    const rows = scrubRows(rawRows);

    // Apply tier 1 penalty delay (repeated failures but not yet shadow-banned)
    const delay = getPenaltyDelayMs(tier);
    if (delay > 0) await new Promise(r => setTimeout(r, delay));
    else await jitter(50, 200); // baseline jitter for passing queries

    logAttempt(ip, query, false, "PASSED_ALL_LAYERS");
    recordPass(ip);

    // Issue next challenge token and attach to response header
    const nextToken = issueToken(ip, reqId);
    res.setHeader("X-Next-Token", nextToken);

    return res.json({
      blocked: false,
      reqId,
      layers_passed: 12,
      tables: ast.tables,
      rows,
      nextToken, // Also in body for clients that can't read headers
      message: "Query passed all 12 AdminZero security layers."
    });

  } catch (err) {
    logAttempt(ip, query, true, `EXEC_ERROR: ${err.message}`);
    await jitter();
    recordBlock(ip);
    return res.status(500).json({
      blocked: true,
      reqId,
      reason: safeReason("EXEC_ERROR"),
      detail: isProd ? undefined : err.message
    });
  }
});

// ─── CTF Stats Endpoint ──────────────────────────────────────────────────────
app.get("/v1/ctf/stats", (req, res) => {
  res.json(getCTFStats());
});

// ─── CTF Logs Endpoint (Admin) ───────────────────────────────────────────────
app.get("/v1/ctf/logs", (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 100;
  res.json(getAuditLogs(limit));
});

// ─── CTF Honeypot Endpoint ───────────────────────────────────────────────────
app.post("/v1/ctf/query", limiter, async (req, res) => {
  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress;
  const { query, hacker_alias } = req.body;
  const reqId = uuidv4().split("-")[0].toUpperCase();
  const challengeToken = req.headers["x-challenge-token"];
  
  // Using query for both prompt and generatedSql since we skip Gemini integration
  const prompt = query || "";
  const generatedSql = query || "";

  const tier = getTier(ip);

  if (tier >= 3) {
    logCTFAttempt(hacker_alias, prompt, generatedSql, "BLOCKED_BY_BEHAVIORAL_HARD_BAN", false);
    return res.status(403).json({ blocked: true, reqId, reason: "BEHAVIORAL_HARD_BAN" });
  }

  if (tier >= 2) {
    await jitter(2000, 2100);
    logCTFAttempt(hacker_alias, prompt, generatedSql, "BLOCKED_BY_SHADOW_BAN", false);
    return res.status(200).json(getShadowResponse(ip, reqId));
  }

  const challengeCheck = validateToken(ip, challengeToken);
  if (!challengeCheck.valid) {
    await jitter();
    recordBlock(ip);
    logCTFAttempt(hacker_alias, prompt, generatedSql, "BLOCKED_BY_CHALLENGE_TOKEN", false);
    return res.status(403).json({ blocked: true, reqId, reason: safeReason(challengeCheck.reason) });
  }

  if (!query || typeof query !== "string") {
    await jitter();
    logCTFAttempt(hacker_alias, prompt, generatedSql, "BLOCKED_BY_L0", false);
    return res.status(400).json({ blocked: true, reqId, reason: safeReason("LAYER_0: No query provided.") });
  }

  if (query.length > 300) {
    await jitter();
    recordBlock(ip);
    logCTFAttempt(hacker_alias, prompt, generatedSql, "BLOCKED_BY_L0", false);
    return res.status(400).json({ blocked: true, reqId, reason: safeReason("LAYER_0: Query too long.") });
  }

  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(query)) {
    await jitter();
    recordBlock(ip);
    logCTFAttempt(hacker_alias, prompt, generatedSql, "BLOCKED_BY_L0", false);
    return res.status(400).json({ blocked: true, reqId, reason: safeReason("LAYER_0: Invalid characters.") });
  }

  const normalizedQuery = normalizeQuery(query);

  const enc = detectEncoding(normalizedQuery);
  if (enc.detected) {
    await jitter();
    recordBlock(ip);
    logCTFAttempt(hacker_alias, prompt, generatedSql, "BLOCKED_BY_L2", false);
    return res.status(400).json({ blocked: true, reqId, reason: "INPUT_OBFUSCATION_BLOCKED" });
  }

  const bl = checkBlacklist(normalizedQuery);
  if (bl.blocked) {
    await jitter();
    recordBlock(ip);
    logCTFAttempt(hacker_alias, prompt, generatedSql, "BLOCKED_BY_PROMPT_GUARD", false);
    return res.status(403).json({ blocked: true, reqId, reason: "CRITICAL risk score" });
  }

  const ast = validateAST(normalizedQuery);
  if (!ast.valid) {
    await jitter();
    recordBlock(ip);
    logCTFAttempt(hacker_alias, prompt, generatedSql, "BLOCKED_BY_AST", false);
    return res.status(403).json({ blocked: true, reqId, reason: ast.reason === "Depth limit exceeded" ? ast.reason : safeReason(ast.reason) });
  }

  try {
    const rawRows = runSafeQuery(ast.safeQuery);
    const rows = scrubRows(rawRows);
    
    // Flag check
    const jsonString = JSON.stringify(rows);
    const capturedFlag = jsonString.includes("AZ_FLAG{w3lc0m3_t0_th3_d4rk_s1d3}") || (process.env.CTF_FLAG && jsonString.includes(process.env.CTF_FLAG));
    
    logCTFAttempt(hacker_alias, prompt, generatedSql, "EXECUTED", capturedFlag);

    const delay = getPenaltyDelayMs(tier);
    if (delay > 0) await new Promise(r => setTimeout(r, delay));
    else await jitter(50, 200);

    recordPass(ip);
    const nextToken = issueToken(ip, reqId);
    res.setHeader("X-Next-Token", nextToken);

    return res.json({
      blocked: false,
      reqId,
      layers_passed: 12,
      tables: ast.tables,
      rows,
      nextToken,
      message: "Query passed all 12 AdminZero security layers."
    });

  } catch (err) {
    await jitter();
    recordBlock(ip);
    logCTFAttempt(hacker_alias, prompt, generatedSql, "EXEC_ERROR", false);
    return res.status(500).json({
      blocked: true,
      reqId,
      reason: safeReason("EXEC_ERROR"),
      detail: isProd ? undefined : err.message
    });
  }
});

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: "Not found." });
});

module.exports = app;
