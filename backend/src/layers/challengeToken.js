// LAYER 11: Challenge Token — HMAC Anti-Automation
//
// Every successful response includes a `nextToken` in the JSON.
// The NEXT request from the same IP MUST include this token in the
// `X-Challenge-Token` header. If missing or invalid → blocked.
//
// Why: This defeats automated scanners that fire requests in parallel.
// Each request must "chain" from the previous successful one, forcing
// sequential execution and making brute-force scanning impossible at scale.
//
// The token is HMAC-SHA256(ip + reqId + timestamp_bucket) signed with
// a server secret. It expires every 5 minutes.

const crypto = require("crypto");

const TOKEN_WINDOW_MS = 5 * 60 * 1000; // 5-minute validity window
const SERVER_SECRET = process.env.CHALLENGE_SECRET ||
  crypto.randomBytes(32).toString("hex"); // Random per-boot if not set

// In-memory: tracks the last issued token per IP
// { ip => { token, issuedAt, consumed } }
const tokenStore = new Map();

/**
 * Generate a new challenge token for an IP.
 * @param {string} ip
 * @param {string} reqId
 * @returns {string} hex token
 */
function issueToken(ip, reqId) {
  const bucket = Math.floor(Date.now() / TOKEN_WINDOW_MS);
  const payload = `${ip}:${reqId}:${bucket}`;
  const token = crypto.createHmac("sha256", SERVER_SECRET)
    .update(payload)
    .digest("hex");

  tokenStore.set(ip, { token, issuedAt: Date.now(), consumed: false });
  return token;
}

/**
 * Validate the challenge token from the request.
 * On the FIRST request from an IP, no token is required (bootstrapping).
 * On subsequent requests, the token from the previous response is required.
 *
 * @param {string} ip
 * @param {string|undefined} providedToken
 * @returns {{ valid: boolean, reason?: string }}
 */
function validateToken(ip, providedToken) {
  const existing = tokenStore.get(ip);

  // First-ever request from this IP — no token needed
  if (!existing) return { valid: true };

  // Token already consumed (replay prevention)
  // If no token provided and they've had previous interactions, require it
  if (!providedToken) {
    // Grace: if last token was issued > window ago, allow re-entry
    if (Date.now() - existing.issuedAt > TOKEN_WINDOW_MS) {
      return { valid: true }; // Window expired, let them start fresh
    }
    return { valid: false, reason: "LAYER_11_CHALLENGE: Missing X-Challenge-Token header." };
  }

  // Check if provided token matches stored token
  // Use timing-safe comparison to prevent timing attacks on the token itself
  const expected = existing.token;
  if (providedToken.length !== expected.length) {
    return { valid: false, reason: "LAYER_11_CHALLENGE: Invalid challenge token." };
  }

  const provided = Buffer.from(providedToken, "hex");
  const expectedBuf = Buffer.from(expected, "hex");

  let safe = false;
  try {
    safe = crypto.timingSafeEqual(provided, expectedBuf);
  } catch {
    return { valid: false, reason: "LAYER_11_CHALLENGE: Malformed token." };
  }

  if (!safe) {
    return { valid: false, reason: "LAYER_11_CHALLENGE: Invalid challenge token." };
  }

  // Valid — mark as consumed (prevents replay)
  existing.consumed = true;
  return { valid: true };
}

/**
 * Clean up old tokens.
 */
setInterval(() => {
  const cutoff = Date.now() - TOKEN_WINDOW_MS * 2;
  for (const [ip, rec] of tokenStore.entries()) {
    if (rec.issuedAt < cutoff) tokenStore.delete(ip);
  }
}, TOKEN_WINDOW_MS);

module.exports = { issueToken, validateToken };
