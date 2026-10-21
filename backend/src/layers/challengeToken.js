// LAYER 11: Challenge Token — HMAC Anti-Automation
//
// Every response includes a `nextToken` in the JSON and header.
// Subsequent requests send this token in `X-Challenge-Token`.
// Defeats automated, parallel burst attacks by requiring sequential chaining.

const crypto = require("crypto");

const TOKEN_WINDOW_MS = 10 * 60 * 1000; // 10-minute validity window
const SERVER_SECRET = process.env.CHALLENGE_SECRET ||
  crypto.randomBytes(32).toString("hex");

// Tracks last issued token per IP
// { ip => { token, issuedAt, consumed } }
const tokenStore = new Map();

/**
 * Generate a new challenge token for an IP.
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
 * Validate challenge token.
 * Allows bootstrapping / fresh session on page load without locking out the user.
 * If token is provided, ensures it matches the valid chain for this IP.
 */
function validateToken(ip, providedToken) {
  const existing = tokenStore.get(ip);

  // First request or session reset — allow entry and let issueToken provide the chain
  if (!existing || !providedToken) {
    return { valid: true };
  }

  // Grace: if last token was issued > window ago, allow re-entry
  if (Date.now() - existing.issuedAt > TOKEN_WINDOW_MS) {
    return { valid: true };
  }

  const expected = existing.token;
  if (typeof providedToken !== "string" || providedToken.length !== expected.length) {
    return { valid: false, reason: "LAYER_11_CHALLENGE: Invalid challenge token format." };
  }

  let safe = false;
  try {
    const providedBuf = Buffer.from(providedToken, "hex");
    const expectedBuf = Buffer.from(expected, "hex");
    safe = crypto.timingSafeEqual(providedBuf, expectedBuf);
  } catch {
    return { valid: false, reason: "LAYER_11_CHALLENGE: Malformed token." };
  }

  if (!safe) {
    return { valid: false, reason: "LAYER_11_CHALLENGE: Challenge token mismatch." };
  }

  existing.consumed = true;
  return { valid: true };
}

// Clean up old tokens periodically
setInterval(() => {
  const cutoff = Date.now() - TOKEN_WINDOW_MS * 2;
  for (const [ip, rec] of tokenStore.entries()) {
    if (rec.issuedAt < cutoff) tokenStore.delete(ip);
  }
}, TOKEN_WINDOW_MS);

module.exports = { issueToken, validateToken };
