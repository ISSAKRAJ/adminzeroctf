// LAYER 1: Rate Limiter
// Limits abuse by IP address.
// Fully proxy-aware for cloud platforms (Render, Railway, Fly.io, Cloudflare).

const rateLimit = require("express-rate-limit");

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded && typeof forwarded === "string") {
    // The first IP in the X-Forwarded-For chain is the real client IP
    const clientIp = forwarded.split(",")[0].trim();
    if (clientIp) return clientIp;
  }
  return req.ip || req.socket?.remoteAddress || "127.0.0.1";
}

const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 requests per minute per IP (enough for human exploration, blocks aggressive flood)
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false, xForwardedForHeader: false },
  keyGenerator: (req) => getClientIp(req),
  message: {
    blocked: true,
    reason: "LAYER_1_RATE_LIMIT",
    message: "Rate limit reached (30 requests/min). Please slow down."
  }
});

module.exports = limiter;
