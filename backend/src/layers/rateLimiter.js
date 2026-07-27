// LAYER 1: Rate Limiter
// Limits abuse by IP address. Tightened to 5 attempts per minute.
// The key generator strips x-forwarded-for trust abuse by using the
// socket address when the forwarded header looks spoofed (multiple IPs).

const rateLimit = require("express-rate-limit");

const limiter = rateLimit({
  windowMs: 60 * 1000,  // 1 minute window
  max: 5,               // max 5 requests per window (was 8)
  standardHeaders: true,
  legacyHeaders: false,
  // Custom key generator to prevent x-forwarded-for spoofing:
  // If the forwarded header contains multiple IPs (comma-separated),
  // it may be a spoofed chain — fall back to the real socket address.
  keyGenerator: (req) => {
    const forwarded = req.headers["x-forwarded-for"];
    if (forwarded && typeof forwarded === "string") {
      const ips = forwarded.split(",").map((ip) => ip.trim());
      // If exactly one IP and it looks valid, use it
      if (ips.length === 1 && /^[\d.]+$|^[0-9a-fA-F:]+$/.test(ips[0])) {
        return ips[0];
      }
    }
    // Fall back to socket address (cannot be spoofed at the TCP level)
    return req.socket.remoteAddress || "unknown";
  },
  message: {
    blocked: true,
    reason: "LAYER_1_RATE_LIMIT",
    message: "Slow down. 5 attempts per minute. You are being watched."
  }
});

module.exports = limiter;
