// ─── Vercel Serverless Entry Point ────────────────────────────────────────────
// Vercel calls this file as a serverless function for ALL routes.
// It wraps the Express app using serverless-http so the app runs without
// binding a port — exactly what Vercel's runtime expects.
//
// Local dev: still use `node backend/src/index.js` (which calls app.listen).
// Production (Vercel): this file is the handler.

const serverless = require("serverless-http");
const app = require("../backend/src/app");

module.exports = serverless(app);
