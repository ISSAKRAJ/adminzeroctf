// ─── Local Development Entry Point ────────────────────────────────────────────
// This file is ONLY used when running locally: `node src/index.js`
// Vercel uses `api/index.js` (serverless wrapper) instead.
// All application logic lives in app.js — this file just binds the port.

const app = require("./app");

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log(`🔒 AdminZero CTF v3.0 — Port ${PORT}`);
  console.log(`🛡️  12 security layers ARMED:`);
  console.log(`   L1:  Rate Limit (5/min, anti-spoof)`);
  console.log(`   L2:  Encoding Detection (18 patterns)`);
  console.log(`   L3:  Keyword Blacklist (SQL + Prompt Injection, 80+ patterns)`);
  console.log(`   L4:  AST Complexity Scorer (40 nodes, depth 8, fanout 12)`);
  console.log(`   L5:  AST Parse & Multi-statement block`);
  console.log(`   L6:  Intent Validation (SELECT-only, no UNION/subquery/CTE/wildcard)`);
  console.log(`   L6b: Table Whitelist (users, products ONLY)`);
  console.log(`   L6c: Column WHITELIST (closed-world, unknown = denied)`);
  console.log(`   L7:  Query Reconstruction (original string discarded)`);
  console.log(`   L8:  PII Scrubber`);
  console.log(`   L9:  Custom SQL Tokenizer (independent of parser)`);
  console.log(`   L10: Behavioral Guard (shadow ban + hard ban)`);
  console.log(`   L11: Challenge Token (HMAC, anti-automation)`);
  console.log(`   L12: Query Normalizer (homoglyphs, zero-width chars)`);
});
