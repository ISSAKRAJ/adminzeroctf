const Database = require("better-sqlite3");
const path = require("path");

const telemetryDb = new Database(path.join(__dirname, "../telemetry.db"));

function initTelemetryDB() {
  telemetryDb.exec(`
    CREATE TABLE IF NOT EXISTS ctf_attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      hacker_alias TEXT,
      prompt TEXT,
      generated_sql TEXT,
      waf_status TEXT,
      captured_flag BOOLEAN DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

function logCTFAttempt(hackerAlias, prompt, generatedSql, wafStatus, capturedFlag) {
  try {
    telemetryDb.prepare(
      "INSERT INTO ctf_attempts (hacker_alias, prompt, generated_sql, waf_status, captured_flag) VALUES (?, ?, ?, ?, ?)"
    ).run(hackerAlias || "Anonymous", prompt, generatedSql, wafStatus, capturedFlag ? 1 : 0);
  } catch (err) {
    console.error("Telemetry Logging Error:", err.message);
  }
}

function getCTFStats() {
  try {
    const totalBlocked = telemetryDb.prepare("SELECT COUNT(*) as count FROM ctf_attempts WHERE captured_flag = 0").get().count;
    const bypasses = telemetryDb.prepare("SELECT COUNT(*) as count FROM ctf_attempts WHERE captured_flag = 1").get().count;
    return {
      total_attacks_blocked: totalBlocked,
      successful_bypasses: bypasses,
      bounty_payout: bypasses === 0 ? '$1,000' : 'CLAIMED'
    };
  } catch (err) {
    console.error("Telemetry Stats Error:", err.message);
    return { total_attacks_blocked: 0, successful_bypasses: 0, bounty_payout: '$1,000' };
  }
}

module.exports = { initTelemetryDB, logCTFAttempt, getCTFStats };
