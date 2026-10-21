const Database = require("better-sqlite3");
const path = require("path");

const dbPath = path.join(__dirname, "../honeypot.db");
const db = new Database(dbPath);

// Enable WAL mode for high concurrency without locking
try {
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = NORMAL");
} catch (e) {
  console.warn("⚠️ [DB] Could not set WAL mode:", e.message);
}

function initDB() {
  // Public tables — challengers can query these
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      role TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      price REAL NOT NULL,
      category TEXT NOT NULL,
      stock INTEGER DEFAULT 0
    );

    -- HONEYPOT: looks tempting, triggers alarm
    CREATE TABLE IF NOT EXISTS fake_flags (
      id INTEGER PRIMARY KEY,
      decoy TEXT
    );

    -- REAL FLAG: protected by all security layers
    CREATE TABLE IF NOT EXISTS flag_table (
      id INTEGER PRIMARY KEY,
      secret TEXT NOT NULL
    );

    -- CTF BOUNTY HONEYPOT
    CREATE TABLE IF NOT EXISTS super_secret_admin (
      id INTEGER PRIMARY KEY,
      role TEXT,
      capture_flag TEXT
    );

    -- Audit log: every attempt is recorded
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT,
      query TEXT,
      blocked INTEGER DEFAULT 1,
      reason TEXT,
      timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Seed users
  const userCount = db.prepare("SELECT COUNT(*) as c FROM users").get();
  if (userCount.c === 0) {
    const ins = db.prepare("INSERT INTO users (name, email, role) VALUES (?, ?, ?)");
    ins.run("Ravi Issak", "issak@adminzero.dev", "admin");
    ins.run("Priya Sharma", "priya@glitchgo.tech", "engineer");
    ins.run("Dev Kumar", "dev@example.com", "user");
    ins.run("Sneha Rao", "sneha@example.com", "user");
    ins.run("Arjun Nair", "arjun@example.com", "moderator");
  }

  // Seed products
  const prodCount = db.prepare("SELECT COUNT(*) as c FROM products").get();
  if (prodCount.c === 0) {
    const ins = db.prepare("INSERT INTO products (name, price, category, stock) VALUES (?, ?, ?, ?)");
    ins.run("AdminZero Pro License", 99.99, "Software", 500);
    ins.run("GlitchGo Support Pack", 49.99, "Services", 200);
    ins.run("Security Audit Report", 299.00, "Consulting", 50);
    ins.run("API Gateway Plugin", 19.99, "Software", 1000);
    ins.run("CTF T-Shirt", 14.99, "Merch", 150);
  }

  // Seed honeypot decoy
  const fakeCount = db.prepare("SELECT COUNT(*) as c FROM fake_flags").get();
  if (fakeCount.c === 0) {
    db.prepare("INSERT INTO fake_flags (decoy) VALUES (?)").run("ADMINZERO_FAKE_{n0t_th3_r34l_fl4g}");
  }

  // Seed/Sync Real Flag
  const currentFlag = (process.env.CTF_FLAG || "ADMINZERO_CTF{AST_1s_th3_l4st_W4ll_y0u_w1ll_3v3r_s33}").trim();
  db.exec("DELETE FROM flag_table;");
  db.prepare("INSERT INTO flag_table (secret) VALUES (?)").run(currentFlag);

  db.exec("DELETE FROM super_secret_admin;");
  db.prepare("INSERT INTO super_secret_admin (role, capture_flag) VALUES (?, ?)").run("super_admin", currentFlag);
}

function logAttempt(ip, query, blocked, reason) {
  try {
    db.prepare("INSERT INTO audit_log (ip, query, blocked, reason) VALUES (?, ?, ?, ?)")
      .run(ip || "unknown", (query || "").substring(0, 500), blocked ? 1 : 0, reason || null);
  } catch (err) {
    console.error("Audit Log Error:", err.message);
  }
}

function getAuditLogs(limit = 100) {
  try {
    return db.prepare("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?").all(limit);
  } catch {
    return [];
  }
}

function runSafeQuery(safeQuery) {
  return db.prepare(safeQuery).all();
}

module.exports = { initDB, logAttempt, getAuditLogs, runSafeQuery };
