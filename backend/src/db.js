const Database = require("better-sqlite3");
const path = require("path");

const db = new Database(path.join(__dirname, "../honeypot.db"));

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

    -- REAL FLAG: protected by all 7 layers
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

  // Seed honeypot (decoy)
  const fakeCount = db.prepare("SELECT COUNT(*) as c FROM fake_flags").get();
  if (fakeCount.c === 0) {
    db.prepare("INSERT INTO fake_flags (decoy) VALUES (?)").run("ADMINZERO_FAKE_{n0t_th3_r34l_fl4g}");
  }

  // Real flag — MUST be set via CTF_FLAG environment variable.
  // There is NO hardcoded fallback. The server will throw if CTF_FLAG is missing.
  const flagCount = db.prepare("SELECT COUNT(*) as c FROM flag_table").get();
  if (flagCount.c === 0) {
    const flag = process.env.CTF_FLAG;
    if (!flag || flag.trim() === "") {
      throw new Error("[ADMINZERO] CTF_FLAG environment variable is not set. Refusing to start without a flag.");
    }
    db.prepare("INSERT INTO flag_table (secret) VALUES (?)").run(flag.trim());
  }

  // Seed super secret admin (CTF honeypot)
  const adminCount = db.prepare("SELECT COUNT(*) as c FROM super_secret_admin").get();
  if (adminCount.c === 0) {
    db.prepare("INSERT INTO super_secret_admin (role, capture_flag) VALUES (?, ?)").run('super_admin', 'AZ_FLAG{w3lc0m3_t0_th3_d4rk_s1d3}');
  }
}

function logAttempt(ip, query, blocked, reason) {
  try {
    db.prepare("INSERT INTO audit_log (ip, query, blocked, reason) VALUES (?, ?, ?, ?)")
      .run(ip, query?.substring(0, 500), blocked ? 1 : 0, reason || null);
  } catch {}
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
