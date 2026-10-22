const Database = require("better-sqlite3");
const path = require("path");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const { Pool } = require("pg");

const telemetryDbPath = path.join(__dirname, "../telemetry.db");
const telemetryDb = new Database(telemetryDbPath);

try {
  telemetryDb.pragma("journal_mode = WAL");
  telemetryDb.pragma("synchronous = NORMAL");
} catch (e) {
  console.warn("⚠️ [TELEMETRY] Could not set WAL mode:", e.message);
}

// ─── Neon Cloud PostgreSQL Connection ─────────────────────────────────────────
const DATABASE_URL = (
  process.env.DATABASE_URL ||
  process.env.POSTGRES_URL ||
  process.env.NEON_DATABASE_URL ||
  ""
).trim();

const isNeonConfigured = Boolean(
  DATABASE_URL && (DATABASE_URL.startsWith("postgres://") || DATABASE_URL.startsWith("postgresql://"))
);

let pgPool = null;
if (isNeonConfigured) {
  try {
    pgPool = new Pool({
      connectionString: DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    });
    console.log("⚡ [NEON DB] Detected Neon PostgreSQL cloud database connection.");
  } catch (err) {
    console.warn("⚠️ [NEON DB] Could not initialize Postgres pool:", err.message);
    pgPool = null;
  }
} else {
  console.log("📁 [TELEMETRY] No DATABASE_URL found. Running with local SQLite database.");
}

const IP_SALT = process.env.IP_SALT || "adminzero_ip_salt_2026_telemetry";

function hashIp(ip) {
  if (!ip) return "anon";
  return crypto.createHmac("sha256", IP_SALT).update(String(ip).trim()).digest("hex").substring(0, 16);
}

async function initTelemetryDB() {
  // 1. Local SQLite Schema
  telemetryDb.exec(`
    -- Registered hackers
    CREATE TABLE IF NOT EXISTS hackers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT UNIQUE NOT NULL,
      handle TEXT UNIQUE NOT NULL,
      real_name TEXT,
      email TEXT NOT NULL,
      role TEXT,
      country TEXT,
      github_url TEXT,
      linkedin_url TEXT,
      signup_time TEXT DEFAULT CURRENT_TIMESTAMP,
      last_active TEXT DEFAULT CURRENT_TIMESTAMP,
      total_points INTEGER DEFAULT 0,
      flags_captured INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_hackers_session ON hackers(session_id);
    CREATE INDEX IF NOT EXISTS idx_hackers_handle ON hackers(handle);

    -- Every attempt made on /v1/ctf/query
    CREATE TABLE IF NOT EXISTS attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      handle TEXT,
      session_id TEXT,
      ip_hash TEXT,
      timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
      layer_targeted TEXT,
      payload_summary TEXT,
      response_code INTEGER,
      blocked INTEGER DEFAULT 1,
      bypassed INTEGER DEFAULT 0,
      points_awarded INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_attempts_session ON attempts(session_id);
    CREATE INDEX IF NOT EXISTS idx_attempts_handle ON attempts(handle);
    CREATE INDEX IF NOT EXISTS idx_attempts_time ON attempts(timestamp);
    CREATE INDEX IF NOT EXISTS idx_attempts_layer ON attempts(layer_targeted);

    -- Track first solvers for bonus points & badges
    CREATE TABLE IF NOT EXISTS first_solvers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      layer_targeted TEXT UNIQUE NOT NULL,
      handle TEXT NOT NULL,
      badge_name TEXT NOT NULL,
      bonus_points INTEGER DEFAULT 500,
      timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Legacy attempts table (for backward compatibility)
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

  // Safe schema migrations for existing databases
  try { telemetryDb.exec("ALTER TABLE hackers ADD COLUMN real_name TEXT;"); } catch {}
  try { telemetryDb.exec("ALTER TABLE hackers ADD COLUMN role TEXT;"); } catch {}
  try { telemetryDb.exec("ALTER TABLE hackers ADD COLUMN country TEXT;"); } catch {}
  try { telemetryDb.exec("ALTER TABLE hackers ADD COLUMN linkedin_url TEXT;"); } catch {}

  // 2. Initialize Neon DB if configured
  if (pgPool) {
    try {
      await pgPool.query(`
        CREATE TABLE IF NOT EXISTS hackers (
          id SERIAL PRIMARY KEY,
          session_id VARCHAR(120) UNIQUE NOT NULL,
          handle VARCHAR(100) UNIQUE NOT NULL,
          real_name VARCHAR(255),
          email VARCHAR(255) NOT NULL,
          role VARCHAR(100),
          country VARCHAR(100),
          github_url VARCHAR(255),
          linkedin_url VARCHAR(255),
          signup_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          total_points INTEGER DEFAULT 0,
          flags_captured INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS attempts (
          id SERIAL PRIMARY KEY,
          handle VARCHAR(100),
          session_id VARCHAR(120),
          ip_hash VARCHAR(64),
          timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          layer_targeted VARCHAR(100),
          payload_summary TEXT,
          response_code INTEGER,
          blocked INTEGER DEFAULT 1,
          bypassed INTEGER DEFAULT 0,
          points_awarded INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS first_solvers (
          id SERIAL PRIMARY KEY,
          layer_targeted VARCHAR(100) UNIQUE NOT NULL,
          handle VARCHAR(100) NOT NULL,
          badge_name VARCHAR(255) NOT NULL,
          bonus_points INTEGER DEFAULT 500,
          timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      console.log("⚡ [NEON DB] PostgreSQL schemas verified and initialized successfully in Neon Cloud.");

      // Restore existing Neon hackers if local container was recreated
      const sqliteCount = telemetryDb.prepare("SELECT COUNT(*) as c FROM hackers").get().c;
      if (sqliteCount === 0) {
        const pgHackers = await pgPool.query("SELECT * FROM hackers");
        if (pgHackers.rows && pgHackers.rows.length > 0) {
          console.log(`⚡ [NEON DB] Restoring ${pgHackers.rows.length} hackers from Neon Cloud into local memory...`);
          const ins = telemetryDb.prepare(`
            INSERT OR IGNORE INTO hackers (session_id, handle, real_name, email, role, country, github_url, linkedin_url, signup_time, last_active, total_points, flags_captured)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `);
          for (const h of pgHackers.rows) {
            ins.run(h.session_id, h.handle, h.real_name, h.email, h.role, h.country, h.github_url, h.linkedin_url, String(h.signup_time), String(h.last_active), h.total_points, h.flags_captured);
          }
        }
      }
    } catch (err) {
      console.warn("⚠️ [NEON DB] Could not initialize Postgres schemas:", err.message);
    }
  }
}

async function syncHackerToNeon(hacker, isNew = false) {
  if (!pgPool) return;
  try {
    if (isNew) {
      await pgPool.query(`
        INSERT INTO hackers (session_id, handle, real_name, email, role, country, github_url, linkedin_url, total_points, flags_captured)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      `, [
        hacker.session_id, hacker.handle, hacker.real_name, hacker.email,
        hacker.role, hacker.country, hacker.github_url, hacker.linkedin_url,
        hacker.total_points || 0, hacker.flags_captured || 0
      ]);
    } else {
      await pgPool.query(`
        UPDATE hackers SET 
          real_name = COALESCE(NULLIF($1, ''), real_name),
          role = COALESCE(NULLIF($2, ''), role),
          country = COALESCE(NULLIF($3, ''), country),
          github_url = COALESCE($4, github_url),
          linkedin_url = COALESCE($5, linkedin_url),
          last_active = CURRENT_TIMESTAMP
        WHERE LOWER(handle) = LOWER($6)
      `, [hacker.real_name, hacker.role, hacker.country, hacker.github_url, hacker.linkedin_url, hacker.handle]);
    }
  } catch (err) {
    console.warn("⚠️ [NEON DB] Cloud hacker sync error:", err.message);
  }
}

async function syncAttemptToNeon(attempt) {
  if (!pgPool) return;
  try {
    await pgPool.query(`
      INSERT INTO attempts (
        handle, session_id, ip_hash, layer_targeted, payload_summary,
        response_code, blocked, bypassed, points_awarded
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `, [
      attempt.handle, attempt.session_id, attempt.ip_hash,
      attempt.layer_targeted, attempt.payload_summary, attempt.response_code,
      attempt.blocked, attempt.bypassed, attempt.points_awarded
    ]);

    if (attempt.handle && attempt.points_awarded > 0) {
      await pgPool.query(`
        UPDATE hackers SET 
          total_points = total_points + $1,
          flags_captured = flags_captured + $2,
          last_active = CURRENT_TIMESTAMP
        WHERE LOWER(handle) = LOWER($3)
      `, [attempt.points_awarded, attempt.captured_flag ? 1 : 0, attempt.handle]);
    }
  } catch (err) {
    console.warn("⚠️ [NEON DB] Cloud attempt sync error:", err.message);
  }
}

// ─── Registration & Profile ──────────────────────────────────────────────────
function registerHacker({ handle, real_name, email, role, country, github_url, linkedin_url, session_id }) {
  const cleanHandle = String(handle || "").trim();
  const cleanRealName = String(real_name || "").trim();
  const cleanEmail = String(email || "").trim().toLowerCase();
  const cleanRole = String(role || "Security Researcher").trim();
  const cleanCountry = String(country || "Global").trim();
  let cleanGithub = String(github_url || "").trim();
  let cleanLinkedin = String(linkedin_url || "").trim();

  if (!cleanHandle || cleanHandle.length < 2 || cleanHandle.length > 30) {
    throw new Error("Handle must be between 2 and 30 characters.");
  }
  if (!/^[a-zA-Z0-9_\-\.]+$/.test(cleanHandle)) {
    throw new Error("Handle can only contain letters, numbers, underscores, and dashes.");
  }
  if (!cleanRealName || cleanRealName.length < 2) {
    throw new Error("Full Real Name is required (minimum 2 characters).");
  }
  if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    throw new Error("A valid email address is required.");
  }

  // Normalize GitHub URL
  if (cleanGithub) {
    cleanGithub = cleanGithub.replace(/^@/, "");
    if (!cleanGithub.startsWith("http://") && !cleanGithub.startsWith("https://")) {
      cleanGithub = `https://github.com/${cleanGithub}`;
    }
  } else {
    cleanGithub = null;
  }

  // Normalize LinkedIn URL
  if (cleanLinkedin) {
    if (!cleanLinkedin.startsWith("http://") && !cleanLinkedin.startsWith("https://")) {
      cleanLinkedin = `https://linkedin.com/in/${cleanLinkedin.replace(/^@/, "")}`;
    }
  } else {
    cleanLinkedin = null;
  }

  // Check if handle already exists
  const existingByHandle = telemetryDb.prepare("SELECT * FROM hackers WHERE handle = ? COLLATE NOCASE").get(cleanHandle);
  if (existingByHandle) {
    if (existingByHandle.email.toLowerCase() === cleanEmail) {
      // Returning user - refresh session, last active, and update profile metadata
      telemetryDb.prepare(`
        UPDATE hackers SET 
          real_name = COALESCE(NULLIF(?, ''), real_name),
          role = COALESCE(NULLIF(?, ''), role),
          country = COALESCE(NULLIF(?, ''), country),
          github_url = COALESCE(?, github_url),
          linkedin_url = COALESCE(?, linkedin_url),
          last_active = CURRENT_TIMESTAMP 
        WHERE id = ?
      `).run(cleanRealName, cleanRole, cleanCountry, cleanGithub, cleanLinkedin, existingByHandle.id);

      const refreshed = telemetryDb.prepare("SELECT * FROM hackers WHERE id = ?").get(existingByHandle.id);
      syncHackerToNeon(refreshed, false);
      return {
        isNew: false,
        session_id: refreshed.session_id,
        hacker: {
          id: refreshed.id,
          handle: refreshed.handle,
          real_name: refreshed.real_name,
          email: refreshed.email,
          role: refreshed.role,
          country: refreshed.country,
          github_url: refreshed.github_url,
          linkedin_url: refreshed.linkedin_url,
          total_points: refreshed.total_points,
          flags_captured: refreshed.flags_captured
        }
      };
    } else {
      throw new Error(`Handle '@${cleanHandle}' is already claimed by another hacker.`);
    }
  }

  // Check if email already registered with another handle
  const existingByEmail = telemetryDb.prepare("SELECT * FROM hackers WHERE email = ? COLLATE NOCASE").get(cleanEmail);
  if (existingByEmail) {
    throw new Error(`Email is already registered under handle '@${existingByEmail.handle}'. Use that handle to log in.`);
  }

  // Create new session ID or reuse provided anonymous session
  const finalSessionId = session_id && typeof session_id === "string" && session_id.length > 8
    ? session_id
    : uuidv4();

  const insert = telemetryDb.prepare(`
    INSERT INTO hackers (session_id, handle, real_name, email, role, country, github_url, linkedin_url, total_points, flags_captured)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0)
  `);
  const info = insert.run(finalSessionId, cleanHandle, cleanRealName, cleanEmail, cleanRole, cleanCountry, cleanGithub, cleanLinkedin);

  // Retroactively link any anonymous attempts from this session to this handle
  try {
    telemetryDb.prepare("UPDATE attempts SET handle = ? WHERE session_id = ? AND (handle IS NULL OR handle = '' OR handle = 'Anonymous')")
      .run(cleanHandle, finalSessionId);
    
    // Sum any previous points from this session
    const prevPoints = telemetryDb.prepare("SELECT COALESCE(SUM(points_awarded), 0) as pts, COALESCE(SUM(bypassed), 0) as bypasses FROM attempts WHERE handle = ?").get(cleanHandle);
    if (prevPoints && prevPoints.pts > 0) {
      telemetryDb.prepare("UPDATE hackers SET total_points = ? WHERE id = ?").run(prevPoints.pts, info.lastInsertRowid);
    }
  } catch (err) {
    console.warn("Failed to link prior attempts:", err.message);
  }

  const newHacker = telemetryDb.prepare("SELECT * FROM hackers WHERE id = ?").get(info.lastInsertRowid);
  syncHackerToNeon(newHacker, true);
  return {
    isNew: true,
    session_id: finalSessionId,
    hacker: {
      id: newHacker.id,
      handle: newHacker.handle,
      real_name: newHacker.real_name,
      email: newHacker.email,
      role: newHacker.role,
      country: newHacker.country,
      github_url: newHacker.github_url,
      linkedin_url: newHacker.linkedin_url,
      total_points: newHacker.total_points,
      flags_captured: newHacker.flags_captured
    }
  };
}

function isRegisteredHacker(sessionId, handle) {
  if (handle && handle !== "Anonymous" && handle.trim().length > 0) {
    const h = telemetryDb.prepare("SELECT id FROM hackers WHERE handle = ? COLLATE NOCASE").get(handle.trim());
    if (h) return true;
  }
  if (sessionId && sessionId.trim().length > 0) {
    const s = telemetryDb.prepare("SELECT id FROM hackers WHERE session_id = ?").get(sessionId.trim());
    if (s) return true;
  }
  return false;
}

function getHackerBySession(sessionId) {
  if (!sessionId) return null;
  return telemetryDb.prepare("SELECT * FROM hackers WHERE session_id = ?").get(sessionId);
}

function getHackerByHandle(handle) {
  if (!handle) return null;
  return telemetryDb.prepare("SELECT * FROM hackers WHERE handle = ? COLLATE NOCASE").get(handle);
}

// ─── Attempt Logging & Scoring ───────────────────────────────────────────────
function logAttemptRecord({
  handle,
  session_id,
  ip,
  layer_targeted,
  payload,
  response_code,
  blocked,
  bypassed,
  captured_flag
}) {
  const ip_hash = hashIp(ip);
  let effectiveHandle = handle && typeof handle === "string" ? handle.trim() : null;

  // If no handle provided, check if session is already registered
  if ((!effectiveHandle || effectiveHandle.toLowerCase() === "anonymous") && session_id) {
    const hacker = getHackerBySession(session_id);
    if (hacker) effectiveHandle = hacker.handle;
  }

  let pointsAwarded = 0;
  let isFirstSolver = false;
  let firstSolverBadge = null;

  // Calculate points
  if (bypassed && !blocked) {
    if (captured_flag) {
      // Flag capture
      pointsAwarded = 1000;
      
      // Check first blood on flag
      const existingFirst = telemetryDb.prepare("SELECT * FROM first_solvers WHERE layer_targeted = 'FLAG_CAPTURED'").get();
      if (!existingFirst && effectiveHandle) {
        isFirstSolver = true;
        firstSolverBadge = "👑 First Blood: CTF Flag Capture";
        pointsAwarded += 1000; // 2000 total for first flag capture
        try {
          telemetryDb.prepare("INSERT INTO first_solvers (layer_targeted, handle, badge_name, bonus_points) VALUES (?, ?, ?, ?)")
            .run("FLAG_CAPTURED", effectiveHandle, firstSolverBadge, 1000);
        } catch {}
      }
    } else {
      // Full query bypass
      pointsAwarded = 100;
      const existingFirst = telemetryDb.prepare("SELECT * FROM first_solvers WHERE layer_targeted = 'FULL_BYPASS'").get();
      if (!existingFirst && effectiveHandle) {
        isFirstSolver = true;
        firstSolverBadge = "⚡ First Blood: 12-Layer Firewall Bypass";
        pointsAwarded += 300;
        try {
          telemetryDb.prepare("INSERT INTO first_solvers (layer_targeted, handle, badge_name, bonus_points) VALUES (?, ?, ?, ?)")
            .run("FULL_BYPASS", effectiveHandle, firstSolverBadge, 300);
        } catch {}
      }
    }
  }

  // Safe payload summary (truncate to 1000 chars, no raw server secrets)
  const safePayload = String(payload || "").substring(0, 1000);

  // Insert attempt
  const info = telemetryDb.prepare(`
    INSERT INTO attempts (
      handle, session_id, ip_hash, layer_targeted, payload_summary,
      response_code, blocked, bypassed, points_awarded
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    effectiveHandle,
    session_id || null,
    ip_hash,
    layer_targeted || "UNKNOWN",
    safePayload,
    response_code || 200,
    blocked ? 1 : 0,
    bypassed ? 1 : 0,
    pointsAwarded
  );

  // Update registered hacker stats
  if (effectiveHandle) {
    try {
      telemetryDb.prepare(`
        UPDATE hackers SET 
          total_points = total_points + ?,
          flags_captured = flags_captured + ?,
          last_active = CURRENT_TIMESTAMP
        WHERE handle = ? COLLATE NOCASE
      `).run(pointsAwarded, captured_flag ? 1 : 0, effectiveHandle);
    } catch (err) {
      console.warn("Could not update hacker points:", err.message);
    }
  }

  // Also log to legacy table for backward compatibility
  try {
    telemetryDb.prepare(
      "INSERT INTO ctf_attempts (hacker_alias, prompt, generated_sql, waf_status, captured_flag) VALUES (?, ?, ?, ?, ?)"
    ).run(effectiveHandle || "Anonymous", safePayload, safePayload, blocked ? layer_targeted : "EXECUTED", captured_flag ? 1 : 0);
  } catch {}

  // Also sync attempt to Neon Cloud Database
  syncAttemptToNeon({
    handle: effectiveHandle,
    session_id,
    ip_hash,
    layer_targeted,
    payload_summary: safePayload,
    response_code,
    blocked,
    bypassed,
    points_awarded: pointsAwarded,
    captured_flag
  });

  return {
    attemptId: info.lastInsertRowid,
    handle: effectiveHandle,
    pointsAwarded,
    isFirstSolver,
    firstSolverBadge
  };
}

// ─── Public Updates ──────────────────────────────────────────────────────────

// Hall of Fame
function getHallOfFame(limit = 25) {
  try {
    const hackers = telemetryDb.prepare(`
      SELECT 
        id, handle, github_url, total_points, flags_captured, signup_time, last_active
      FROM hackers
      ORDER BY flags_captured DESC, total_points DESC, signup_time ASC
      LIMIT ?
    `).all(limit);

    // Get all badges
    const allBadges = telemetryDb.prepare("SELECT * FROM first_solvers").all();
    const badgesByHandle = {};
    for (const b of allBadges) {
      const h = b.handle.toLowerCase();
      if (!badgesByHandle[h]) badgesByHandle[h] = [];
      badgesByHandle[h].push(b.badge_name);
    }

    return hackers.map((hacker, index) => ({
      rank: index + 1,
      handle: hacker.handle,
      github_url: hacker.github_url,
      total_points: hacker.total_points,
      flags_captured: hacker.flags_captured,
      badges: badgesByHandle[hacker.handle.toLowerCase()] || [],
      last_active: hacker.last_active,
      signup_time: hacker.signup_time
    }));
  } catch (err) {
    console.error("Hall of Fame Error:", err.message);
    return [];
  }
}

// Live Activity Feed (Last 20 attempts)
function getLiveFeed(limit = 20) {
  try {
    const attempts = telemetryDb.prepare(`
      SELECT 
        id,
        COALESCE(NULLIF(handle, ''), 'Anonymous') as handle,
        layer_targeted,
        blocked,
        bypassed,
        points_awarded,
        timestamp
      FROM attempts
      ORDER BY id DESC
      LIMIT ?
    `).all(limit);

    return attempts.map(a => ({
      id: a.id,
      handle: a.handle,
      layer_targeted: a.layer_targeted,
      status: a.bypassed ? "BYPASSED" : "BLOCKED",
      blocked: a.blocked === 1,
      bypassed: a.bypassed === 1,
      points_awarded: a.points_awarded,
      timestamp: a.timestamp
    }));
  } catch (err) {
    console.error("Live Feed Error:", err.message);
    return [];
  }
}

// Global Stats (for HUD on main page)
function getCTFStats() {
  try {
    const totalBlocked = telemetryDb.prepare("SELECT COUNT(*) as count FROM attempts WHERE blocked = 1").get().count;
    const totalBypasses = telemetryDb.prepare("SELECT COUNT(*) as count FROM attempts WHERE bypassed = 1").get().count;
    const totalHackers = telemetryDb.prepare("SELECT COUNT(*) as count FROM hackers").get().count;
    const activeHackers5m = telemetryDb.prepare(`
      SELECT COUNT(DISTINCT COALESCE(NULLIF(handle, ''), ip_hash)) as count 
      FROM attempts 
      WHERE timestamp >= datetime('now', '-5 minutes')
    `).get().count;

    return {
      total_attacks_blocked: totalBlocked,
      successful_bypasses: totalBypasses,
      registered_hackers: totalHackers,
      active_players_5m: activeHackers5m,
      bounty_payout: totalBypasses === 0 ? "CLAIM PRIZE" : "CLAIMED"
    };
  } catch (err) {
    console.error("Telemetry Stats Error:", err.message);
    return {
      total_attacks_blocked: 0,
      successful_bypasses: 0,
      registered_hackers: 0,
      active_players_5m: 0,
      bounty_payout: "CLAIM PRIZE"
    };
  }
}

// ─── Admin Dashboard Endpoints ───────────────────────────────────────────────

function getAdminHackersList({ search = "", date_from, date_to } = {}) {
  try {
    let sql = `
      SELECT 
        h.id, h.session_id, h.handle, h.real_name, h.email, h.role, h.country, h.github_url, h.linkedin_url,
        h.signup_time, h.last_active, h.total_points, h.flags_captured,
        COUNT(a.id) as total_attempts,
        COALESCE(SUM(CASE WHEN a.bypassed = 1 THEN 1 ELSE 0 END), 0) as bypasses_count,
        COALESCE(SUM(CASE WHEN a.blocked = 1 THEN 1 ELSE 0 END), 0) as blocked_count
      FROM hackers h
      LEFT JOIN attempts a ON (h.handle = a.handle OR h.session_id = a.session_id)
      WHERE 1=1
    `;
    const params = [];

    if (search && search.trim()) {
      sql += " AND (h.handle LIKE ? OR h.email LIKE ? OR h.real_name LIKE ? OR h.role LIKE ? OR h.country LIKE ?)";
      const pattern = `%${search.trim()}%`;
      params.push(pattern, pattern, pattern, pattern, pattern);
    }

    if (date_from) {
      sql += " AND h.signup_time >= ?";
      params.push(date_from);
    }
    if (date_to) {
      sql += " AND h.signup_time <= ?";
      params.push(date_to);
    }

    sql += " GROUP BY h.id ORDER BY h.total_points DESC, h.last_active DESC";

    return telemetryDb.prepare(sql).all(...params);
  } catch (err) {
    console.error("Admin Hackers List Error:", err.message);
    return [];
  }
}

function getAdminHackerDetail(hackerId) {
  try {
    const hacker = telemetryDb.prepare("SELECT * FROM hackers WHERE id = ?").get(hackerId);
    if (!hacker) return null;

    // Full timeline of every attempt (newest first)
    const timeline = telemetryDb.prepare(`
      SELECT 
        id, timestamp, layer_targeted, payload_summary, response_code, blocked, bypassed, points_awarded
      FROM attempts
      WHERE handle = ? OR session_id = ?
      ORDER BY id DESC
    `).all(hacker.handle, hacker.session_id);

    // Per-layer breakdown
    const layerStats = telemetryDb.prepare(`
      SELECT 
        layer_targeted,
        COUNT(*) as attempts_count,
        COALESCE(SUM(CASE WHEN bypassed = 1 THEN 1 ELSE 0 END), 0) as bypass_count,
        COALESCE(SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END), 0) as blocked_count
      FROM attempts
      WHERE handle = ? OR session_id = ?
      GROUP BY layer_targeted
      ORDER BY attempts_count DESC
    `).all(hacker.handle, hacker.session_id);

    // Compute success rate per layer
    const layerBreakdown = layerStats.map(l => ({
      layer: l.layer_targeted,
      attempts: l.attempts_count,
      bypasses: l.bypass_count,
      blocked: l.blocked_count,
      success_rate: l.attempts_count > 0 ? ((l.bypass_count / l.attempts_count) * 100).toFixed(1) + "%" : "0%"
    }));

    // Points progress points (cumulative over time)
    let cumulative = 0;
    const pointsProgress = timeline.slice().reverse().map(t => {
      cumulative += t.points_awarded || 0;
      return {
        timestamp: t.timestamp,
        points: cumulative,
        cumulative_points: cumulative,
        awarded: t.points_awarded,
        points_awarded: t.points_awarded
      };
    });

    return {
      hacker,
      timeline,
      layerBreakdown,
      layer_breakdown: layerBreakdown,
      pointsProgress,
      points_progress: pointsProgress
    };
  } catch (err) {
    console.error("Admin Hacker Detail Error:", err.message);
    return null;
  }
}

function getAdminGlobalStats() {
  try {
    const totalAttempts = telemetryDb.prepare("SELECT COUNT(*) as c FROM attempts").get().c;
    const uniqueVisitors = telemetryDb.prepare("SELECT COUNT(DISTINCT ip_hash) as c FROM attempts").get().c;
    const totalHackers = telemetryDb.prepare("SELECT COUNT(*) as c FROM hackers").get().c;
    const totalFlags = telemetryDb.prepare("SELECT COUNT(*) as c FROM attempts WHERE bypassed = 1 AND layer_targeted = 'FLAG_CAPTURED'").get().c;

    const activePlayers5m = telemetryDb.prepare(`
      SELECT COUNT(DISTINCT COALESCE(NULLIF(handle, ''), ip_hash)) as c 
      FROM attempts 
      WHERE timestamp >= datetime('now', '-5 minutes')
    `).get().c;

    // Attempts per layer
    const layerCounts = telemetryDb.prepare(`
      SELECT 
        layer_targeted,
        COUNT(*) as total,
        COALESCE(SUM(CASE WHEN bypassed = 1 THEN 1 ELSE 0 END), 0) as bypasses,
        COALESCE(SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END), 0) as blocked
      FROM attempts
      GROUP BY layer_targeted
      ORDER BY total DESC
    `).all();

    const attemptsPerLayer = {};
    const successRatePerLayer = {};
    let mostAttackedLayer = { layer: "None", count: 0 };

    for (const item of layerCounts) {
      attemptsPerLayer[item.layer_targeted] = item.total;
      const rate = item.total > 0 ? ((item.bypasses / item.total) * 100).toFixed(1) + "%" : "0%";
      successRatePerLayer[item.layer_targeted] = rate;
      if (item.total > mostAttackedLayer.count) {
        mostAttackedLayer = { layer: item.layer_targeted, count: item.total };
      }
    }

    return {
      total_attempts: totalAttempts,
      unique_visitors: uniqueVisitors,
      total_hackers: totalHackers,
      registered_hackers: totalHackers,
      flags_captured: totalFlags,
      active_last_5min: activePlayers5m,
      active_players_5m: activePlayers5m,
      most_attacked_layer: mostAttackedLayer.layer,
      most_attacked_layer_info: mostAttackedLayer,
      attempts_per_layer: attemptsPerLayer,
      success_rate_per_layer: successRatePerLayer,
      layer_stats: layerCounts.map(l => ({
        layer: l.layer_targeted,
        total_attempts: l.total,
        bypasses: l.bypasses,
        success_rate: l.total > 0 ? ((l.bypasses / l.total) * 100).toFixed(1) : "0.0"
      })),
      layer_table: layerCounts
    };
  } catch (err) {
    console.error("Admin Global Stats Error:", err.message);
    return {
      total_attempts: 0,
      unique_visitors: 0,
      total_hackers: 0,
      registered_hackers: 0,
      flags_captured: 0,
      active_last_5min: 0,
      active_players_5m: 0,
      most_attacked_layer: "None",
      most_attacked_layer_info: { layer: "None", count: 0 },
      attempts_per_layer: {},
      success_rate_per_layer: {},
      layer_stats: [],
      layer_table: []
    };
  }
}

function exportAttemptsToCsv() {
  try {
    const rows = telemetryDb.prepare(`
      SELECT 
        a.id, a.timestamp, COALESCE(a.handle, 'Anonymous') as handle,
        COALESCE(h.real_name, '') as real_name,
        COALESCE(h.email, '') as email,
        COALESCE(h.role, '') as role,
        COALESCE(h.country, '') as country,
        COALESCE(h.github_url, '') as github_url,
        COALESCE(h.linkedin_url, '') as linkedin_url,
        COALESCE(a.session_id, '') as session_id,
        a.ip_hash, a.layer_targeted, a.payload_summary,
        a.response_code, a.blocked, a.bypassed, a.points_awarded
      FROM attempts a
      LEFT JOIN hackers h ON (a.handle = h.handle OR a.session_id = h.session_id)
      ORDER BY a.id ASC
    `).all();

    const headers = [
      "ID", "Timestamp", "Handle", "RealName", "Email", "Role", "Country",
      "GitHub", "LinkedIn", "SessionID", "IPHash", "LayerTargeted",
      "PayloadSummary", "ResponseCode", "Blocked", "Bypassed", "PointsAwarded"
    ];

    const escapeCsv = (str) => {
      const s = String(str === null || str === undefined ? "" : str);
      if (s.includes(",") || s.includes("\"") || s.includes("\n") || s.includes("\r")) {
        return `"${s.replace(/"/g, '""')}"`;
      }
      return s;
    };

    const csvLines = [headers.join(",")];
    for (const r of rows) {
      csvLines.push([
        r.id,
        escapeCsv(r.timestamp),
        escapeCsv(r.handle),
        escapeCsv(r.real_name),
        escapeCsv(r.email),
        escapeCsv(r.role),
        escapeCsv(r.country),
        escapeCsv(r.github_url),
        escapeCsv(r.linkedin_url),
        escapeCsv(r.session_id),
        escapeCsv(r.ip_hash),
        escapeCsv(r.layer_targeted),
        escapeCsv(r.payload_summary),
        r.response_code,
        r.blocked,
        r.bypassed,
        r.points_awarded
      ].join(","));
    }

    return csvLines.join("\n");
  } catch (err) {
    console.error("Export CSV Error:", err.message);
    return "ID,Timestamp,Handle,RealName,Email,Role,Country,GitHub,LinkedIn,SessionID,IPHash,LayerTargeted,PayloadSummary,ResponseCode,Blocked,Bypassed,PointsAwarded\n";
  }
}

module.exports = {
  initTelemetryDB,
  registerHacker,
  isRegisteredHacker,
  getHackerBySession,
  getHackerByHandle,
  logAttemptRecord,
  getHallOfFame,
  getLiveFeed,
  getCTFStats,
  getAdminHackersList,
  getAdminHackerDetail,
  getAdminGlobalStats,
  exportAttemptsToCsv
};
