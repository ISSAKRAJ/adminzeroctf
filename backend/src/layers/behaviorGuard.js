// LAYER 10: Behavioral Guard — Shadow Ban + Escalating Penalties
//
// Tracks every IP's behavior over time. Attackers who repeatedly trigger
// blocks get progressively harsher treatment:
//
//   Tier 0 (0-2 blocks):   Normal rejection messages
//   Tier 1 (3-5 blocks):   Artificial delay + vague error
//   Tier 2 (6-9 blocks):   Shadow ban — return 200 with FAKE data
//   Tier 3 (10+ blocks):   Hard ban — 429 with no useful info
//
// The shadow ban is the cruelest: the attacker gets a "success" response
// with fabricated users/products data. They waste time analyzing fake data.

const crypto = require("crypto");

// In-memory store — keyed by IP
// Structure: { blocks: number, tier: 0-3, shadowBanSeed: string, lastReset: number }
const ipRecords = new Map();

// Reset counters after 10 minutes of silence
const WINDOW_MS = 10 * 60 * 1000;

const TIER_THRESHOLDS = {
  0: 0,   // normal
  1: 2,   // slight delay
  2: 3,   // shadow ban
  3: 10,  // hard ban
};

// Fake data returned during shadow ban — looks plausible but is totally wrong
const SHADOW_USERS = [
  { name: "Ravi Issak", role: "admin" },
  { name: "Priya Sharma", role: "engineer" },
  { name: "Dev Kumar", role: "user" },
];

const SHADOW_PRODUCTS = [
  { name: "AdminZero Pro License", price: 99.99 },
  { name: "GlitchGo Support Pack", price: 49.99 },
];

function getRecord(ip) {
  const now = Date.now();
  let record = ipRecords.get(ip);

  if (!record) {
    record = { blocks: 0, tier: 0, shadowSeed: crypto.randomBytes(8).toString("hex"), lastSeen: now };
    ipRecords.set(ip, record);
    return record;
  }

  // Reset if window expired and no recent activity
  if (now - record.lastSeen > WINDOW_MS) {
    record.blocks = 0;
    record.tier = 0;
  }

  record.lastSeen = now;
  return record;
}

function computeTier(blocks) {
  if (blocks >= TIER_THRESHOLDS[3]) return 3;
  if (blocks >= TIER_THRESHOLDS[2]) return 2;
  if (blocks >= TIER_THRESHOLDS[1]) return 1;
  return 0;
}

/**
 * Called on every BLOCKED query.
 * Returns the updated record so the caller can decide how to respond.
 */
function recordBlock(ip) {
  const record = getRecord(ip);
  record.blocks += 1;
  record.tier = computeTier(record.blocks);
  return record;
}

/**
 * Called on every PASSED query to track legitimate usage.
 */
function recordPass(ip) {
  const record = getRecord(ip);
  // Partial forgiveness on legit queries — but don't reset completely
  record.blocks = Math.max(0, record.blocks - 1);
  record.tier = computeTier(record.blocks);
  return record;
}

/**
 * Get the current tier for an IP (for pre-check).
 */
function getTier(ip) {
  const record = getRecord(ip);
  return record.tier;
}

/**
 * Get the shadow response data to send a banned attacker.
 * The data looks legitimate but is randomized by the IP's shadow seed.
 */
function getShadowResponse(ip, reqId) {
  const record = getRecord(ip);
  // Use the seed to deterministically pick fake data
  const seedNum = parseInt(record.shadowSeed.substring(0, 4), 16);
  const rows = seedNum % 2 === 0 ? SHADOW_USERS : SHADOW_PRODUCTS;

  return {
    blocked: false,
    reqId,
    layers_passed: 8,
    tables: seedNum % 2 === 0 ? ["users"] : ["products"],
    rows,
    message: "Query passed all 8 AdminZero security layers."
  };
}

/**
 * Compute artificial delay in ms based on tier.
 */
function getPenaltyDelayMs(tier) {
  switch (tier) {
    case 1: return 800 + Math.floor(Math.random() * 400);   // 0.8–1.2s
    case 2: return 1500 + Math.floor(Math.random() * 500);  // 1.5–2.0s
    case 3: return 0;
    default: return 0;
  }
}

/**
 * Clean up old records periodically (prevent memory leak).
 */
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of ipRecords.entries()) {
    if (now - record.lastSeen > WINDOW_MS * 2) {
      ipRecords.delete(ip);
    }
  }
}, WINDOW_MS);

module.exports = { recordBlock, recordPass, getTier, getShadowResponse, getPenaltyDelayMs };
