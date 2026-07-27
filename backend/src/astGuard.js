// LAYER 5 + 6 + 7: AdminZero AST Guard
// Parse → Validate → Reconstruct (the original string is NEVER executed)
//
// Security properties:
//  - Only SELECT statements allowed
//  - Only whitelisted tables reachable
//  - No subqueries (proper recursive walk, not string-matching)
//  - No UNION / INTERSECT / EXCEPT (recursive walk)
//  - No wildcard SELECT * (must project explicit columns)
//  - No sensitive column names
//  - No CTEs (WITH ... AS)
//  - Complexity is independently scored before reaching here
//  - Reconstructed query re-validated against blacklist before execution

const { Parser } = require("node-sql-parser");
const { scoreComplexity } = require("./layers/complexityScorer");
const { checkBlacklist } = require("./layers/keywordBlacklist");
const { detectEncoding } = require("./layers/encodingDetector");
const { tokenizerCheck } = require("./layers/sqlTokenizer");

const parser = new Parser();

// ─── Access Control Lists ────────────────────────────────────────────────────

// Only these tables are accessible to challengers
const ALLOWED_TABLES = new Set(["users", "products"]);

// Absolutely forbidden tables — explicitly deny in addition to "not in whitelist"
const FORBIDDEN_TABLES = new Set([
  "flag_table",
  "audit_log",
  "fake_flags",
  "sqlite_master",
  "sqlite_sequence",
  "sqlite_temp_master",
]);

// ── COLUMN WHITELIST (NOT a blacklist) ──────────────────────────────────────
// ONLY these exact columns are permitted. Any column not in this list is
// blocked regardless of what table it comes from. This is far stronger than
// a blacklist because it's closed-world: unknown = denied.
//
// This means even if a future bug adds a sensitive column to users/products,
// it still won't be queryable unless explicitly added here.
const COLUMN_WHITELIST = {
  users: new Set(["id", "name", "role", "created_at"]),
  // email is intentionally excluded from whitelist:
  // PII scrubber masks it, but simpler to just not allow the column at all
  products: new Set(["id", "name", "price", "category", "stock"]),
};

// All columns permitted across ALL whitelisted tables (union for WHERE clause checks)
const ALL_ALLOWED_COLUMNS = new Set([
  ...COLUMN_WHITELIST.users,
  ...COLUMN_WHITELIST.products,
]);

// ─── AST Walkers ─────────────────────────────────────────────────────────────

/**
 * Generic depth-first walker.
 * Calls visitor(node) for every object node in the AST.
 * Uses an explicit stack to avoid call-stack overflows on deep trees.
 */
function walkAST(rootNode, visitor) {
  const stack = [rootNode];
  while (stack.length > 0) {
    const node = stack.pop();
    if (!node || typeof node !== "object") continue;
    visitor(node);
    for (const val of Object.values(node)) {
      if (Array.isArray(val)) {
        for (const item of val) {
          if (item && typeof item === "object") stack.push(item);
        }
      } else if (val && typeof val === "object") {
        stack.push(val);
      }
    }
  }
}

/**
 * LAYER 6: Extract all table names referenced anywhere in the AST.
 * This catches table refs in FROM, JOIN, subquery FROM, etc.
 */
function extractTableNames(astNode) {
  const tables = new Set();
  walkAST(astNode, (node) => {
    // Direct table reference: { db, table, as }
    if (node.table && typeof node.table === "string") {
      tables.add(node.table.toLowerCase());
    }
    // Parser sometimes puts the table ref in a `name` field on from-clause items
    if (node.name && typeof node.name === "string" && node.type === "table") {
      tables.add(node.name.toLowerCase());
    }
  });
  return tables;
}

/**
 * LAYER 6: Extract all column refs anywhere in the AST.
 */
function extractColumns(astNode) {
  const cols = [];
  walkAST(astNode, (node) => {
    if (node.type === "column_ref" && node.column != null) {
      // node.column can be a string OR an object (e.g. { name: "secret", quote: "`" })
      // depending on parser version and column syntax. Handle both.
      let colName;
      if (typeof node.column === "string") {
        colName = node.column;
      } else if (typeof node.column === "object") {
        // Try common object shapes from node-sql-parser
        colName = node.column.name || node.column.value || node.column.column ||
                  JSON.stringify(node.column); // worst case — stringify so it never silently passes
      } else {
        colName = String(node.column);
      }
      if (colName) cols.push(colName.toLowerCase());
    }
  });
  return cols;
}

/**
 * LAYER 6: Detect any nested SELECT statements (subqueries).
 * Counts nodes whose type === "select"; if more than one found → subquery exists.
 */
function containsSubquery(stmtNode) {
  let selectCount = 0;
  walkAST(stmtNode, (node) => {
    if (node.type === "select") selectCount += 1;
  });
  return selectCount > 1;
}

/**
 * LAYER 6: Detect UNION / INTERSECT / EXCEPT anywhere in the AST.
 * node-sql-parser models these as chained _next / union properties.
 */
function containsSetOperation(astNode) {
  let found = false;
  walkAST(astNode, (node) => {
    if (
      node._next != null ||
      node.union != null ||
      node.intersect != null ||
      node.except != null ||
      node.type === "union" ||
      node.type === "intersect" ||
      node.type === "except"
    ) {
      found = true;
    }
  });
  return found;
}

/**
 * LAYER 6: Detect CTEs (WITH ... AS clauses).
 */
function containsCTE(astNode) {
  if (!astNode) return false;
  // node-sql-parser puts CTEs in a `with` array on the top-level statement
  if (Array.isArray(astNode.with) && astNode.with.length > 0) return true;
  let found = false;
  walkAST(astNode, (node) => {
    if (node.type === "with" || (Array.isArray(node.with) && node.with.length > 0)) {
      found = true;
    }
  });
  return found;
}

/**
 * LAYER 6: Detect SELECT * (wildcard projections).
 */
function containsWildcard(stmtNode) {
  if (!stmtNode.columns) return false;
  if (stmtNode.columns === "*") return true;
  if (Array.isArray(stmtNode.columns)) {
    return stmtNode.columns.some(
      (col) => col.expr?.type === "star" || col.expr?.column === "*" || col === "*"
    );
  }
  return false;
}

/**
 * Reconstruct SQL from AST — the original user string is discarded here.
 */
function reconstructQuery(stmtNode) {
  try {
    // IMPORTANT: Pass the same dialect used during astify() so that
    // sqlify() output is consistent. Without this, MySQL-dialect backtick
    // quoting and other dialect differences can appear in the output.
    return parser.sqlify(stmtNode, { database: "SQLite" });
  } catch {
    return null;
  }
}

/**
 * LAYER 6: Enforce a hard LIMIT cap.
 * Prevents full-table dump attacks. If the query has no LIMIT, inject one.
 * If it has a LIMIT > MAX_ROWS, reject it.
 */
const MAX_ROWS = 10;
function enforceLimitCap(stmtNode) {
  if (!stmtNode.limit) {
    // Inject LIMIT 10 directly into the AST node
    stmtNode.limit = {
      separator: "",
      value: [{ type: "number", value: MAX_ROWS }]
    };
    return { ok: true };
  }
  // Parse out the limit value
  const limitVal = stmtNode.limit?.value?.[0]?.value;
  if (limitVal != null && Number(limitVal) > MAX_ROWS) {
    return { ok: false, reason: `LAYER_6_LIMIT: LIMIT ${limitVal} exceeds maximum of ${MAX_ROWS}` };
  }
  return { ok: true };
}

// ─── Main Validator ───────────────────────────────────────────────────────────

function validateAST(query) {
  let ast;

  // LAYER 5: Parse — if the SQL is invalid, reject immediately
  try {
    ast = parser.astify(query, { database: "SQLite" });
  } catch (e) {
    return { valid: false, reason: "LAYER_5_PARSE_FAIL: Invalid SQL syntax" };
  }

  const statements = Array.isArray(ast) ? ast : [ast];

  // Only one statement allowed (stacked queries)
  if (statements.length > 1) {
    return { valid: false, reason: "LAYER_5_MULTI_STATEMENT: Stacked queries blocked" };
  }

  const stmt = statements[0];

  // ─── LAYER 6: Intent Validation ──────────────────────────────────────────

  // Only SELECT allowed
  if (!stmt || stmt.type !== "select") {
    return {
      valid: false,
      reason: `LAYER_6_MUTATION: Only SELECT is allowed, got ${stmt?.type?.toUpperCase() ?? "UNKNOWN"}`
    };
  }

  // No CTEs (WITH ... AS (...))
  if (containsCTE(stmt)) {
    return { valid: false, reason: "LAYER_6_CTE: Common Table Expressions (WITH) are blocked" };
  }

  // No UNION / INTERSECT / EXCEPT (proper AST walk)
  if (containsSetOperation(stmt)) {
    return { valid: false, reason: "LAYER_6_SET_OP: UNION / INTERSECT / EXCEPT are blocked" };
  }

  // No subqueries (proper AST walk, not string-matching)
  if (containsSubquery(stmt)) {
    return { valid: false, reason: "LAYER_6_SUBQUERY: Nested SELECT (subquery) is blocked" };
  }

  // No SELECT * wildcard
  if (containsWildcard(stmt)) {
    return { valid: false, reason: "LAYER_6_WILDCARD: SELECT * is not allowed. List columns explicitly." };
  }

  // ─── LAYER 6: Table Access Control ───────────────────────────────────────
  const tables = extractTableNames(stmt);

  for (const tbl of tables) {
    if (FORBIDDEN_TABLES.has(tbl)) {
      return { valid: false, reason: `LAYER_6_FORBIDDEN_TABLE: Access to '${tbl}' is denied` };
    }
    if (!ALLOWED_TABLES.has(tbl)) {
      return { valid: false, reason: `LAYER_6_UNKNOWN_TABLE: Table '${tbl}' does not exist` };
    }
  }

  if (tables.size === 0) {
    return { valid: false, reason: "LAYER_6_NO_TABLE: Query must reference at least one valid table" };
  }

  // ─── LAYER 6: Column WHITELIST check ─────────────────────────────────────
  // CLOSED-WORLD: only columns that appear in COLUMN_WHITELIST are permitted.
  // Unknown column = denied. Period.
  const cols = extractColumns(stmt);
  for (const col of cols) {
    // Allow '*' only if we already blocked wildcard SELECT above
    // (this catches col refs in WHERE / ORDER BY that use *)
    if (col === "*") {
      return { valid: false, reason: "LAYER_6_WILDCARD: Wildcard column reference blocked" };
    }
    if (!ALL_ALLOWED_COLUMNS.has(col)) {
      return {
        valid: false,
        reason: `LAYER_6_COLUMN_NOT_WHITELISTED: Column '${col}' is not in the allowed column list`
      };
    }
  }

  // ─── LAYER 6: Enforce LIMIT cap (prevent full-table dump) ────────────────
  const limitCheck = enforceLimitCap(stmt);
  if (!limitCheck.ok) {
    return { valid: false, reason: limitCheck.reason };
  }

  // ─── LAYER 4: Complexity Check (before reconstruction) ───────────────────
  const complexity = scoreComplexity(stmt);
  if (complexity.tooComplex) {
    return { valid: false, reason: complexity.reason };
  }

  // ─── LAYER 7: Reconstruct from AST ───────────────────────────────────────
  // The original user string is completely discarded.
  // Only the sanitized, parser-reconstructed SQL is passed to the DB driver.
  const safeQuery = reconstructQuery(stmt);
  if (!safeQuery) {
    return { valid: false, reason: "LAYER_7_RECONSTRUCT_FAIL: Could not reconstruct safe query" };
  }

  // Post-reconstruction secondary scan:
  // Run the reconstructed SQL through the keyword blacklist to catch
  // any parser edge cases where sqlify may produce unexpected output.
  const postCheck = checkBlacklist(safeQuery);
  if (postCheck.blocked) {
    return {
      valid: false,
      reason: `LAYER_7_POST_VALIDATE: Reconstructed query contains blocked pattern. ${postCheck.reason}`
    };
  }

  // Final paranoia check: forbidden table names in the reconstructed string
  const reconstructedLower = safeQuery.toLowerCase();
  for (const tbl of FORBIDDEN_TABLES) {
    if (reconstructedLower.includes(tbl)) {
      return {
        valid: false,
        reason: `LAYER_7_POST_VALIDATE: Forbidden table '${tbl}' found in reconstructed query`
      };
    }
  }

  // Run the RECONSTRUCTED (sqlify output) through the encoding detector.
  // sqlify() legitimately wraps identifiers in backticks (SQLite dialect).
  // Strip those before checking to avoid false positives, but still catch
  // any genuine encoding attack patterns in string literals or values.
  const queryWithoutIdentifierBackticks = safeQuery.replace(/`[a-zA-Z_][a-zA-Z0-9_]*`/g, "IDENTIFIER");
  const encCheck = detectEncoding(queryWithoutIdentifierBackticks);
  if (encCheck.detected) {
    return {
      valid: false,
      reason: `LAYER_7_POST_VALIDATE: Reconstructed query triggered encoding detector: ${encCheck.reason}`
    };
  }

  // ─── LAYER 9: Custom Tokenizer Check (independent of AST parser) ─────────
  // Run the ORIGINAL query through the hand-rolled tokenizer.
  // This catches any identifier the AST parser may have misread.
  // It operates purely on the raw string lexical tokens — zero trust in the parser.
  const tokCheck = tokenizerCheck(query);
  if (!tokCheck.safe) {
    return {
      valid: false,
      reason: `LAYER_9_TOKENIZER: Raw identifier '${tokCheck.found}' is forbidden`
    };
  }
  // Also run tokenizer on the RECONSTRUCTED query for double coverage
  const tokCheckReconstructed = tokenizerCheck(safeQuery);
  if (!tokCheckReconstructed.safe) {
    return {
      valid: false,
      reason: `LAYER_9_TOKENIZER: Reconstructed query contains forbidden identifier '${tokCheckReconstructed.found}'`
    };
  }

  return { valid: true, safeQuery, tables: [...tables] };
}

module.exports = { validateAST };
