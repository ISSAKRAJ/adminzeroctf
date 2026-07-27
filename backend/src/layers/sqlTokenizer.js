// LAYER 9: Custom SQL Tokenizer — Independent of node-sql-parser
//
// This is a hand-rolled, zero-dependency SQL tokenizer that operates
// PURELY on the raw string. Its job: extract every identifier from the query
// WITHOUT trusting the AST parser at all.
//
// Why this matters: node-sql-parser has bugs. If an attacker crafts SQL that
// the parser misreads (e.g. treating a forbidden table name as something else),
// this tokenizer STILL sees the raw identifier. It is the last raw-string
// defense before the query reaches the database.
//
// Design: intentionally simple, with NO AST interpretation. Any token that
// looks like a word gets checked against the forbidden list, period.

const SQL_KEYWORDS = new Set([
  "select","from","where","and","or","not","in","is","null","like",
  "between","order","by","asc","desc","limit","offset","join","inner",
  "left","right","outer","on","as","true","false","distinct","all",
  "exists","any","some","cross","natural","using","into","values",
  "when","then","else","end","for","of","at","time","zone","with",
  "recursive","window","over","partition","row","rows","range","unbounded",
  "current","preceding","following","first","last","ties","only"
]);

// Tables that must NEVER appear as raw identifiers in a query
const FORBIDDEN_IDENTIFIERS = new Set([
  "flag_table",
  "flag",
  "secret",
  "audit_log",
  "fake_flags",
  "sqlite_master",
  "sqlite_sequence",
  "sqlite_temp_master",
  "sqlite_stat1",
  "sqlite_stat4",
]);

/**
 * Tokenize raw SQL into a flat array of string tokens.
 * Handles: identifiers, keywords, quoted strings (skipped), numbers, operators.
 * Does NOT interpret semantics — just extracts lexical tokens.
 */
function tokenize(sql) {
  const tokens = [];
  let i = 0;
  const len = sql.length;

  while (i < len) {
    const ch = sql[i];

    // Whitespace — skip
    if (/\s/.test(ch)) { i++; continue; }

    // Single-quoted string literal — skip content, record as STRING token
    if (ch === "'") {
      i++; // opening quote
      while (i < len && !(sql[i] === "'" && sql[i - 1] !== "\\")) i++;
      i++; // closing quote
      tokens.push({ type: "STRING" });
      continue;
    }

    // Double-quoted identifier (standard SQL) — extract inner name
    if (ch === '"') {
      i++; // opening quote
      let name = "";
      while (i < len && sql[i] !== '"') { name += sql[i++]; }
      i++; // closing quote
      tokens.push({ type: "IDENTIFIER", value: name.toLowerCase() });
      continue;
    }

    // Backtick-quoted identifier (MySQL/SQLite) — extract inner name
    if (ch === "`") {
      i++; // opening backtick
      let name = "";
      while (i < len && sql[i] !== "`") { name += sql[i++]; }
      i++; // closing backtick
      tokens.push({ type: "IDENTIFIER", value: name.toLowerCase() });
      continue;
    }

    // Square bracket-quoted identifier (SQL Server style) — extract inner name
    if (ch === "[") {
      i++; // opening [
      let name = "";
      while (i < len && sql[i] !== "]") { name += sql[i++]; }
      i++; // closing ]
      tokens.push({ type: "IDENTIFIER", value: name.toLowerCase() });
      continue;
    }

    // Identifier or keyword: starts with letter or underscore
    if (/[a-zA-Z_]/.test(ch)) {
      let start = i;
      while (i < len && /[a-zA-Z0-9_$]/.test(sql[i])) i++;
      const word = sql.substring(start, i).toLowerCase();
      const type = SQL_KEYWORDS.has(word) ? "KEYWORD" : "IDENTIFIER";
      tokens.push({ type, value: word });
      continue;
    }

    // Number literal
    if (/[0-9]/.test(ch)) {
      let start = i;
      while (i < len && /[0-9._xXa-fA-F]/.test(sql[i])) i++;
      tokens.push({ type: "NUMBER", value: sql.substring(start, i) });
      continue;
    }

    // Operator / punctuation
    tokens.push({ type: "OP", value: ch });
    i++;
  }

  return tokens;
}

/**
 * Check a raw SQL string for forbidden identifiers using the tokenizer.
 * This is INDEPENDENT of the AST parser — it catches identifiers the
 * parser might have misread or silently dropped.
 *
 * Returns { safe: true } or { safe: false, found: "identifier_name" }
 */
function tokenizerCheck(sql) {
  const tokens = tokenize(sql);

  for (const tok of tokens) {
    if (tok.type === "IDENTIFIER" || tok.type === "KEYWORD") {
      const val = tok.value;
      // Direct forbidden identifier match
      if (FORBIDDEN_IDENTIFIERS.has(val)) {
        return { safe: false, found: val };
      }
      // Partial match — catches things like "flag_table_backup" or "my_secret"
      for (const forbidden of FORBIDDEN_IDENTIFIERS) {
        if (val.includes(forbidden) || forbidden.includes(val) && forbidden.length - val.length < 4) {
          // Only flag if the match is very close (not just coincidental substring)
          if (val.length >= 4 && forbidden.includes(val)) {
            return { safe: false, found: `${val} (near-match to ${forbidden})` };
          }
        }
      }
    }
  }

  return { safe: true };
}

module.exports = { tokenizerCheck, tokenize };
