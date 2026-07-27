// LAYER 2: Encoding Attack Detector
// Catches hex encoding, unicode tricks, URL encoding, null bytes,
// and other obfuscation vectors.
// IMPORTANT: Do NOT use /g flag on patterns — global regexes are stateful
// in JS and will give wrong results on repeated .test() calls.

const ENCODING_PATTERNS = [
  // Hex literals (0x...)
  { pattern: /0x[0-9a-fA-F]+/,           reason: "HEX_ENCODING" },
  // URL encoding (%XX)
  { pattern: /%[0-9a-fA-F]{2}/,           reason: "URL_ENCODING" },
  // Double URL encoding (%25XX)
  { pattern: /%25[0-9a-fA-F]{2}/,         reason: "DOUBLE_URL_ENCODING" },
  // Unicode escapes (\uXXXX)
  { pattern: /\\u[0-9a-fA-F]{4}/,         reason: "UNICODE_ESCAPE" },
  // Hex escapes (\xXX)
  { pattern: /\\x[0-9a-fA-F]{2}/,         reason: "HEX_ESCAPE" },
  // Null bytes
  { pattern: /\u0000/,                     reason: "NULL_BYTE" },
  // CHAR() function (SQL string encoding trick)
  { pattern: /\bchar\s*\(/i,               reason: "CHAR_FUNCTION" },
  // NCHAR() function
  { pattern: /\bnchar\s*\(/i,              reason: "NCHAR_FUNCTION" },
  // ASCII() function (used in blind extraction)
  { pattern: /\bascii\s*\(/i,              reason: "ASCII_FUNCTION" },
  // CONCAT() / CONCAT_WS() obfuscation
  { pattern: /\bconcat(?:_ws)?\s*\(/i,    reason: "CONCAT_OBFUSCATION" },
  // Binary encoding (0b...)
  { pattern: /0b[01]+/,                    reason: "BINARY_ENCODING" },
  // HTML entity encoding (&#...)
  { pattern: /&#[0-9]+;/,                  reason: "HTML_ENTITY_ENCODING" },
  // Backtick identifier quoting tricks
  { pattern: /`[^`]*`/,                    reason: "BACKTICK_IDENTIFIER" },
  // Hex string literals (x'...' SQLite syntax)
  { pattern: /x'[0-9a-fA-F]+'/i,          reason: "HEX_STRING_LITERAL" },
  // UNHEX / HEX functions
  { pattern: /\b(?:un)?hex\s*\(/i,        reason: "HEX_FUNCTION" },
  // SQLite glob with encoded patterns
  { pattern: /\bglob\s+['"][^'"]*[%_]/i,  reason: "GLOB_PATTERN" },
  // TYPEOF / TYPEOF tricks
  { pattern: /\btypeof\s*\(/i,            reason: "TYPEOF_TRICK" },
];

function detectEncoding(query) {
  for (const { pattern, reason } of ENCODING_PATTERNS) {
    // Always reset lastIndex just in case (defensive)
    if (pattern.lastIndex !== undefined) pattern.lastIndex = 0;
    if (pattern.test(query)) {
      return { detected: true, reason: `LAYER_2_ENCODING: ${reason}` };
    }
  }
  return { detected: false };
}

module.exports = { detectEncoding };
