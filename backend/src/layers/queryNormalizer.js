// LAYER 12: Query Normalizer
//
// Before any other layer runs, normalize the raw query:
//  - Collapse all whitespace (tabs, newlines, multiple spaces)
//  - Strip Unicode lookalike characters (homoglyph attacks)
//  - Remove zero-width characters
//  - Expand common SQL shorthand forms
//
// This closes the "whitespace trick" and "homoglyph" attack surfaces
// that many WAFs miss because they check the original string.
// The NORMALIZED form is what all subsequent layers validate against.

// Homoglyph map: Unicode chars that look like ASCII SQL characters
// and could fool regex-based detectors
const HOMOGLYPH_MAP = {
  // Cyrillic lookalikes
  "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "r",
  "\u0441": "c", "\u0445": "x", "\u0456": "i",
  "\u0410": "A", "\u0415": "E", "\u041E": "O", "\u0420": "R",
  "\u0421": "C", "\u0425": "X", "\u0406": "I",
  // Greek lookalikes
  "\u03BF": "o", "\u03B5": "e", "\u03B9": "i", "\u03BD": "v",
  // Full-width ASCII (U+FF01..U+FF5E)
  ...Object.fromEntries(
    Array.from({ length: 94 }, (_, i) => [
      String.fromCodePoint(0xFF01 + i),
      String.fromCodePoint(0x21 + i)
    ])
  ),
};

// Zero-width and invisible characters that could be used to split keywords
const INVISIBLE_CHARS = /[\u200B\u200C\u200D\u200E\u200F\uFEFF\u00AD\u034F\u061C\u17B4\u17B5]/g;

/**
 * Normalize a SQL query string.
 * Returns the normalized string to use for all subsequent validation.
 */
function normalizeQuery(query) {
  let q = query;

  // 1. Remove invisible/zero-width characters (used to split keywords)
  q = q.replace(INVISIBLE_CHARS, "");

  // 2. Replace homoglyphs with their ASCII equivalents
  q = q.split("").map(ch => HOMOGLYPH_MAP[ch] || ch).join("");

  // 3. Collapse all whitespace variants to single space
  q = q.replace(/[\t\r\n\f\v]+/g, " ");
  q = q.replace(/  +/g, " ");

  // 4. Trim
  q = q.trim();

  return q;
}

/**
 * Additional normalization for the keyword check pass —
 * generates EXTRA variants that a clever attacker might use
 * to slip past case-sensitive checks.
 */
function generateNormVariants(query) {
  return [
    query,
    query.toUpperCase(),
    query.toLowerCase(),
    query.replace(/\s+/g, ""), // no-space variant (caught by parser but checked again)
  ];
}

module.exports = { normalizeQuery, generateNormVariants };
