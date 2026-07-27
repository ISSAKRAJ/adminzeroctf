// NEW LAYER: PII Scrubber
// Masks personally identifiable information in query results
// before they are sent back to the client.
// Ensures that even if a valid query hits user data,
// sensitive fields are partially obscured.

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_REGEX = /^\+?[\d\s\-().]{7,20}$/;

// Fields that should always be masked regardless of value format
const SENSITIVE_FIELD_NAMES = new Set([
  "email",
  "phone",
  "mobile",
  "ssn",
  "dob",
  "date_of_birth",
  "address",
  "password",
  "hash",
  "token",
  "secret",
  "api_key",
  "credit_card",
  "card_number",
  "cvv",
  "pin",
]);

function maskEmail(email) {
  if (typeof email !== "string") return email;
  const atIdx = email.indexOf("@");
  if (atIdx < 0) return "***@***.***";
  const local = email.substring(0, atIdx);
  const domain = email.substring(atIdx + 1);
  const maskedLocal = local.length <= 2
    ? local[0] + "***"
    : local[0] + "***" + local[local.length - 1];
  return `${maskedLocal}@${domain}`;
}

function maskPhone(phone) {
  if (typeof phone !== "string") return phone;
  return phone.replace(/\d(?=\d{4})/g, "*");
}

function maskValue(fieldName, value) {
  if (value === null || value === undefined) return value;
  const lower = (fieldName || "").toLowerCase();

  if (SENSITIVE_FIELD_NAMES.has(lower)) {
    if (lower === "email" || (typeof value === "string" && EMAIL_REGEX.test(value))) {
      return maskEmail(String(value));
    }
    if (lower === "phone" || lower === "mobile") {
      return maskPhone(String(value));
    }
    // Generic sensitive field — full mask
    return "***REDACTED***";
  }

  // Auto-detect by value format even if field name is not in the set
  if (typeof value === "string") {
    if (EMAIL_REGEX.test(value)) return maskEmail(value);
    if (PHONE_REGEX.test(value) && value.replace(/\D/g, "").length >= 7) {
      return maskPhone(value);
    }
  }

  return value;
}

/**
 * Scrub PII from an array of row objects.
 * @param {Array<Object>} rows - raw DB rows
 * @returns {Array<Object>} rows with PII fields masked
 */
function scrubRows(rows) {
  if (!Array.isArray(rows)) return rows;
  return rows.map((row) => {
    if (!row || typeof row !== "object") return row;
    const scrubbed = {};
    for (const [key, value] of Object.entries(row)) {
      scrubbed[key] = maskValue(key, value);
    }
    return scrubbed;
  });
}

module.exports = { scrubRows };
