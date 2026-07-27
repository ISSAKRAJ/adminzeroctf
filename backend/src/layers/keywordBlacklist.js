// LAYER 3: Keyword Blacklist (runs AFTER encoding detection)
// Comprehensive defense against dangerous SQL patterns, SQLite-specific tricks,
// and prompt injection payloads.
// NOTE: All patterns use no /g flag to avoid stateful regex bugs.

const BLACKLIST = [
  // ─── Execution ────────────────────────────────────────────────────────────
  /\bEXEC\b/i,
  /\bEXECUTE\b/i,
  /\bxp_/i,
  /\bsp_/i,

  // ─── Timing Attacks ───────────────────────────────────────────────────────
  /\bWAITFOR\b/i,
  /\bSLEEP\s*\(/i,
  /\bBENCHMARK\s*\(/i,
  /\bpg_sleep\b/i,
  /\bRANDOMBLOB\s*\(/i,
  /\bZEROBLOB\s*\(/i,

  // ─── File Operations ──────────────────────────────────────────────────────
  /\bLOAD_FILE\s*\(/i,
  /\bOUTFILE\b/i,
  /\bDUMPFILE\b/i,
  /\bINTO\s+FILE\b/i,
  /\bINTO\s+OUTFILE\b/i,
  /\bINTO\s+DUMPFILE\b/i,

  // ─── Stacked / Multi-Statement ────────────────────────────────────────────
  /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|ATTACH|DETACH|PRAGMA)/i,

  // ─── SQL Comments (all forms) ─────────────────────────────────────────────
  /--/,
  /\/\*/,
  /\*\//,
  /#/,
  /\/\*!/,

  // ─── Mutations ────────────────────────────────────────────────────────────
  /\bDROP\b/i,
  /\bDELETE\b/i,
  /\bINSERT\b/i,
  /\bUPDATE\b/i,
  /\bTRUNCATE\b/i,
  /\bALTER\b/i,
  /\bCREATE\b/i,
  /\bREPLACE\b/i,
  /\bMERGE\b/i,
  /\bUPSERT\b/i,

  // ─── Privilege Operations ─────────────────────────────────────────────────
  /\bGRANT\b/i,
  /\bREVOKE\b/i,
  /\bSHUTDOWN\b/i,

  // ─── Schema Leaks ─────────────────────────────────────────────────────────
  /information_schema/i,
  /\bsqlite_master\b/i,
  /\bsqlite_sequence\b/i,
  /\bsqlite_temp_master\b/i,
  /\bsys\./i,
  /\bsysobjects\b/i,

  // ─── SQLite-Specific Dangerous Statements ─────────────────────────────────
  /\bPRAGMA\b/i,
  /\bATTACH\b/i,
  /\bDETACH\b/i,
  /\bVACUUM\b/i,
  /\bREINDEX\b/i,
  /\bANALYZE\b/i,

  // ─── Set Operations (UNION / INTERSECT / EXCEPT) ──────────────────────────
  /\bUNION\b/i,
  /\bINTERSECT\b/i,
  /\bEXCEPT\b/i,

  // ─── CTEs (WITH clause) ───────────────────────────────────────────────────
  /\bWITH\s+\w+\s+AS\s*\(/i,
  /\bRECURSIVE\b/i,

  // ─── Boolean-Based Blind Patterns ─────────────────────────────────────────
  /\bIF\s*\(/i,
  /\bIIF\s*\(/i,
  /\bCASE\s+WHEN\b/i,
  /\bNULLIF\s*\(/i,
  /\bCOALESCE\s*\(/i,

  // ─── Error-Based Extraction ───────────────────────────────────────────────
  /\bEXTRACTVALUE\s*\(/i,
  /\bUPDATEXML\s*\(/i,
  /\bGEOGET\b/i,
  /\bJSON_EXTRACT\s*\(/i,
  /\bJSON_EACH\s*\(/i,

  // ─── Out-of-Band / Dangerous Built-ins ───────────────────────────────────
  /\bLOAD\s+DATA\b/i,
  /\bCURSOR\b/i,
  /\bOPENROWSET\b/i,

  // ─── Substringing / Blind Extraction Functions ────────────────────────────
  /\bSUBSTR\s*\(/i,
  /\bSUBSTRING\s*\(/i,
  /\bMID\s*\(/i,
  /\bINSTR\s*\(/i,
  /\bLENGTH\s*\(/i,
  /\bGROUP_CONCAT\s*\(/i,
  /\bHAVING\b/i,

  // ─── Aggregate / Math Leakage Functions ──────────────────────────────────
  /\bMAX\s*\(/i,
  /\bMIN\s*\(/i,
  /\bSUM\s*\(/i,
  /\bAVG\s*\(/i,
  /\bCOUNT\s*\(/i,
  /\bABS\s*\(/i,
  /\bROUND\s*\(/i,

  // ─── String Manipulation (data extraction via transformation) ─────────────
  /\bUPPER\s*\(/i,
  /\bLOWER\s*\(/i,
  /\bTRIM\s*\(/i,
  /\bLTRIM\s*\(/i,
  /\bRTRIM\s*\(/i,
  /\bREPLACE\s*\(/i,   // Note: REPLACE keyword is already blocked, but REPLACE() function too
  /\bQUOTE\s*\(/i,    // SQLite QUOTE() can expose data in different form
  /\bSPRINTF\s*\(/i,
  /\bFORMAT\s*\(/i,

  // ─── String Concatenation (used to build payloads or leak data) ───────────
  /\|\|/,             // SQL string concat operator: name || ' ' || role

  // ─── Prompt Injection (LLM-targeted) ─────────────────────────────────────
  /ignore\s+(all\s+)?previous\s+instructions?/i,
  /disregard\s+(all\s+)?previous/i,
  /forget\s+(all\s+)?previous/i,
  /system\s*:/i,
  /<\|im_start\|>/i,
  /\[INST\]/i,
  /\[\/INST\]/i,
  /<system>/i,
  /<\/system>/i,
  /\bjailbreak\b/i,
  /\bDAN\s+mode\b/i,
  /act\s+as\s+(?:a\s+)?(?:DAN|unrestricted|unfiltered)/i,
  /you\s+are\s+now\s+(?:a\s+)?(?:DAN|jailbroken)/i,
  /\bprompt\s+injection\b/i,
];

function checkBlacklist(query) {
  for (const pattern of BLACKLIST) {
    // Defensive: reset lastIndex for any accidentally-global patterns
    if (pattern.lastIndex !== undefined) pattern.lastIndex = 0;
    if (pattern.test(query)) {
      return {
        blocked: true,
        reason: `LAYER_3_BLACKLIST: ${pattern.toString().substring(0, 60)}`
      };
    }
  }
  return { blocked: false };
}

module.exports = { checkBlacklist };
