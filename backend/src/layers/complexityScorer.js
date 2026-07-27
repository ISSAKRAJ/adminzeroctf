// LAYER 4: AST Complexity Scorer
// Counts AST nodes — rejects queries that are suspiciously deep, complex,
// or have too many sibling branches (wide attacks).

const MAX_NODES = 40;   // was 60
const MAX_DEPTH = 8;    // was 10
const MAX_FANOUT = 12;  // max children at any single node

function countNodes(node, depth = 0, stats = { nodes: 0, maxFanout: 0, depthExceeded: false }) {
  if (!node || typeof node !== "object") return stats;

  // Instant reject on depth overflow
  if (depth > MAX_DEPTH) {
    stats.depthExceeded = true;
    stats.nodes = MAX_NODES + 1; // Force rejection
    return stats;
  }

  stats.nodes += 1;

  const children = [];
  for (const val of Object.values(node)) {
    if (Array.isArray(val)) {
      for (const item of val) {
        if (item && typeof item === "object") children.push(item);
      }
    } else if (val && typeof val === "object") {
      children.push(val);
    }
  }

  // Track fan-out
  if (children.length > stats.maxFanout) stats.maxFanout = children.length;

  for (const child of children) {
    countNodes(child, depth + 1, stats);
    // Early exit if already over budget
    if (stats.nodes > MAX_NODES) return stats;
  }

  return stats;
}

function scoreComplexity(ast) {
  const stats = countNodes(ast);

  if (stats.depthExceeded) {
    return {
      tooComplex: true,
      reason: "Depth limit exceeded"
    };
  }

  if (stats.nodes > MAX_NODES) {
    return {
      tooComplex: true,
      reason: `LAYER_4_COMPLEXITY: ${stats.nodes} AST nodes (max ${MAX_NODES})`
    };
  }

  if (stats.maxFanout > MAX_FANOUT) {
    return {
      tooComplex: true,
      reason: `LAYER_4_FANOUT: ${stats.maxFanout} children on a single node (max ${MAX_FANOUT})`
    };
  }

  return { tooComplex: false, nodeCount: stats.nodes };
}

module.exports = { scoreComplexity };
