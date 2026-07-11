const fs = require("fs");

const DATA_START = 0x3043B0;
const DATA_GUARD = 0x30809C;
const FAILED_END = 0x3082D4;
const CATEGORY_SWEEP_END = 0x307FC4;

function parse(path) {
  const text = fs.readFileSync(path, "utf8");
  const map = new Map();
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^patch=0,EE,([0-9A-Fa-f]+),word,([0-9A-Fa-f]{8})$/);
    if (m) map.set(parseInt(m[1], 16), m[2].toUpperCase());
  }
  return map;
}

function hex(n, width = 6) {
  if (n < 0) return "-0x" + (-n).toString(16).toUpperCase();
  return "0x" + n.toString(16).toUpperCase().padStart(width, "0");
}

function dataEnd(map) {
  let addr = DATA_START;
  let last = null;
  while (map.has(addr)) {
    last = addr;
    addr += 4;
  }
  return last;
}

function hooks(map) {
  const end = dataEnd(map);
  const out = new Map();
  for (const [addr, value] of map) {
    if (!(addr >= DATA_START && end !== null && addr <= end)) out.set(addr, value);
  }
  return out;
}

const official = parse("reproducibility/official-v2.4-934F9081.pnach");
const candidate = parse("mod/934F9081.pnach");
const officialHooks = hooks(official);
const candidateHooks = hooks(candidate);
const officialHookSet = [...officialHooks.keys()].sort((a, b) => a - b);
const candidateHookSet = [...candidateHooks.keys()].sort((a, b) => a - b);
const candidateEnd = dataEnd(candidate);
const unexpected = candidateHookSet.filter((addr) => !officialHooks.has(addr));
const missing = officialHookSet.filter((addr) => !candidateHooks.has(addr));
const changed = officialHookSet.filter((addr) => candidateHooks.has(addr) && officialHooks.get(addr) !== candidateHooks.get(addr));
const guardPass = candidateEnd !== null && candidateEnd <= DATA_GUARD;
const hookSetsSame = unexpected.length === 0 && missing.length === 0;

fs.writeFileSync("reproducibility/official-patch-addresses.txt", [...official.keys()].sort((a, b) => a - b).map(hex).join("\n") + "\n");
fs.writeFileSync("reproducibility/candidate-patch-addresses.txt", [...candidate.keys()].sort((a, b) => a - b).map(hex).join("\n") + "\n");

const report = [
  `data_start=${hex(DATA_START)}`,
  `data_end=${hex(candidateEnd)}`,
  `guard=${hex(DATA_GUARD)}`,
  `guard_pass=${guardPass ? "yes" : "no"}`,
  `margin_bytes=${DATA_GUARD - candidateEnd}`,
  `margin_hex=${hex(DATA_GUARD - candidateEnd, 1)}`,
  `reduction_from_failed_bytes=${FAILED_END - candidateEnd}`,
  `reduction_from_failed_hex=${hex(FAILED_END - candidateEnd, 1)}`,
  `delta_vs_category_sweep_bytes=${candidateEnd - CATEGORY_SWEEP_END}`,
  `delta_vs_category_sweep_hex=${hex(candidateEnd - CATEGORY_SWEEP_END, 1)}`,
  `preferred_target_pass=${candidateEnd <= CATEGORY_SWEEP_END ? "yes" : "no"}`,
  `hook_sets_same=${hookSetsSame ? "yes" : "no"}`,
  `candidate_hooks=${candidateHookSet.map(hex).join(",")}`,
  `missing_hook_addresses=${missing.map(hex).join(",") || "none"}`,
  `unexpected_patch_addresses=${unexpected.map(hex).join(",") || "none"}`,
  "changed_hook_target_values:",
];

if (changed.length === 0) {
  report.push("none");
} else {
  for (const addr of changed) report.push(`${hex(addr)} ${officialHooks.get(addr)} -> ${candidateHooks.get(addr)}`);
}

fs.writeFileSync("reproducibility/address-report.txt", report.join("\n") + "\n");
console.log(report.join("\n"));

if (!guardPass || !hookSetsSame || unexpected.length) process.exit(1);
