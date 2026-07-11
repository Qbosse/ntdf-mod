const fs = require("fs");

const DATA_START = 0x3043B0;
const DATA_GUARD = 0x30809C;
const PASS1_END = 0x308084;
const PREFERRED_END = 0x307FC4;

function parse(path) {
  const text = fs.readFileSync(path, "utf8");
  const map = new Map();
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^patch=0,EE,([0-9A-Fa-f]+),word,([0-9A-Fa-f]{8})$/);
    if (match) map.set(parseInt(match[1], 16), match[2].toUpperCase());
  }
  return map;
}

function hex(value, width = 6) {
  if (value < 0) return "-0x" + (-value).toString(16).toUpperCase();
  return "0x" + value.toString(16).toUpperCase().padStart(width, "0");
}

function dataEnd(map) {
  let address = DATA_START;
  let last = null;
  while (map.has(address)) {
    last = address;
    address += 4;
  }
  return last;
}

function hooks(map) {
  const end = dataEnd(map);
  const out = new Map();
  for (const [address, value] of map) {
    if (!(address >= DATA_START && end !== null && address <= end)) out.set(address, value);
  }
  return out;
}

function requireSource(source, pattern, label) {
  if (!pattern.test(source)) throw new Error(`missing safety requirement: ${label}`);
}

const official = parse("reproducibility/official-v2.4-934F9081.pnach");
const candidate = parse("mod/934F9081.pnach");
const officialHooks = hooks(official);
const candidateHooks = hooks(candidate);
const officialHookSet = [...officialHooks.keys()].sort((a, b) => a - b);
const candidateHookSet = [...candidateHooks.keys()].sort((a, b) => a - b);
const candidateEnd = dataEnd(candidate);
const unexpected = candidateHookSet.filter((address) => !officialHooks.has(address));
const missing = officialHookSet.filter((address) => !candidateHooks.has(address));
const changed = officialHookSet.filter((address) => candidateHooks.has(address) && officialHooks.get(address) !== candidateHooks.get(address));
const guardPass = candidateEnd !== null && candidateEnd <= DATA_GUARD;
const hookSetsSame = unexpected.length === 0 && missing.length === 0;

fs.writeFileSync("reproducibility/official-patch-addresses.txt", [...official.keys()].sort((a, b) => a - b).map((address) => hex(address)).join("\n") + "\n");
fs.writeFileSync("reproducibility/candidate-patch-addresses.txt", [...candidate.keys()].sort((a, b) => a - b).map((address) => hex(address)).join("\n") + "\n");

const report = [
  `data_start=${hex(DATA_START)}`,
  `data_end=${hex(candidateEnd)}`,
  `guard=${hex(DATA_GUARD)}`,
  `guard_pass=${guardPass ? "yes" : "no"}`,
  `margin_bytes=${DATA_GUARD - candidateEnd}`,
  `margin_hex=${hex(DATA_GUARD - candidateEnd, 1)}`,
  `reduction_from_pass1_bytes=${PASS1_END - candidateEnd}`,
  `reduction_from_pass1_hex=${hex(PASS1_END - candidateEnd, 1)}`,
  `delta_vs_preferred_bytes=${candidateEnd - PREFERRED_END}`,
  `delta_vs_preferred_hex=${hex(candidateEnd - PREFERRED_END, 1)}`,
  `preferred_target_pass=${candidateEnd <= PREFERRED_END ? "yes" : "no"}`,
  `hook_sets_same=${hookSetsSame ? "yes" : "no"}`,
  `candidate_hooks=${candidateHookSet.map((address) => hex(address)).join(",")}`,
  `missing_hook_addresses=${missing.map((address) => hex(address)).join(",") || "none"}`,
  `unexpected_patch_addresses=${unexpected.map((address) => hex(address)).join(",") || "none"}`,
  "changed_hook_target_values:",
];

if (changed.length === 0) {
  report.push("none");
} else {
  for (const address of changed) report.push(`${hex(address)} ${officialHooks.get(address)} -> ${candidateHooks.get(address)}`);
}

fs.writeFileSync("reproducibility/address-report.txt", report.join("\n") + "\n");
console.log(report.join("\n"));

const source = fs.readFileSync("mod/mod.cpp", "utf8");
requireSource(source, /GetCurrentEquipmentSlot\(items, 1\)/, "category 1 lookup");
requireSource(source, /GetItemConfig\(manager, 130\)/, "hardcoded target 130 lookup");
requireSource(source, /\*\(\(short\*\)\(config \+ 0x0c\)\) != 133/, "current item 133 validation");
requireSource(source, /\*\(\(short\*\)\(candidate \+ 0x0c\)\) != 130/, "target item 130 validation");
requireSource(source, /slot != outfit_test\.saved_slot/, "saved slot restore validation");
requireSource(source, /config != outfit_test\.target_config/, "target config restore validation");
requireSource(source, /\*\(\(int\*\)slot\) = outfit_test\.original_config/, "original config restore write");
requireSource(source, /config == outfit_test\.original_config && \*\(\(short\*\)\(config \+ 0x0c\)\) == 133/, "post-restore config and ID verification");
requireSource(source, /outfit_test\.state = 2/, "DONE terminal state");
requireSource(source, /outfit_test\.state = 4/, "WRITEFAIL_SAFE state");
requireSource(source, /\? 1 : 5/, "ACTIVE and ACTIVE_BADID classification");
requireSource(source, /outfit_test\.state = 6/, "UNSAFE state");

if (!guardPass || !hookSetsSame || unexpected.length) process.exit(1);
