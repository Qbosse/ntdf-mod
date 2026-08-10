const crypto = require("crypto");
const fs = require("fs");

const DATA_START = 0x3043B0;
const DATA_GUARD = 0x30809C;
const PASS2_END = 0x30802C;
const PREFERRED_END = 0x307FC4;
const EXPECTED_PASS2_PNACH = "c067a19c1cb3e670ea3bb63506dfdc87449be42d481f880928017f5f88c4b617";
const EXPECTED_PASS2_ELF = "042b0ce2ffa7d47f61ea4b3d461a29ae95150f083520613e6d70dd0dbe2152b7";
const ORIGINAL_ADVICE = "Okay, since you keep coming back here";
const REPLACEMENT_ADVICE = "Ledge fly stopped.\\x01\\x02\\x04\\x04\\x02Wait for full white, then hold ^.";

function parse(path) {
  const text = fs.readFileSync(path, "utf8");
  const map = new Map();
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^patch=0,EE,([0-9A-Fa-f]+),word,([0-9A-Fa-f]{8})$/);
    if (match) map.set(parseInt(match[1], 16), match[2].toUpperCase());
  }
  return map;
}

function sha256(path) {
  return crypto.createHash("sha256").update(fs.readFileSync(path)).digest("hex");
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

const pass2PnachPath = "reproducibility/previous/pass2/mod/934F9081.pnach";
const pass2ElfPath = "reproducibility/previous/pass2/mod/df_hack.elf";
if (sha256(pass2PnachPath) !== EXPECTED_PASS2_PNACH) throw new Error("pass-2 PNACH identity mismatch");
if (sha256(pass2ElfPath) !== EXPECTED_PASS2_ELF) throw new Error("pass-2 ELF identity mismatch");

const official = parse("reproducibility/official-v2.4-934F9081.pnach");
const pass2 = parse(pass2PnachPath);
const candidate = parse("mod/934F9081.pnach");
if (dataEnd(pass2) !== PASS2_END || pass2.size !== 3886) throw new Error("pass-2 layout mismatch");

const officialHooks = hooks(official);
const candidateHooks = hooks(candidate);
const officialHookSet = [...officialHooks.keys()].sort((a, b) => a - b);
const candidateHookSet = [...candidateHooks.keys()].sort((a, b) => a - b);
const candidateEnd = dataEnd(candidate);
const unexpected = candidateHookSet.filter((address) => !officialHooks.has(address));
const missing = officialHookSet.filter((address) => !candidateHooks.has(address));
const changed = officialHookSet.filter((address) => candidateHooks.has(address) && officialHooks.get(address) !== candidateHooks.get(address));
const guardPass = candidateEnd !== null && candidateEnd <= DATA_GUARD;
const preferredPass = candidateEnd !== null && candidateEnd <= PREFERRED_END;
const hookSetsSame = unexpected.length === 0 && missing.length === 0;

fs.writeFileSync("reproducibility/official-patch-addresses.txt", [...official.keys()].sort((a, b) => a - b).map((address) => hex(address)).join("\n") + "\n");
fs.writeFileSync("reproducibility/pass2-patch-addresses.txt", [...pass2.keys()].sort((a, b) => a - b).map((address) => hex(address)).join("\n") + "\n");
fs.writeFileSync("reproducibility/candidate-patch-addresses.txt", [...candidate.keys()].sort((a, b) => a - b).map((address) => hex(address)).join("\n") + "\n");

const report = [
  `data_start=${hex(DATA_START)}`,
  `pass2_end=${hex(PASS2_END)}`,
  `data_end=${hex(candidateEnd)}`,
  `guard=${hex(DATA_GUARD)}`,
  `guard_pass=${guardPass ? "yes" : "no"}`,
  `margin_bytes=${DATA_GUARD - candidateEnd}`,
  `margin_hex=${hex(DATA_GUARD - candidateEnd, 1)}`,
  `reduction_from_pass2_bytes=${PASS2_END - candidateEnd}`,
  `reduction_from_pass2_hex=${hex(PASS2_END - candidateEnd, 1)}`,
  `delta_vs_preferred_bytes=${candidateEnd - PREFERRED_END}`,
  `delta_vs_preferred_hex=${hex(candidateEnd - PREFERRED_END, 1)}`,
  `preferred_target_pass=${preferredPass ? "yes" : "no"}`,
  `hook_sets_same=${hookSetsSame ? "yes" : "no"}`,
  `candidate_hooks=${candidateHookSet.map((address) => hex(address)).join(",")}`,
  `missing_hook_addresses=${missing.map((address) => hex(address)).join(",") || "none"}`,
  `unexpected_patch_addresses=${unexpected.map((address) => hex(address)).join(",") || "none"}`,
  "changed_hook_target_values:",
];

if (changed.length === 0) report.push("none");
else for (const address of changed) report.push(`${hex(address)} ${officialHooks.get(address)} -> ${candidateHooks.get(address)}`);

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
requireSource(source, /outfit_test\.state = 3/, "REFUSED terminal state");
requireSource(source, /outfit_test\.state = 4/, "WRITEFAIL_SAFE state");
requireSource(source, /\? 1 : 5/, "ACTIVE and ACTIVE_BADID classification");
requireSource(source, /outfit_test\.state = 6/, "UNSAFE state");
requireSource(source, /\(cbi & 0x10\) && !OUTFIT_UNRESOLVED\(\)/, "Triangle unresolved-state block");
requireSource(source, /cbi & 0x80[\s\S]*stage1_action\(true\)/, "Square restore action");
requireSource(source, /cbi & 0x40[\s\S]*stage1_action\(false\)/, "X apply action");
requireSource(source, /sprintf\(line, "J%d id:%d"/, "compact diagnostic display");
requireSource(source, /case 3:\s*DisplayDialogText\("Ledge fly stopped\.\\x01\\x02\\x04\\x04\\x02Wait for full white, then hold \^\."\);\s*break;/, "isolated case-3 replacement text");
if (source.includes(ORIGINAL_ADVICE)) throw new Error("original case-3 advice remains");
if (!source.includes(REPLACEMENT_ADVICE)) throw new Error("replacement case-3 advice missing");

if (!guardPass || !preferredPass || !hookSetsSame || unexpected.length || missing.length) process.exit(1);
