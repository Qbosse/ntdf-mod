#!/usr/bin/env node

const crypto = require("crypto");
const fs = require("fs");

const DATA_START = 0x3043b0;
const DATA_GUARD = 0x30809c;
const PREFERRED_END = 0x307fc4;
const CALL_ADDRESS = 0x305604;
const BAD_CALL = "0C0C10EC";
const CORRECT_CALL = "0C0C11C1";
const EXPECTED_PARENT = {
  pnach: "2df67d2d394a30b9af794dc35f5b236f59f5c6498efc9c1ca7505621859f8d2f",
  elf: "87f706dedc750aad624f7bad017aacc88c40eb4389ee947f622584e22889426a",
  patch: "ed6c9cb3a53a3a3b2b3e1f97a865e6b642da776a22fd23f903cd87442dd2cf9a",
  modIi: "6bef961da8a6e93009f201ed40c3dca37046c4fe9bcdaa766b3d299e10a27fe6",
  modS: "d82d7967a02ec09be76a4d28db78522bb42e46ae05ed617b66c760eb53067e1e",
  modO: "14316a7a59700c45b44739985d9e5d0ae1a11579d27f0787c076d3ba5315863a",
};

function sha256(path) {
  return crypto.createHash("sha256").update(fs.readFileSync(path)).digest("hex");
}

function parse(path) {
  const text = fs.readFileSync(path, "utf8");
  const words = new Map();
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^patch=0,EE,([0-9A-Fa-f]+),word,([0-9A-Fa-f]{8})$/);
    if (match) words.set(parseInt(match[1], 16), match[2].toUpperCase());
  }
  return { text, words };
}

function dataEnd(words) {
  let address = DATA_START;
  let last = null;
  while (words.has(address)) {
    last = address;
    address += 4;
  }
  return last;
}

function hooks(words) {
  const end = dataEnd(words);
  return new Map([...words].filter(([address]) => !(address >= DATA_START && address <= end)));
}

function hex(value, width = 6) {
  return `0x${value.toString(16).toUpperCase().padStart(width, "0")}`;
}

function requireSource(source, pattern, label) {
  if (!pattern.test(source)) throw new Error(`missing Stage-1 safeguard: ${label}`);
}

const parentRoot = "reproducibility/previous/pass3";
const parentPaths = {
  pnach: `${parentRoot}/mod/934F9081.pnach`,
  elf: `${parentRoot}/mod/df_hack.elf`,
  patch: `${parentRoot}/mod/loader/patch.c`,
  modIi: `${parentRoot}/mod/mod.ii`,
  modS: `${parentRoot}/mod/mod.s`,
  modO: `${parentRoot}/mod/mod.o`,
};
for (const [name, expected] of Object.entries(EXPECTED_PARENT)) {
  const actual = sha256(parentPaths[name]);
  if (actual !== expected) throw new Error(`parent ${name} identity mismatch: ${actual}`);
}

if (sha256("mod/mod.ii") !== EXPECTED_PARENT.modIi ||
    sha256("mod/mod.s") !== EXPECTED_PARENT.modS ||
    sha256("mod/mod.o") !== EXPECTED_PARENT.modO) {
  throw new Error("functional Stage-1 compiler outputs changed from pass 3");
}

const parent = parse(parentPaths.pnach);
const candidate = parse("mod/934F9081.pnach");
if (parent.words.get(CALL_ADDRESS) !== BAD_CALL) throw new Error("parent bad call identity mismatch");
if (candidate.words.get(CALL_ADDRESS) !== CORRECT_CALL) throw new Error("corrected Stage-1 call is missing");

const allAddresses = new Set([...parent.words.keys(), ...candidate.words.keys()]);
const differences = [...allAddresses].filter((address) => parent.words.get(address) !== candidate.words.get(address));
if (differences.length !== 1 || differences[0] !== CALL_ADDRESS) {
  throw new Error(`candidate differs from pass 3 outside the authorized relocation word: ${differences.map(hex).join(",")}`);
}

const parentHooks = hooks(parent.words);
const candidateHooks = hooks(candidate.words);
const missingHooks = [...parentHooks.keys()].filter((address) => !candidateHooks.has(address));
const unexpectedHooks = [...candidateHooks.keys()].filter((address) => !parentHooks.has(address));
const changedHooks = [...parentHooks.keys()].filter(
  (address) => candidateHooks.has(address) && parentHooks.get(address) !== candidateHooks.get(address)
);
if (missingHooks.length || unexpectedHooks.length || changedHooks.length) {
  throw new Error("hook address/value comparison failed");
}

const end = dataEnd(candidate.words);
const lines = candidate.text.trimEnd().split(/\r?\n/).length;
if (end > DATA_GUARD || end > PREFERRED_END) throw new Error("candidate layout gate failed");
if (lines !== 3776) throw new Error(`unexpected PNACH line count ${lines}`);

const source = fs.readFileSync("mod/mod.cpp", "utf8");
requireSource(source, /GetCurrentEquipmentSlot\(items, 1\)/, "category 1 lookup");
requireSource(source, /GetItemConfig\(manager, 130\)/, "target item 130 lookup");
requireSource(source, /\*\(\(short\*\)\(config \+ 0x0c\)\) != 133/, "current item 133 validation");
requireSource(source, /\*\(\(short\*\)\(candidate \+ 0x0c\)\) != 130/, "target item 130 validation");
requireSource(source, /slot != outfit_test\.saved_slot/, "saved-slot validation");
requireSource(source, /config != outfit_test\.target_config/, "target-config restore validation");
requireSource(source, /\*\(\(int\*\)slot\) = outfit_test\.original_config/, "non-blind restore write");
requireSource(source, /config == outfit_test\.original_config && \*\(\(short\*\)\(config \+ 0x0c\)\) == 133/, "post-restore verification");
requireSource(source, /outfit_test\.state = 2/, "DONE state");
requireSource(source, /outfit_test\.state = 3/, "REFUSED state");
requireSource(source, /outfit_test\.state = 4/, "WRITEFAIL_SAFE state");
requireSource(source, /\? 1 : 5/, "ACTIVE and ACTIVE_BADID states");
requireSource(source, /outfit_test\.state = 6/, "UNSAFE state");
requireSource(source, /\(cbi & 0x10\) && !OUTFIT_UNRESOLVED\(\)/, "Triangle unresolved block");
requireSource(source, /cbi & 0x80[\s\S]*stage1_action\(true\)/, "Square restore action");
requireSource(source, /cbi & 0x40[\s\S]*stage1_action\(false\)/, "X apply action");
requireSource(source, /sprintf\(line, "J%d id:%d"/, "seven-state diagnostic display");

const report = [
  `parent_pnach=${EXPECTED_PARENT.pnach}`,
  `candidate_pnach=${sha256("mod/934F9081.pnach")}`,
  `candidate_elf=${sha256("mod/df_hack.elf")}`,
  `candidate_patch_c=${sha256("mod/loader/patch.c")}`,
  `line_count=${lines}`,
  `data_start=${hex(DATA_START)}`,
  `data_end=${hex(end)}`,
  `guard=${hex(DATA_GUARD)}`,
  `guard_pass=yes`,
  `margin_bytes=${DATA_GUARD - end}`,
  `margin_hex=${hex(DATA_GUARD - end, 1)}`,
  `preferred_margin_pass=yes`,
  `hook_sets_same=yes`,
  `missing_hooks=none`,
  `unexpected_patch_addresses=none`,
  `changed_hook_values=none`,
  `pnach_word_differences=1`,
  `corrected_call=${hex(CALL_ADDRESS)} ${BAD_CALL}->${CORRECT_CALL}`,
  `stage1_compiler_outputs_identical_to_pass3=yes`,
  `stage1_safeguards_present=yes`,
];
fs.writeFileSync("reproducibility/stage1-corrected-report.txt", report.join("\n") + "\n");
console.log(report.join("\n"));
