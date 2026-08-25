#!/usr/bin/env node

const crypto = require("crypto");
const fs = require("fs");

const DATA_START = 0x3043b0;
const DATA_GUARD = 0x30809c;
const PREFERRED_END = 0x307fc4;
const EXPECTED_PARENT = {
  source: "ace19be88030e2955b891ce7061a1ff194939fc6039204957bcea803b8adc15e",
  pnach: "89eb7456718ad72c8c2325ebf848adbffd164202ba2e1b72b72ff7db6538632f",
  elf: "b33308d5bf969d2c8778d85babfe50c13ce3b1b089608f2e82b2c3b36fd18cb2",
  patchC: "0bce6c026a0a484e25590d7066021698be0c4d16a5502918acb9488ce9c2bebe",
  modIi: "6bef961da8a6e93009f201ed40c3dca37046c4fe9bcdaa766b3d299e10a27fe6",
  modS: "d82d7967a02ec09be76a4d28db78522bb42e46ae05ed617b66c760eb53067e1e",
  modO: "14316a7a59700c45b44739985d9e5d0ae1a11579d27f0787c076d3ba5315863a",
};

function sha256(path) {
  return crypto.createHash("sha256").update(fs.readFileSync(path)).digest("hex");
}

function requireEqual(actual, expected, label) {
  if (actual !== expected) throw new Error(`${label}: ${actual} != ${expected}`);
}

function requireMatch(text, pattern, label) {
  if (!pattern.test(text)) throw new Error(`missing requirement: ${label}`);
}

function hex(value, width = 6) {
  return `0x${value.toString(16).toUpperCase().padStart(width, "0")}`;
}

function parsePnach(path) {
  const text = fs.readFileSync(path, "utf8");
  const words = new Map();
  let patchLines = 0;
  for (const line of text.split(/\r?\n/)) {
    if (!line.startsWith("patch=")) continue;
    patchLines++;
    const match = line.match(/^patch=0,EE,([0-9A-Fa-f]+),word,([0-9A-Fa-f]{8})$/);
    if (!match) throw new Error(`unexpected PNACH patch form: ${line}`);
    words.set(parseInt(match[1], 16), match[2].toUpperCase());
  }
  return { text, words, patchLines };
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

function hooks(parsed) {
  const end = dataEnd(parsed.words);
  return new Map([...parsed.words].filter(([address]) => address < DATA_START || address > end));
}

function writeAddresses(path, words) {
  fs.writeFileSync(path, [...words.keys()].sort((a, b) => a - b).map((address) => hex(address)).join("\n") + "\n");
}

function functionText(disassembly, name) {
  const marker = new RegExp(`^([0-9a-f]+) <${name}>:$`, "mi");
  const match = marker.exec(disassembly);
  if (!match) throw new Error(`generated function not found: ${name}`);
  const start = match.index;
  const after = disassembly.slice(start + match[0].length);
  const next = /\n[0-9a-f]+ <[^>]+>:/i.exec(after);
  return disassembly.slice(start, next ? start + match[0].length + next.index : undefined);
}

function instructions(functionBody) {
  const out = [];
  for (const line of functionBody.split(/\r?\n/)) {
    const match = line.match(/^\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+(.+)$/i);
    if (match) out.push({ offset: parseInt(match[1], 16), asm: match[2].trim() });
  }
  return out;
}

function slotStoreLoads(stageInstructions) {
  const stores = [];
  for (let index = 0; index < stageInstructions.length; index++) {
    const store = stageInstructions[index].asm.match(/^sw\s+([^,]+),0\(s0\)$/);
    if (!store) continue;
    const loadIndex = stageInstructions.findIndex((instruction, candidateIndex) =>
      candidateIndex > index && candidateIndex <= index + 6 && /^lw\s+[^,]+,0\(s0\)$/.test(instruction.asm)
    );
    if (loadIndex < 0) throw new Error(`slot store at .text+${hex(stageInstructions[index].offset)} lacks immediate volatile reload`);
    const load = stageInstructions[loadIndex].asm.match(/^lw\s+([^,]+),0\(s0\)$/);
    stores.push({ store: stageInstructions[index], load: stageInstructions[loadIndex], loadedRegister: load[1] });
  }
  return stores;
}

const parentRoot = "reproducibility/previous/parent/mod";
const parentPaths = {
  source: `${parentRoot}/mod.cpp`,
  pnach: `${parentRoot}/934F9081.pnach`,
  elf: `${parentRoot}/df_hack.elf`,
  patchC: `${parentRoot}/loader/patch.c`,
  modIi: `${parentRoot}/mod.ii`,
  modS: `${parentRoot}/mod.s`,
  modO: `${parentRoot}/mod.o`,
};
for (const [name, expected] of Object.entries(EXPECTED_PARENT)) {
  requireEqual(sha256(parentPaths[name]), expected, `corrected parent ${name} identity`);
}
requireEqual(sha256("reproducibility/previous/parent-source/mod.cpp"), EXPECTED_PARENT.source, "reconstructed parent source");

const source = fs.readFileSync("mod/mod.cpp", "utf8");
requireMatch(source, /if\(outfit_test\.state != 0\) return;/, "helper non-READY no-op");
requireMatch(source, /if\(outfit_test\.saved_slot \|\| outfit_test\.original_config \|\| outfit_test\.target_config\)[\s\S]*outfit_test\.state = 3;/, "READY stale-context refusal");
requireMatch(source, /volatile int \*slot_word = \(volatile int\*\)slot;/, "volatile slot word");
requireMatch(source, /\*slot_word = candidate;\s*int active_config = \*slot_word;/, "volatile apply store and reload");
requireMatch(source, /\*slot_word = outfit_test\.original_config;\s*config = \*slot_word;/, "volatile restore store and reload");
requireMatch(source, /active_config == candidate[\s\S]*\? 1 : 5[\s\S]*active_config == config[\s\S]*outfit_test\.state = 4[\s\S]*outfit_test\.state = 6/, "four apply classifications");
requireMatch(source, /config == outfit_test\.original_config && \*\(\(short\*\)\(config \+ 0x0c\)\) == 133/, "restore ID from reloaded pointer");
requireMatch(source, /if\(outfit_test\.state == 0\)[\s\S]*stage1_action\(false\);[\s\S]*else if\(outfit_test\.state == 1\)[\s\S]*return HandleResumeGameTrampoline\(a0, a1, a2, a3, t0\);/, "mutually exclusive READY apply and ACTIVE preview return");
requireMatch(source, /else if\(cbi & 0x80\)[\s\S]*stage1_action\(true\);[\s\S]*else if\(cbi & 0x40\)/, "Square-before-X dispatch priority");
requireMatch(source, /#define OUTFIT_UNRESOLVED\(\) \(outfit_test\.state == 1 \|\| outfit_test\.state > 4\)/, "Triangle blocked for 1, 5, 6");
requireMatch(source, /case 4:[\s\S]*state = MENU_OPTIONS;[\s\S]*break;[\s\S]*return \(void\*\)0;/, "Options entry returns without same-frame fallthrough");
requireMatch(source, /GetCurrentEquipmentSlot\(items, 1\)/, "category 1 only");
requireMatch(source, /GetItemConfig\(manager, 130\)/, "target 130 only");
if ((source.match(/stage1_action\(false\)/g) || []).length !== 1) throw new Error("unexpected apply call-site count");
if ((source.match(/^\s*return HandleResumeGameTrampoline\(a0, a1, a2, a3, t0\);/gm) || []).length !== 3) throw new Error("expected exactly three active trampoline return call sites");
if (/\*\(\(short\*\)[^;\n]*0x0c[^;\n]*\)\)\s*=(?!=)/.test(source)) throw new Error("config+0x0C write found");

const official = parsePnach("reproducibility/official-v2.4-934F9081.pnach");
const parent = parsePnach(parentPaths.pnach);
const candidate = parsePnach("mod/934F9081.pnach");
const end = dataEnd(candidate.words);
if (end === null || end > DATA_GUARD) throw new Error("absolute data guard failed");
if (end > PREFERRED_END) throw new Error("preferred 0xD8 margin gate failed");
const officialHooks = hooks(official);
const parentHooks = hooks(parent);
const candidateHooks = hooks(candidate);
if (officialHooks.size !== 14 || parentHooks.size !== 14 || candidateHooks.size !== 14) throw new Error("expected exactly 14 external hooks");
const missing = [...officialHooks.keys()].filter((address) => !candidateHooks.has(address));
const unexpected = [...candidateHooks.keys()].filter((address) => !officialHooks.has(address));
if (missing.length || unexpected.length) throw new Error(`hook set mismatch missing=${missing.map(hex)} unexpected=${unexpected.map(hex)}`);
writeAddresses("reproducibility/official-patch-addresses.txt", official.words);
writeAddresses("reproducibility/parent-patch-addresses.txt", parent.words);
writeAddresses("reproducibility/candidate-patch-addresses.txt", candidate.words);
const changedExternal = [...candidateHooks.keys()].filter((address) => parentHooks.get(address) !== candidateHooks.get(address));
fs.writeFileSync(
  "reproducibility/changed-external-patch-words.txt",
  (changedExternal.length ? changedExternal.map((address) => `${hex(address)} ${parentHooks.get(address)} -> ${candidateHooks.get(address)}`) : ["none"]).join("\n") + "\n"
);

const disassembly = fs.readFileSync("reproducibility/mod-objdump-dr.txt", "utf8");
const stageBody = functionText(disassembly, "_Z13stage1_actionb");
const resumeBody = functionText(disassembly, "ResumeGameHook");
const stageInstructions = instructions(stageBody);
const slotPairs = slotStoreLoads(stageInstructions);
if (slotPairs.length !== 2) throw new Error(`expected exactly two equipment-slot store/reload pairs, found ${slotPairs.length}`);
const [restorePair, applyPair] = slotPairs;
for (const [label, pair] of [["restore", restorePair], ["apply", applyPair]]) {
  const remainder = stageInstructions.filter((instruction) => instruction.offset > pair.load.offset).slice(0, 24).map((instruction) => instruction.asm).join("\n");
  const register = pair.loadedRegister.replace("$", "\\$");
  requireMatch(remainder, new RegExp(`\\b(?:beq|bne|beql|bnel)\\s+${register},|\\b(?:beq|bne|beql|bnel)\\s+[^,]+,${register}`), `${label} loaded pointer comparison`);
  requireMatch(remainder, new RegExp(`\\blh\\s+[^,]+,12\\(${register}\\)`), `${label} item-ID read derives from loaded pointer`);
}
requireMatch(stageBody, /\bli\s+[^,]+,4\b/, "generated WRITEFAIL_SAFE state");
requireMatch(stageBody, /\bli\s+[^,]+,5\b/, "generated ACTIVE_BADID state");
requireMatch(stageBody, /\bli\s+[^,]+,6\b/, "generated UNSAFE state");
requireMatch(resumeBody, /R_MIPS_26\s+HandleResumeGameTrampolineBytes/, "generated ACTIVE preview trampoline relocation");
requireMatch(resumeBody, /andi\s+[^,]+,[^,]+,0x80[\s\S]*andi\s+[^,]+,[^,]+,0x40/, "generated Square-before-X masks");

const lines = candidate.text.trimEnd().split(/\r?\n/).length;
const report = [
  `parent_source=${EXPECTED_PARENT.source}`,
  `candidate_source=${sha256("mod/mod.cpp")}`,
  `parent_pnach=${EXPECTED_PARENT.pnach}`,
  `candidate_pnach=${sha256("mod/934F9081.pnach")}`,
  `candidate_elf=${sha256("mod/df_hack.elf")}`,
  `candidate_patch_c=${sha256("mod/loader/patch.c")}`,
  `candidate_mod_ii=${sha256("mod/mod.ii")}`,
  `candidate_mod_s=${sha256("mod/mod.s")}`,
  `candidate_mod_o=${sha256("mod/mod.o")}`,
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
  `unexpected_external_patch_addresses=none`,
  `changed_external_patch_words=${changedExternal.length}`,
  `restore_slot_sw=${hex(DATA_START + restorePair.store.offset)}`,
  `restore_slot_lw=${hex(DATA_START + restorePair.load.offset)}`,
  `apply_slot_sw=${hex(DATA_START + applyPair.store.offset)}`,
  `apply_slot_lw=${hex(DATA_START + applyPair.load.offset)}`,
  `generated_state4=yes`,
  `generated_state5=yes`,
  `generated_state6=yes`,
  `active_preview_trampoline_relocation=yes`,
  `source_scope_gate=pass`,
];
fs.writeFileSync("reproducibility/stage2-preview-safety-readback-report.txt", report.join("\n") + "\n");
console.log(report.join("\n"));
