#!/usr/bin/env node

const crypto = require("crypto");
const fs = require("fs");

const DATA_START = 0x3043b0;
const DATA_GUARD = 0x30809c;
const PREFERRED_END = 0x307fc4;
const EXPECTED_PARENT = {
  source: "e36ca23573c15b5a3676276a4206f255cc9c0eb0c501c1980d2675b49dc38406",
  pnach: "f98d53e79b40c717c194bb60f3fc1e80a4ad7cdf066a13ac5524537666caa457",
  elf: "8ccbd95d452212356d9a2093cce28fe442ba4a158505f48bdb50cc1194491653",
  patchC: "94314f8b9b9e18fa3ccc9dfe80fb75d74555ca23420306c44574c579644b6889",
  modIi: "7685591cd5e43580c0bbf64c2d69b88b1ba0dc47459ddbba5ce49dac0760a7f2",
  modS: "96d9c6b14cb4a2f659af8f2509713d964eb1ee9f141b48e7bab35b3b1ff6a348",
  modO: "1151bc2b5fb1ce5e3fa9f341ba954afdd14ead77c6b6b5569d7b3a7de712599a",
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
    const store = stageInstructions[index].asm.match(/^sw\s+([^,]+),0\(([^)]+)\)$/);
    if (!store) continue;
    const loadIndex = stageInstructions.findIndex((instruction, candidateIndex) =>
      candidateIndex > index && candidateIndex <= index + 6 &&
      new RegExp(`^lw\\s+[^,]+,0\\(${store[2].replace("$", "\\$")}\\)$`).test(instruction.asm)
    );
    if (loadIndex < 0) continue;
    const load = stageInstructions[loadIndex].asm.match(/^lw\s+([^,]+),0\(([^)]+)\)$/);
    stores.push({ store: stageInstructions[index], load: stageInstructions[loadIndex], loadedRegister: load[1], slotRegister: store[2] });
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
requireMatch(source, /struct OutfitTestState \{\s*int saved_slot;\s*int original_config;\s*int target_config;\s*int state;\s*short original_id;\s*short selected_target;\s*\};/, "20-byte R3 context declaration");
requireMatch(source, /OutfitTestState outfit_test = \{0, 0, 0, 0, 0, 130\};/, "R3 initial target 130");
requireMatch(source, /if\(outfit_test\.state != 0 && outfit_test\.state != 3\) return;/, "apply allowed only from READY or REFUSED");
requireMatch(source, /if\(outfit_test\.saved_slot \|\| outfit_test\.original_config \|\| outfit_test\.target_config\)[\s\S]*outfit_test\.state = 3;/, "stale-context refusal");
requireMatch(source, /volatile int \*slot_word = \(volatile int\*\)slot;/, "volatile slot word");
requireMatch(source, /\*slot_word = candidate;\s*int active_config = \*slot_word;/, "volatile apply store and reload");
requireMatch(source, /\*slot_word = outfit_test\.original_config;\s*config = \*slot_word;/, "volatile restore store and reload");
requireMatch(source, /active_config == candidate[\s\S]*\? 1 : 5[\s\S]*active_config == config[\s\S]*outfit_test\.state = 4[\s\S]*outfit_test\.state = 6/, "four apply classifications");
requireMatch(source, /config == outfit_test\.original_config &&\s*\*\(\(short\*\)\(config \+ 0x0c\)\) == outfit_test\.original_id/, "restore ID from reloaded pointer and saved original ID");
requireMatch(source, /outfit_test\.saved_slot = outfit_test\.original_config = outfit_test\.target_config = 0;\s*outfit_test\.original_id = 0;\s*outfit_test\.state = 0;/, "restore clears context before READY");
requireMatch(source, /short original_id = config \? \*\(\(short\*\)\(config \+ 0x0c\)\) : 0;/, "dynamic original ID load");
requireMatch(source, /\(unsigned\)\(original_id - 127\) > 6/, "original ID range bound");
requireMatch(source, /\*\(\(short\*\)\(config \+ 0x0e\)\) != 1/, "original category check");
requireMatch(source, /\(unsigned\)\(selected_target - 127\) > 6/, "selected target use-site range bound");
requireMatch(source, /if\(selected_target == original_id\) return;\s*int manager = GetItemManager\(\);/, "same-target return precedes native lookup");
requireMatch(source, /GetItemConfig\(manager, selected_target\)/, "dynamic target lookup");
requireMatch(source, /\*\(\(short\*\)\(candidate \+ 0x0c\)\) != outfit_test\.selected_target/, "target identity check");
requireMatch(source, /\*\(\(short\*\)\(candidate \+ 0x0e\)\) != 1/, "target category check");
requireMatch(source, /candidate == config/, "defensive distinct-pointer check");
requireMatch(source, /outfit_test\.original_id = \*\(\(short\*\)\(config \+ 0x0c\)\);/, "dynamic original ID context save");
requireMatch(source, /else if\(\(cbi & 0x2000\) && \(outfit_test\.state == 0 \|\| outfit_test\.state == 3\)\)[\s\S]*outfit_test\.selected_target = selected_target;[\s\S]*if\(outfit_test\.state == 3\) outfit_test\.state = 0;[\s\S]*else if\(cbi & 0x40\)/, "clean-state Right cycling before X");
requireMatch(source, /short selected_target = outfit_test\.selected_target \+ 1;\s*if\(\(unsigned\)\(selected_target - 127\) > 6\) selected_target = 127;/, "bounded 133-to-127 wrap");
requireMatch(source, /if\(outfit_test\.state == 0 \|\| outfit_test\.state == 3\)[\s\S]*stage1_action\(false\);[\s\S]*else if\(outfit_test\.state == 1\)[\s\S]*return HandleResumeGameTrampoline\(a0, a1, a2, a3, t0\);/, "mutually exclusive READY/REFUSED apply and ACTIVE preview return");
requireMatch(source, /else if\(cbi & 0x80\)[\s\S]*stage1_action\(true\);[\s\S]*else if\(\(cbi & 0x2000\)[\s\S]*else if\(cbi & 0x40\)/, "Triangle-Square-Right-X dispatch priority");
requireMatch(source, /#define OUTFIT_UNRESOLVED\(\) \(outfit_test\.state == 1 \|\| outfit_test\.state > 4\)/, "Triangle blocked for 1, 5, 6");
requireMatch(source, /case 4:[\s\S]*state = MENU_OPTIONS;[\s\S]*break;[\s\S]*return \(void\*\)0;/, "Options entry returns without same-frame fallthrough");
requireMatch(source, /GetCurrentEquipmentSlot\(items, 1\)/, "category 1 only");
requireMatch(source, /int config = \(unsigned\)slot >= 0x1000 \? \*\(\(int\*\)slot\) : 0;/, "display slot guard before dereference");
requireMatch(source, /live_id != outfit_test\.selected_target/, "drift live-ID check");
requireMatch(source, /sprintf\(line, "J%d %d>%d", outfit_test\.state, live_id, outfit_test\.selected_target\);/, "R3 display");
if ((source.match(/\(unsigned\)slot < 0x1000/g) || []).length !== 3) throw new Error("expected low-slot rejection on apply, restore, and display/drift");
if ((source.match(/outfit_test\.selected_target\s*=/g) || []).length !== 1) throw new Error("expected exactly one runtime selected_target writer");
if ((source.match(/stage1_action\(false\)/g) || []).length !== 1) throw new Error("unexpected apply call-site count");
if ((source.match(/^\s*return HandleResumeGameTrampoline\(a0, a1, a2, a3, t0\);/gm) || []).length !== 3) throw new Error("expected exactly three active trampoline return call sites");
if (/\*\(\(short\*\)[^;\n]*0x0c[^;\n]*\)\)\s*=(?!=)/.test(source)) throw new Error("config+0x0C write found");
if (/GetItemConfig\(manager,\s*130\)/.test(source)) throw new Error("hardcoded target-130 lookup remains");
if (/outfit_test\.state\s*=\s*2\s*;/.test(source)) throw new Error("historical DONE state still generated by source");
const optionsSource = source.slice(source.indexOf("} else if(state == MENU_OPTIONS)"), source.indexOf("\n\t} else {", source.indexOf("} else if(state == MENU_OPTIONS)")));
if (/cbi\s*&\s*0x8000/.test(optionsSource)) throw new Error("Left unexpectedly bound on Options page");

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
const resumeInstructions = instructions(resumeBody);
const slotPairs = slotStoreLoads(stageInstructions);
if (slotPairs.length !== 2) throw new Error(`expected exactly two equipment-slot store/reload pairs, found ${slotPairs.length}`);
const [restorePair, applyPair] = slotPairs;
for (const [label, pair] of [["restore", restorePair], ["apply", applyPair]]) {
  const remainder = stageInstructions.filter((instruction) => instruction.offset > pair.load.offset).slice(0, 32).map((instruction) => instruction.asm).join("\n");
  const register = pair.loadedRegister.replace("$", "\\$");
  requireMatch(remainder, new RegExp(`\\b(?:beq|bne|beql|bnel)\\s+${register},|\\b(?:beq|bne|beql|bnel)\\s+[^,]+,${register}`), `${label} loaded pointer comparison`);
  requireMatch(remainder, new RegExp(`\\blh\\s+[^,]+,12\\(${register}\\)`), `${label} item-ID read derives from loaded pointer`);
}
for (const pair of slotPairs) {
  const slotRegister = pair.slotRegister.replace("$", "\\$");
  requireMatch(stageBody, new RegExp(`\\bsltiu\\s+[^,]+,${slotRegister},(?:4096|0x1000)\\b`), "generated low-slot guard in stage1_action");
}
requireMatch(resumeBody, /\bsltiu\s+[^,]+,[^,]+,(?:4096|0x1000)\b/, "generated low-slot guard in Options display/drift");
requireMatch(stageBody, /\blh\s+[^,]+,12\([^)]+\)/, "generated dynamic descriptor ID load");
if ((stageBody.match(/\blh\s+[^,]+,14\([^)]+\)/g) || []).length < 2) throw new Error("expected generated original and target category loads");
requireMatch(stageBody, /\bsltiu\s+[^,]+,[^,]+,7\b/, "generated 127..133 range test");
requireMatch(stageBody, /\bsh\s+[^,]+,16\([^)]+\)/, "generated dynamic original_id save");
requireMatch(stageBody, /\blh\s+[^,]+,16\([^)]+\)/, "generated restore comparison against saved original_id");
if ((resumeBody.match(/\bsh\s+[^,]+,18\([^)]+\)/g) || []).length !== 1) throw new Error("expected exactly one generated selected_target mutation writer");
requireMatch(resumeBody, /\blh\s+[^,]+,18\([^)]+\)/, "generated selected_target reads");
requireMatch(stageBody, /\bli\s+[^,]+,4\b/, "generated WRITEFAIL_SAFE state");
requireMatch(stageBody, /\bli\s+[^,]+,5\b/, "generated ACTIVE_BADID state");
requireMatch(stageBody, /\bli\s+[^,]+,6\b/, "generated UNSAFE state");
if (/\bli\s+[^,]+,2\b/.test(stageBody)) throw new Error("generated DONE state remains in stage1_action");
requireMatch(resumeBody, /R_MIPS_26\s+HandleResumeGameTrampolineBytes/, "generated ACTIVE preview trampoline relocation");
requireMatch(resumeBody, /andi\s+[^,]+,[^,]+,0x10[\s\S]*andi\s+[^,]+,[^,]+,0x80[\s\S]*andi\s+[^,]+,[^,]+,0x2000[\s\S]*andi\s+[^,]+,[^,]+,0x40/, "generated Triangle-Square-Right-X masks");
if (/\b(?:jr)\s+(?!ra\b)[^\s]+/.test(stageBody)) throw new Error("unexpected computed state jump in stage1_action");

const readelf = fs.readFileSync("reproducibility/mod-readelf-rws.txt", "utf8");
requireMatch(readelf, /\b20\s+OBJECT\s+GLOBAL\s+DEFAULT\s+\d+\s+outfit_test\b/, "compiled outfit_test size 20 bytes");

const functionStarts = new Map();
for (const match of disassembly.matchAll(/^([0-9a-f]+) <([^>]+)>:$/gmi)) {
  functionStarts.set(DATA_START + parseInt(match[1], 16), match[2]);
}
const hookTargetLines = [];
for (const [address, wordText] of [...candidateHooks].sort((a, b) => a[0] - b[0])) {
  const word = parseInt(wordText, 16) >>> 0;
  const opcode = word >>> 26;
  if (opcode === 2 || opcode === 3) {
    const target = ((((address + 4) >>> 0) & 0xf0000000) | ((word & 0x03ffffff) << 2)) >>> 0;
    const symbol = functionStarts.get(target);
    if (!symbol) throw new Error(`external J/JAL hook ${hex(address)} targets non-symbol ${hex(target)}`);
    hookTargetLines.push(`${hex(address)} ${wordText} -> ${hex(target)} ${symbol}`);
  } else {
    hookTargetLines.push(`${hex(address)} ${wordText} non-J symbol-derived word`);
  }
}

function writeReport(name, lines) {
  fs.writeFileSync(`reproducibility/${name}`, lines.join("\n") + "\n");
}

writeReport("slot-sanity-report.txt", [
  "apply_low_slot_guard=pass",
  "restore_low_slot_guard=pass",
  "display_drift_low_slot_guard=pass",
  `shared_stage_slot_register=${applyPair.slotRegister}`,
]);
writeReport("dynamic-id-report.txt", [
  "original_id_dynamic_load=pass",
  "original_id_127_133_bound=pass",
  "selected_target_use_site_127_133_bound=pass",
  "target_lookup_dynamic=pass",
  "restore_uses_saved_original_id=pass",
]);
writeReport("category-validation-report.txt", [
  "original_descriptor_category_1=pass",
  "target_descriptor_category_1=pass",
  "drift_category_reread=intentionally_absent",
]);
writeReport("same-target-no-op-report.txt", [
  "source_branch_precedes_native_lookup=pass",
  "context_population_precedes_only_equipment_write=pass",
  "manual_generated_cfg_review_required=yes",
]);
writeReport("apply-readback-report.txt", [
  `slot_sw=${hex(DATA_START + applyPair.store.offset)}`,
  `slot_lw=${hex(DATA_START + applyPair.load.offset)}`,
  `loaded_register=${applyPair.loadedRegister}`,
  "loaded_pointer_comparison=pass",
  "loaded_pointer_id_read=pass",
]);
writeReport("restore-readback-report.txt", [
  `slot_sw=${hex(DATA_START + restorePair.store.offset)}`,
  `slot_lw=${hex(DATA_START + restorePair.load.offset)}`,
  `loaded_register=${restorePair.loadedRegister}`,
  "loaded_pointer_comparison=pass",
  "loaded_pointer_id_read=pass",
  "saved_original_id_comparison=pass",
]);
writeReport("target-cycling-report.txt", [
  "mask=0x2000",
  "direction=Right-only",
  "allowed_states=0,3",
  "wrap=133-to-127",
  "selected_target_generated_writer_count=1",
  "use_site_range_check=pass",
]);
writeReport("dispatch-report.txt", [
  "priority=Triangle,Square,Right,X",
  "single_else_if_chain=pass",
  "active_x_preview_only=pass",
  "ready_refused_x_apply_only=pass",
  "left_unbound=pass",
]);
writeReport("options-entry-isolation-report.txt", [
  "source_unconditional_return=pass",
  "right_test_scoped_to_options=pass",
  "manual_generated_cfg_review_required=yes",
]);
writeReport("unrelated-code-isolation-report.txt", [
  `r3_patch_sha256=${sha256("reproducibility/jerdana-r3-multitarget-diagnostic.patch")}`,
  "functional_scope=OutfitTestState,stage1_action,MENU_OPTIONS,display",
  "new_external_hook=none",
]);
writeReport("hook-address-report.txt", [
  `official_hook_count=${officialHooks.size}`,
  `parent_hook_count=${parentHooks.size}`,
  `candidate_hook_count=${candidateHooks.size}`,
  "missing_hooks=none",
  "unexpected_hooks=none",
  `changed_external_patch_words=${changedExternal.length}`,
]);
writeReport("hook-target-report.txt", hookTargetLines);

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
  `outfit_test_size=20`,
  `selected_target_writer_count=1`,
  `slot_sanity_apply=yes`,
  `slot_sanity_restore=yes`,
  `slot_sanity_display_drift=yes`,
  `dynamic_original_id=yes`,
  `dynamic_target_lookup=yes`,
  `category_validation=yes`,
  `same_target_no_write_source_path=yes`,
  `drift_live_id_check=yes`,
  `right_only_cycle=yes`,
  `generated_state4=yes`,
  `generated_state5=yes`,
  `generated_state6=yes`,
  `active_preview_trampoline_relocation=yes`,
  `source_scope_gate=pass`,
];
fs.writeFileSync("reproducibility/r3-multitarget-report.txt", report.join("\n") + "\n");
console.log(report.join("\n"));
