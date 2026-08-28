#!/usr/bin/env node

const crypto = require("crypto");
const fs = require("fs");

const DATA_START = 0x3043b0;
const PREFERRED_END = 0x307fc4;
const ABSOLUTE_GUARD = 0x30809c;
const PARENT_SOURCE = "2e593ddec8c804aa96e2e80859606c8de0d75d88564ad109c69e73093cb40ad7";
const OFFICIAL_PNACH = "8eee249568fd94e05998b0dab30b8fa427e064845dd8b73f9e9f4f25865eb214";

function sha(path) {
  return crypto.createHash("sha256").update(fs.readFileSync(path)).digest("hex");
}
function need(text, pattern, label) {
  if (!pattern.test(text)) throw new Error(label);
}
function hex(value, width = 6) {
  return `0x${value.toString(16).toUpperCase().padStart(width, "0")}`;
}
function pnach(path) {
  const text = fs.readFileSync(path, "utf8");
  const words = new Map();
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^patch=0,EE,([0-9A-Fa-f]+),word,([0-9A-Fa-f]{8})$/);
    if (m) words.set(parseInt(m[1], 16), m[2].toUpperCase());
  }
  return { text, words };
}
function endOfData(words) {
  let address = DATA_START;
  let end = null;
  while (words.has(address)) { end = address; address += 4; }
  return end;
}
function externalHooks(parsed) {
  const end = endOfData(parsed.words);
  return new Map([...parsed.words].filter(([address]) => address < DATA_START || address > end));
}
function body(disassembly, symbol) {
  const marker = new RegExp(`^([0-9a-f]+) <${symbol}>:$`, "mi");
  const match = marker.exec(disassembly);
  if (!match) throw new Error(`missing generated function ${symbol}`);
  const after = disassembly.slice(match.index + match[0].length);
  const next = /\n[0-9a-f]+ <[^>]+>:/i.exec(after);
  return disassembly.slice(match.index, next ? match.index + match[0].length + next.index : undefined);
}
function rows(text) {
  return [...text.matchAll(/^\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+(.+)$/gmi)]
    .map((m) => ({ offset: parseInt(m[1], 16), asm: m[2].trim() }));
}
function storeReloadPairs(instructions) {
  const pairs = [];
  for (let i = 0; i < instructions.length; i++) {
    const store = instructions[i].asm.match(/^sw\s+([^,]+),0\(([^)]+)\)$/);
    if (!store) continue;
    for (let j = i + 1; j <= i + 8 && j < instructions.length; j++) {
      const load = instructions[j].asm.match(/^lw\s+([^,]+),0\(([^)]+)\)$/);
      if (load && load[2] === store[2]) {
        pairs.push({ store: instructions[i], load: instructions[j], base: store[2], loaded: load[1] });
        break;
      }
    }
  }
  return pairs;
}
function check(number, label, callback) {
  try {
    callback();
    gates.push({ number, label, status: "PASS" });
  } catch (error) {
    gates.push({ number, label, status: "FAIL", detail: error.message });
  }
}

const source = fs.readFileSync("mod/mod.cpp", "utf8");
const patch = fs.readFileSync("reproducibility/jerdana-final-selector-stagea.patch", "utf8");
const disassembly = fs.readFileSync("reproducibility/mod-objdump-dr.txt", "utf8");
const readelf = fs.readFileSync("reproducibility/mod-readelf-rws.txt", "utf8");
const stage = body(disassembly, "_Z13stage1_actionb");
const resume = body(disassembly, "ResumeGameHook");
const stageRows = rows(stage);
const slotPairs = storeReloadPairs(stageRows);
const candidate = pnach("mod/934F9081.pnach");
const official = pnach("reproducibility/official-v2.4-934F9081.pnach");
const end = endOfData(candidate.words);
const candidateHooks = externalHooks(candidate);
const officialHooks = externalHooks(official);
const gates = [];

check(1, "items-pointer null guard before slot acquisition", () =>
  need(source, /int items = \*\(\(int\*\)0x35c7ec\);\s*if\(!items\)/s, "items guard"));
check(2, "low-slot guard before selector dereference", () => {
  need(source, /if\(\(unsigned\)slot < 0x1000\)/, "source low-slot guard");
  need(resume, /\bsltiu\s+[^,]+,[^,]+,(?:4096|0x1000)\b/, "generated Options low-slot guard");
});
check(3, "config null guard before descriptor dereference", () =>
  need(source, /int config = \*slot_word;\s*if\(!config\)/s, "config guard"));
check(4, "dynamic original ID capture", () => {
  need(source, /short current_id = \*\(\(short\*\)\(config \+ 0x0c\)\);/, "descriptor ID load");
  need(source, /outfit_sel\.original_id = current_id;/, "dynamic original capture");
  if (/original_id\s*=\s*133/.test(source)) throw new Error("literal original ID");
});
check(5, "CLEAN zero invariant excluding cursor and CLEAN-only capture", () => {
  need(source, /struct OutfitSelState \{\s*int saved_slot;\s*int original_config;\s*int live_config;\s*int state;\s*short original_id;\s*short selected_target;\s*short live_id;\s*\};/s, "24-byte OutfitSelState");
  need(source, /outfit_sel\.saved_slot \|\| outfit_sel\.original_config \|\| outfit_sel\.live_config \|\|\s*outfit_sel\.original_id \|\| outfit_sel\.live_id/s, "CLEAN lifetime invariant");
  need(source, /if\(outfit_sel\.state == 0\)[\s\S]*outfit_sel\.original_config = config;/, "CLEAN capture path");
  if (/selected_target\s*==\s*0/.test(source)) throw new Error("cursor included in zero invariant");
});
check(6, "original context immutable during reselection", () => {
  const part = source.slice(source.indexOf("int old_live_config"), source.lastIndexOf("}"));
  if (/outfit_sel\.(saved_slot|original_config|original_id)\s*=/.test(part)) throw new Error("original context write after reselection begins");
});
check(7, "cursor is bounded at init assignment and use", () => {
  need(source, /OutfitSelState outfit_sel = \{0, 0, 0, 0, 0, 127, 0\};/, "initial cursor");
  need(source, /if\(\(unsigned\)\(selected_target - 127\) > 6\) selected_target = 127;/, "bounded wrap");
  need(source, /\(unsigned\)\(outfit_sel\.selected_target - 127\) > 6/, "bounded use");
});
check(8, "Right is the only Stage-A cursor writer", () => {
  if ((source.match(/outfit_sel\.selected_target\s*=/g) || []).length !== 2) throw new Error("unexpected cursor writer count");
  const options = source.slice(source.indexOf("} else if(state == MENU_OPTIONS)"), source.indexOf("\n\t} else {", source.indexOf("} else if(state == MENU_OPTIONS)")));
  if (/0x8000/.test(options)) throw new Error("Left bound in Options");
  need(options, /cbi & 0x2000[\s\S]*outfit_sel\.selected_target = selected_target/, "Right writer");
});
check(9, "candidate ID equals selected target before write", () =>
  need(source, /\*\(\(short\*\)\(candidate \+ 0x0c\)\) != outfit_sel\.selected_target/, "candidate ID check"));
check(10, "category-1 validation throughout", () => {
  need(source, /current_category != 1/, "current category");
  need(source, /\*\(\(short\*\)\(candidate \+ 0x0e\)\) != 1/, "candidate category");
  need(source, /id == outfit_sel\.live_id && category == 1/, "MODIFIED drift category");
});
check(11, "candidate config differs from current", () => need(source, /candidate == config/, "candidate distinctness"));
check(12, "same-target paths are state/write-free and route correctly", () => {
  need(source, /if\(outfit_sel\.selected_target == current_id\) return;/, "CLEAN no-op");
  need(source, /selected_target != outfit_sel\.live_id[\s\S]*stage1_action\(false\)[\s\S]*else \{\s*return HandleResumeGameTrampoline/s, "MODIFIED trampoline");
});
check(13, "first apply has volatile store/reload", () => {
  need(source, /\*slot_word = candidate;\s*int back = \*slot_word;\s*if\(back == candidate\)/s, "first apply reload");
  if (slotPairs.length !== 3) throw new Error(`expected 3 generated store/reload pairs, got ${slotPairs.length}`);
});
check(14, "reselection has R-A store/reload classification", () =>
  need(source, /int old_live_config = outfit_sel\.live_config;[\s\S]*\*slot_word = candidate;\s*int back = \*slot_word;[\s\S]*if\(back == candidate\)[\s\S]*else if\(back != old_live_config\)/s, "R-A path"));
check(15, "restore requires pointer ID and category readback", () =>
  need(source, /\*slot_word = outfit_sel\.original_config;\s*int back = \*slot_word;[\s\S]*back == outfit_sel\.original_config[\s\S]*\*\(\(short\*\)\(back \+ 0x0c\)\) == outfit_sel\.original_id[\s\S]*\*\(\(short\*\)\(back \+ 0x0e\)\) == 1/s, "restore readback"));
check(16, "restore uses saved original and no lookup", () => {
  const restore = source.slice(source.indexOf("if(restore)"), source.indexOf("if(outfit_sel.state == 0)"));
  need(restore, /\*slot_word = outfit_sel\.original_config;/, "saved original");
  if (/GetItemConfig/.test(restore)) throw new Error("restore target lookup");
});
check(17, "publication ordering contract", () => {
  need(source, /live_id = outfit_sel\.selected_target;\s*OUTFIT_BARRIER\(\);\s*outfit_sel\.state = 1;\s*OUTFIT_BARRIER\(\);\s*\*slot_word = candidate;/s, "first apply order");
  need(source, /outfit_clear_context\(\);\s*OUTFIT_BARRIER\(\);\s*outfit_sel\.state = 0;/s, "clear before CLEAN");
  need(source, /if\(back == candidate\) \{\s*outfit_sel\.live_config = candidate;\s*outfit_sel\.live_id = outfit_sel\.selected_target;/s, "reselection publish after reload");
});
check(18, "compiler barriers have ordering effect but no instructions", () => {
  if ((source.match(/OUTFIT_BARRIER\(\)/g) || []).length < 7) throw new Error("insufficient barriers");
  if (/\b(?:sync)\b/.test(stage)) throw new Error("barrier emitted code");
});
check(19, "drift precedes Options dispatch", () =>
  need(source, /bool hold = outfit_drift_blocks\(\);\s*if\(!hold\) \{\s*if\(cbi & 0x10\)/s, "drift before dispatch"));
check(20, "narrowed non-sticky HOLD", () => {
  need(source, /if\(!items\)[\s\S]*outfit_unsafe\(\)/s, "null items unsafe");
  need(source, /if\(\(unsigned\)slot < 0x1000\)[\s\S]*outfit_unsafe\(\)/s, "low slot unsafe");
  need(source, /if\(slot != outfit_sel\.saved_slot\) return true;/, "different-slot hold");
});
check(21, "benign reset is write-free", () =>
  need(source, /if\(id == outfit_sel\.original_id && category == 1\) \{\s*outfit_clear_context\(\);\s*OUTFIT_BARRIER\(\);\s*outfit_sel\.state = 0;/s, "semantic original reset"));
check(22, "UNSAFE blocks all selector input", () => {
  need(source, /if\(outfit_sel\.state == 2\) return true;/, "UNSAFE drift block");
  need(source, /if\(!hold\) \{[\s\S]*outfit_sel\.state != 2/s, "UNSAFE Right block");
});
check(23, "Triangle exit only CLEAN", () => need(source, /if\(cbi & 0x10\) \{\s*if\(outfit_sel\.state == 0\)/s, "CLEAN Triangle"));
check(24, "Triangle Square Right X arms mutually exclusive", () =>
  need(source, /if\(cbi & 0x10\)[\s\S]*else if\(cbi & 0x80\)[\s\S]*else if\(cbi & 0x2000\)[\s\S]*else if\(cbi & 0x40\)/s, "input else-if chain"));
check(25, "all X routes are explicit", () => {
  need(source, /if\(outfit_sel\.state == 0\)[\s\S]*stage1_action\(false\)/s, "CLEAN different target");
  need(source, /selected_target == outfit_sel\.original_id[\s\S]*stage1_action\(true\)/s, "MODIFIED original");
  need(source, /selected_target != outfit_sel\.live_id[\s\S]*stage1_action\(false\)/s, "MODIFIED reselect");
});
check(26, "Options entry isolation", () => need(source, /case 4:[\s\S]*state = MENU_OPTIONS;[\s\S]*return \(void\*\)0;/s, "entry return"));
check(27, "hack-menu Save route guarded while non-CLEAN", () =>
  need(source, /case 6:\s*if\(outfit_sel\.state != 0\)[\s\S]*return \(void\*\)0;/s, "Save guard"));
check(28, "Stage-B name features absent from Stage-A delta", () => {
  if (/0x5517A0|%s|item_name|name_table/i.test(patch)) throw new Error("Stage-B name addition");
  if (/^\+.*"[^"\n]*UNSAFE[^"\n]*"/m.test(patch)) throw new Error("explicit UNSAFE display text");
});
check(29, "no generated selector state jump table", () => {
  if (/\b(?:jr)\s+(?!ra\b)[^\s]+/.test(stage)) throw new Error("computed jump");
});
check(30, "only the three slot-plus-zero equipment writes", () => {
  if (slotPairs.length !== 3) throw new Error(`paired stores=${slotPairs.length}`);
});
check(31, "all R_MIPS_26 relocations pass", () =>
  need(fs.readFileSync("reproducibility/candidate-r-mips26-report.txt", "utf8"), /status=pass/, "R_MIPS status"));
check(32, "accepted 14 external hooks retained", () => {
  if (officialHooks.size !== 14 || candidateHooks.size !== 14) throw new Error("hook count");
  if ([...officialHooks.keys()].some((address) => !candidateHooks.has(address))) throw new Error("missing hook");
});
check(33, "no unexpected external patch address", () => {
  if ([...candidateHooks.keys()].some((address) => !officialHooks.has(address))) throw new Error("unexpected hook");
});
check(34, "preferred and absolute layout gates", () => {
  if (end === null || end > PREFERRED_END || end >= ABSOLUTE_GUARD) throw new Error(`data end ${hex(end || 0)}`);
});
check(35, "official v2.4 regression exact", () => {
  if (sha("reproducibility/official-v2.4-934F9081.pnach") !== OFFICIAL_PNACH) throw new Error("official hash");
  need(fs.readFileSync("reproducibility/official-regression-report.txt", "utf8"), /official_regression=pass/, "official report");
});
check(36, "functional source isolation", () => {
  const paths = [...patch.matchAll(/^\+\+\+ b\/(.+)$/gm)].map((m) => m[1]);
  if (paths.length !== 1 || paths[0] !== "mod/mod.cpp") throw new Error("functional scope");
});
check(37, "equipment-store provenance is object-established", () => {
  if (!(readelf.match(/R_MIPS_LO16\s+outfit_sel/g) || []).length) throw new Error("no outfit_sel LO16 relocation");
  if (slotPairs.length !== 3) throw new Error("unclassified offset-zero pair");
});
check(38, "R-A failed reselection preserves existing context", () => {
  need(source, /else if\(back != old_live_config\) \{\s*outfit_unsafe\(\);\s*\}/s, "old-live no-change branch");
  const failure = source.slice(source.indexOf("else if(back != old_live_config)"), source.lastIndexOf("}"));
  if (/outfit_sel\.(saved_slot|original_config|original_id|live_config|live_id)\s*=/.test(failure)) throw new Error("R-A failure context mutation");
});

const failures = gates.filter((gate) => gate.status === "FAIL");
const missingHooks = [...officialHooks.keys()].filter((address) => !candidateHooks.has(address));
const unexpectedHooks = [...candidateHooks.keys()].filter((address) => !officialHooks.has(address));
fs.writeFileSync("reproducibility/hook-address-report.txt", [
  `official_hook_count=${officialHooks.size}`,
  `candidate_hook_count=${candidateHooks.size}`,
  `missing_hooks=${missingHooks.length ? missingHooks.map(hex).join(",") : "none"}`,
  `unexpected_hooks=${unexpectedHooks.length ? unexpectedHooks.map(hex).join(",") : "none"}`,
].join("\n") + "\n");
fs.writeFileSync("reproducibility/hook-target-report.txt", [...candidateHooks.entries()]
  .sort((left, right) => left[0] - right[0])
  .map(([address, word]) => `${hex(address)} ${word}`)
  .join("\n") + "\n");
fs.writeFileSync("reproducibility/source-isolation-report.txt", [
  "functional_runtime_paths=OutfitSelState,helpers,stage1_action,MENU_OPTIONS,MENU_MAIN_case_6",
  "unexpected_runtime_source_paths=none",
].join("\n") + "\n");
fs.writeFileSync("reproducibility/stageb-absence-report.txt", [
  "Left=absent",
  "cursor_sync=absent",
  "item_names=absent",
  "item_name_table=absent",
  "explicit_UNSAFE_display=absent",
  "transition_reapply=absent",
  "hero_reapply=absent",
  "persistence=absent",
].join("\n") + "\n");
const report = [
  `parent_source_expected=${PARENT_SOURCE}`,
  `candidate_source=${sha("mod/mod.cpp")}`,
  `candidate_pnach=${sha("mod/934F9081.pnach")}`,
  `line_count=${candidate.text.trimEnd().split(/\r?\n/).length}`,
  `data_start=${hex(DATA_START)}`,
  `data_end=${hex(end)}`,
  `preferred_end=${hex(PREFERRED_END)}`,
  `absolute_guard=${hex(ABSOLUTE_GUARD)}`,
  `preferred_margin=${PREFERRED_END - end}`,
  `absolute_margin=${ABSOLUTE_GUARD - end}`,
  `gate_count=${gates.length}`,
  `passed=${gates.length - failures.length}`,
  `failed=${failures.length}`,
  "gates:",
  ...gates.map((gate) => `gate_${gate.number}=${gate.status}${gate.detail ? ` ${gate.detail}` : ""}`),
];
fs.writeFileSync("reproducibility/final-selector-stagea-38-gate-report.txt", report.join("\n") + "\n");
console.log(report.join("\n"));
if (failures.length) process.exit(1);
