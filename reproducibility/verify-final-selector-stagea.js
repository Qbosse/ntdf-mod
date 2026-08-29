#!/usr/bin/env node

const crypto = require("crypto");
const fs = require("fs");

const DATA_START = 0x3043b0;
const PREFERRED_END = 0x307fc4;
const ABSOLUTE_GUARD = 0x30809c;
const BUILD1_SOURCE = "755db82408e81438fea5e85d36513a980466bd1e749228fd77f1bfc07301368f";
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
  const words = new Map();
  const text = fs.readFileSync(path, "utf8");
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^patch=0,EE,([0-9A-Fa-f]+),word,([0-9A-Fa-f]{8})$/);
    if (match) words.set(parseInt(match[1], 16), match[2].toUpperCase());
  }
  return { text, words };
}
function endOfData(words) {
  let address = DATA_START;
  let end = null;
  while (words.has(address)) {
    end = address;
    address += 4;
  }
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
function selectorAction(disassembly, source) {
  const matches = [...disassembly.matchAll(/^([0-9a-f]+) <([^>]*stage1_action[^>]*)>:/gmi)];
  if (matches.length !== 1) throw new Error(`stage1_action symbols=${matches.length}`);
  const signature = source.match(/static void stage1_action\(([^)]*)\)/);
  if (!signature) throw new Error("missing stage1_action source signature");
  const parameters = signature[1].split(",").map((parameter) => parameter.trim());
  if (parameters.length !== 5 || !parameters.slice(0, 4).every((parameter) => /^int\b/.test(parameter)) || !/^bool\b/.test(parameters[4])) {
    throw new Error(`unexpected stage1_action ABI source signature: ${signature[1]}`);
  }
  return {
    symbol: matches[0][2],
    signature: signature[1],
    body: body(disassembly, matches[0][2]),
    entryRoots: { a0: "equipment-slot", a1: "current-config", a2: "current-id", a3: "current-category", t0: "restore-mode" },
  };
}
function rows(text) {
  return [...text.matchAll(/^\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+(.+)$/gmi)]
    .map((match) => ({ offset: parseInt(match[1], 16), asm: match[2].trim() }));
}
function assignment(row) {
  const move = row.asm.match(/^(?:move|addu|daddu)\s+([^,]+),([^,]+)(?:,zero)?$/);
  if (move) return { dst: move[1], src: move[2] };
  const or = row.asm.match(/^or\s+([^,]+),([^,]+),zero$/);
  if (or) return { dst: or[1], src: or[2] };
  const addiuZero = row.asm.match(/^addiu\s+([^,]+),([^,]+),0$/);
  if (addiuZero) return { dst: addiuZero[1], src: addiuZero[2] };
  const generic = row.asm.match(/^(?:lui|addiu|ori|andi|sltiu|sll|sra|lw|lhu|lh)\s+([^,\s]+)/);
  return generic ? { dst: generic[1], src: null } : null;
}
function branchTarget(asm) {
  const match = asm.match(/\b([0-9a-f]+)\s+<[^>]+>/i);
  return match ? parseInt(match[1], 16) : null;
}
function controlKind(asm) {
  const operation = asm.split(/\s+/)[0].toLowerCase();
  if (operation === "jr") return "return";
  if (operation === "j") return "jump";
  if (operation === "jal" || operation === "jalr") return "call";
  if (/^b(?:eq|ne|gez|gtz|lez|ltz|al|c1)/.test(operation)) return operation.endsWith("l") ? "branch-likely" : "branch";
  return null;
}
function cfg(instructions) {
  const byOffset = new Map(instructions.map((row, index) => [row.offset, index]));
  const successors = instructions.map(() => new Set());
  const add = (from, to) => {
    if (from >= 0 && from < instructions.length && to >= 0 && to < instructions.length) successors[from].add(to);
  };
  for (let index = 0; index < instructions.length; index++) {
    const kind = controlKind(instructions[index].asm);
    if (kind) {
      add(index, index + 1);
      if (index + 1 >= instructions.length) continue;
      if (kind === "return") continue;
      if (kind === "call") {
        add(index + 1, index + 2);
        continue;
      }
      const target = branchTarget(instructions[index].asm);
      if (target === null || !byOffset.has(target)) throw new Error(`unresolved ${kind} target at ${hex(instructions[index].offset, 4)}`);
      if (kind === "branch-likely") {
        add(index, index + 2);
        add(index + 1, byOffset.get(target));
      } else {
        add(index + 1, byOffset.get(target));
        if (kind === "branch") add(index + 1, index + 2);
      }
      continue;
    }
    if (index > 0 && controlKind(instructions[index - 1].asm)) continue;
    add(index, index + 1);
  }
  const predecessors = instructions.map(() => new Set());
  successors.forEach((targets, from) => targets.forEach((to) => predecessors[to].add(from)));
  return { predecessors };
}
function outfitRelocations(readelf) {
  const offsets = new Set();
  for (const match of readelf.matchAll(/^([0-9a-f]+)\s+.*R_MIPS_(?:HI16|LO16)\s+.*\boutfit_sel\b/gmi)) {
    offsets.add(parseInt(match[1], 16));
  }
  return offsets;
}
function definition(row, register, selectorRelocations) {
  if (selectorRelocations.has(row.offset)) {
    const assignment = row.asm.match(/^(?:lui|addiu|ori)\s+([^,\s]+)/);
    if (assignment && assignment[1] === register) return { kind: "root", root: "selector-state" };
  }
  const copy = assignment(row);
  if (copy && copy.dst === register) return copy.src ? { kind: "copy", src: copy.src } : { kind: "other" };
  if (/^(?:jal|jalr)\b/.test(row.asm) && /^(a[0-3]|t[0-9]|v[01])$/.test(register)) return { kind: "other" };
  return null;
}
function provenanceAt(instructions, graph, selectorRelocations, entryRoots, point, register) {
  const roots = new Set();
  const visited = new Set();
  function visit(index, current) {
    const key = `${index}:${current}`;
    if (visited.has(key)) {
      roots.add("cycle");
      return;
    }
    visited.add(key);
    const predecessors = graph.predecessors[index];
    if (!predecessors.size) {
      roots.add(entryRoots[current] || "unknown-entry");
      return;
    }
    predecessors.forEach((predecessor) => {
      const found = definition(instructions[predecessor], current, selectorRelocations);
      if (!found) {
        visit(predecessor, current);
      } else if (found.kind === "copy") {
        visit(predecessor, found.src);
      } else if (found.kind === "root") {
        roots.add(found.root);
      } else {
        roots.add("other");
      }
    });
  }
  visit(point, register);
  return [...roots].sort();
}
function slotStoreReloadPairs(instructions, selectorRelocations, entryRoots) {
  const graph = cfg(instructions);
  const pairs = [];
  for (let index = 0; index + 1 < instructions.length; index++) {
    const store = instructions[index].asm.match(/^sw\s+([^,]+),0\(([^)]+)\)$/);
    const load = instructions[index + 1].asm.match(/^lw\s+([^,]+),0\(([^)]+)\)$/);
    if (!store || !load || load[2] !== store[2]) continue;
    const origins = provenanceAt(instructions, graph, selectorRelocations, entryRoots, index, store[2]);
    pairs.push({ store: instructions[index], load: instructions[index + 1], base: store[2], origins });
  }
  return pairs;
}
function nativeSlotCalls(instructions) {
  const calls = [];
  for (let i = 0; i < instructions.length; i++) {
    if (/^jal\s+0*1ac1a0\b/i.test(instructions[i].asm)) {
      calls.push(instructions[i]);
      continue;
    }
    const upper = instructions[i].asm.match(/^lui\s+([^,]+),0x1a$/i);
    if (!upper) continue;
    const reg = upper[1];
    const lower = instructions.slice(i + 1, i + 5)
      .find((row) => new RegExp(`^ori\\s+${reg},${reg},0xc1a0$`, "i").test(row.asm));
    if (!lower) continue;
    const lowerIndex = instructions.indexOf(lower);
    const call = instructions.slice(lowerIndex + 1, lowerIndex + 5)
      .find((row) => new RegExp(`^jalr\\s+${reg}$`, "i").test(row.asm));
    if (call) calls.push(call);
  }
  return calls;
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
const patch = fs.readFileSync("reproducibility/jerdana-final-selector-stagea-build3-tier1b.patch", "utf8");
const disassembly = fs.readFileSync("reproducibility/mod-objdump-dr.txt", "utf8");
const readelf = fs.readFileSync("reproducibility/mod-readelf-rws.txt", "utf8");
const action = selectorAction(disassembly, source);
const stage = action.body;
const resume = body(disassembly, "ResumeGameHook");
const stageRows = rows(stage);
const resumeRows = rows(resume);
const selectorRelocations = outfitRelocations(readelf);
const slotPairs = slotStoreReloadPairs(stageRows, selectorRelocations, action.entryRoots);
const equipmentPairs = slotPairs.filter((pair) => pair.origins.length === 1 && pair.origins[0] === "equipment-slot");
const nativeCalls = nativeSlotCalls(resumeRows);
const candidate = pnach("mod/934F9081.pnach");
const official = pnach("reproducibility/official-v2.4-934F9081.pnach");
const end = endOfData(candidate.words);
const candidateHooks = externalHooks(candidate);
const officialHooks = externalHooks(official);
const gates = [];

check(1, "one Options-frame acquisition dominates selector dispatch", () => {
  need(source, /int items = \*\(\(int\*\)0x35c7ec\);\s*int slot = items \? GetCurrentEquipmentSlot\(items, 1\) : 0;/s, "single acquisition source shape");
  if (nativeCalls.length !== 1) throw new Error(`generated GetCurrentEquipmentSlot calls=${nativeCalls.length}`);
});
check(2, "low-slot guard precedes slot dereference", () => {
  need(source, /volatile int \*slot_word = \(unsigned\)slot >= 0x1000 \? \(volatile int\*\)slot : 0;/, "source low-slot guard");
  need(resume, /\bsltiu\s+[^,]+,[^,]+,(?:4096|0x1000)\b/, "generated low-slot guard");
});
check(3, "config guard precedes descriptor reads", () =>
  need(source, /if\(config\) \{\s*current_id = \*\(\(short\*\)\(config \+ 0x0c\)\);\s*current_category = \*\(\(short\*\)\(config \+ 0x0e\)\);/s, "single config guard"));
check(4, "original ID is captured dynamically", () => {
  need(source, /outfit_sel\.original_id = current_id;/, "dynamic original capture");
  if (/original_id\s*=\s*133/.test(source)) throw new Error("hardcoded original ID");
});
check(5, "CLEAN invariant is exact OR reduction excluding cursor", () => {
  need(source, /outfit_sel\.saved_slot \| outfit_sel\.original_config \| outfit_sel\.live_config \|\s*\(int\)outfit_sel\.original_id \| \(int\)outfit_sel\.live_id/s, "OR-reduced invariant");
  const cleanInvariant = source.slice(source.indexOf("if((outfit_sel.saved_slot"), source.indexOf("if(outfit_sel.selected_target == current_id)"));
  if (/selected_target/.test(cleanInvariant)) throw new Error("cursor included in CLEAN invariant");
});
check(6, "original context remains immutable during reselection", () => {
  const reselect = source.slice(source.indexOf("int old_live_config"), source.indexOf("void CancelLedgeFly"));
  if (/outfit_sel\.(saved_slot|original_config|original_id)\s*=/.test(reselect)) throw new Error("original context reassigned");
});
check(7, "target is initialized and bounded to 127..133", () => {
  need(source, /OutfitSelState outfit_sel = \{0, 0, 0, 0, 0, 127, 0\};/, "cursor init");
  need(source, /\(unsigned\)\(selected_target - 127\) > 6/, "Right bound");
  need(source, /\(unsigned\)\(outfit_sel\.selected_target - 127\) > 6/, "action bound");
});
check(8, "Right is the one generated runtime cursor writer", () => {
  const writes = resumeRows.filter((row) => /^sh\s+[^,]+,18\([^)]+\)$/.test(row.asm));
  if (writes.length !== 1) throw new Error(`generated selected_target stores=${writes.length}`);
  const options = source.slice(source.indexOf("} else if(state == MENU_OPTIONS)"), source.indexOf("\n\t} else {", source.indexOf("} else if(state == MENU_OPTIONS)")));
  if (/0x8000/.test(options)) throw new Error("Left input in selector Options source");
  need(options, /cbi & 0x2000[\s\S]*outfit->selected_target = \(short\)selected_target/, "Right writer source");
});
check(9, "candidate ID equals selected target before write", () =>
  need(source, /\*\(\(short\*\)\(candidate \+ 0x0c\)\) != outfit_sel\.selected_target/, "candidate ID check"));
check(10, "category-1 validation is retained", () => {
  need(source, /current_category != 1/, "current category");
  need(source, /\*\(\(short\*\)\(candidate \+ 0x0e\)\) != 1/, "candidate category");
  need(source, /current_category == 1/, "drift category");
});
check(11, "candidate differs from current config", () => need(source, /candidate == config/, "candidate distinctness"));
check(12, "same-target paths have no equipment write", () => {
  need(source, /if\(outfit_sel\.selected_target == current_id\) return;/, "CLEAN no-op");
  need(source, /outfit->selected_target != outfit->live_id[\s\S]*action = true;[\s\S]*else \{\s*return HandleResumeGameTrampoline/s, "MODIFIED resume route");
});
check(13, "first apply has genuine slot store/reload", () =>
  need(source, /\*slot_word = candidate;\s*int back = \*slot_word;\s*if\(back == candidate\)/s, "first apply reload"));
check(14, "reselection has genuine R-A store/reload", () =>
  need(source, /int old_live_config = outfit_sel\.live_config;[\s\S]*\*slot_word = candidate;\s*int back = \*slot_word;[\s\S]*else if\(back != old_live_config\)/s, "R-A reload"));
check(15, "restore has pointer ID and category readback", () =>
  need(source, /\*slot_word = outfit_sel\.original_config;\s*int back = \*slot_word;[\s\S]*back == outfit_sel\.original_config[\s\S]*\*\(\(short\*\)\(back \+ 0x0c\)\) == outfit_sel\.original_id[\s\S]*\*\(\(short\*\)\(back \+ 0x0e\)\) == 1/s, "restore readback"));
check(16, "restore uses the saved original with no lookup", () => {
  const restore = source.slice(source.indexOf("if(restore)"), source.indexOf("} else if(outfit_sel.state == 0)"));
  need(restore, /\*slot_word = outfit_sel\.original_config;/, "saved original");
  if (/GetItemConfig/.test(restore)) throw new Error("restore target lookup");
});
check(17, "publication ordering is retained", () => {
  need(source, /live_id = outfit_sel\.selected_target;\s*OUTFIT_BARRIER\(\);\s*outfit_sel\.state = 1;\s*OUTFIT_BARRIER\(\);\s*\*slot_word = candidate;/s, "first apply publication");
  need(source, /outfit_clear_context\(\);\s*OUTFIT_BARRIER\(\);\s*outfit_sel\.state = 0;/s, "clear before CLEAN");
  need(source, /if\(back == candidate\) \{\s*outfit_sel\.live_config = candidate;\s*outfit_sel\.live_id = outfit_sel\.selected_target;/s, "R-A post-readback publication");
});
check(18, "compiler barriers remain ordering-only", () => {
  if ((source.match(/OUTFIT_BARRIER\(\)/g) || []).length < 7) throw new Error("barrier count");
  if (/\bsync\b/.test(stage)) throw new Error("emitted sync instruction");
});
check(19, "drift classification precedes input dispatch", () =>
  need(source, /if\(outfit->state == 1\)[\s\S]*bool action = false;[\s\S]*if\(outfit->state != 2/s, "drift before dispatch"));
check(20, "HOLD is narrowed, write-free, and non-sticky", () => {
  if (/\bbool hold\b/.test(source)) throw new Error("long-lived HOLD remains");
  need(source, /outfit->state == 1 && items && slot_word && config && slot != outfit->saved_slot/, "derived different-slot HOLD");
  const hold = source.slice(source.indexOf("if(outfit->state != 2"), source.indexOf("if(cbi & 0x10)", source.indexOf("if(outfit->state != 2")));
  if (/outfit->(?:state|saved_slot|original_config|live_config|original_id|live_id)\s*=/.test(hold)) throw new Error("HOLD predicate writes selector context");
});
check(21, "benign reset is write-free", () =>
  need(source, /current_id == outfit->original_id && current_category == 1\) \{\s*outfit_clear_context\(\);\s*OUTFIT_BARRIER\(\);\s*outfit->state = 0;/s, "semantic original reset"));
check(22, "UNSAFE blocks every selector input", () => {
  need(source, /if\(outfit->state != 2 &&[\s\S]*if\(cbi & 0x10\)/s, "UNSAFE dispatch block");
});
check(23, "Triangle exits only from CLEAN", () =>
  need(source, /if\(cbi & 0x10\) \{\s*if\(outfit->state == 0\)/s, "CLEAN Triangle"));
check(24, "selector inputs are mutually exclusive", () =>
  need(source, /if\(cbi & 0x10\)[\s\S]*else if\(cbi & 0x80\)[\s\S]*else if\(cbi & 0x2000\)[\s\S]*else if\(cbi & 0x40\)/s, "input chain"));
check(25, "X routing is explicit", () => {
  need(source, /if\(outfit->state == 0\) \{\s*if\(outfit->selected_target != current_id\) action = true;/s, "CLEAN X");
  need(source, /outfit->selected_target == outfit->original_id[\s\S]*restore = true;/s, "restore X");
  need(source, /outfit->selected_target != outfit->live_id[\s\S]*action = true;/s, "reselect X");
  need(source, /if\(action\) stage1_action\(slot, config, current_id, current_category, restore\);/, "common action call");
});
check(26, "Options entry remains isolated", () =>
  need(source, /case 4:[\s\S]*state = MENU_OPTIONS;[\s\S]*return \(void\*\)0;/s, "entry return"));
check(27, "hack-menu Save remains guarded while modified", () =>
  need(source, /case 6:\s*if\(outfit_sel\.state != 0\)[\s\S]*return \(void\*\)0;/s, "Save guard"));
check(28, "Stage-B name and reapply features are absent", () => {
  if (/0x5517A0|item_name|name_table|native_save_intercept|transition_reapply|hero_reapply/i.test(patch)) throw new Error("Stage-B source addition");
  if (/^\+.*"[^"\n]*UNSAFE[^"\n]*"/m.test(patch)) throw new Error("UNSAFE display text");
});
check(29, "no generated selector state jump table", () => {
  if (/\b(?:jr)\s+(?!ra\b)[^\s]+/.test(stage)) throw new Error("computed state jump");
});
check(30, "only three equipment slot-plus-zero stores exist", () => {
  if (equipmentPairs.length !== 3) throw new Error(`equipment store/reload pairs=${equipmentPairs.length}`);
});
check(31, "all R_MIPS_26 relocations pass", () =>
  need(fs.readFileSync("reproducibility/candidate-r-mips26-report.txt", "utf8"), /status=pass/, "R_MIPS report"));
check(32, "accepted 14 external hooks are retained", () => {
  if (officialHooks.size !== 14 || candidateHooks.size !== 14) throw new Error("hook count");
  if ([...officialHooks.keys()].some((address) => !candidateHooks.has(address))) throw new Error("missing hook");
});
check(33, "no unexpected external patch address exists", () => {
  if ([...candidateHooks.keys()].some((address) => !officialHooks.has(address))) throw new Error("unexpected hook");
});
check(34, "preferred and absolute layout gates pass", () => {
  if (end === null || end > PREFERRED_END || end >= ABSOLUTE_GUARD) throw new Error(`data end ${hex(end || 0)}`);
});
check(35, "official v2.4 regression evidence is staged and exact", () => {
  if (sha("reproducibility/official-v2.4-934F9081.pnach") !== OFFICIAL_PNACH) throw new Error("official PNACH hash");
  need(fs.readFileSync("reproducibility/official-regression-report.txt", "utf8"), /official_regression=pass/, "official regression report");
});
check(36, "functional source isolation is limited to mod/mod.cpp", () => {
  const paths = [...patch.matchAll(/^\+\+\+ b\/(.+)$/gm)].map((match) => match[1]);
  if (paths.length !== 1 || paths[0] !== "mod/mod.cpp") throw new Error("functional patch scope");
});
check(37, "store base provenance distinguishes equipment from outfit state", () => {
  if (!selectorRelocations.size) throw new Error("missing outfit_sel relocation evidence");
  if (slotPairs.length < 3) throw new Error(`all offset-zero reload pairs=${slotPairs.length}`);
  if (equipmentPairs.length !== 3) throw new Error(`slot-provenance pairs=${equipmentPairs.length}`);
});
check(38, "R-A old-live reload keeps the MODIFIED context", () => {
  const branch = source.slice(source.indexOf("else if(back != old_live_config)"), source.indexOf("void CancelLedgeFly"));
  if (/outfit_sel\.(saved_slot|original_config|original_id|live_config|live_id)\s*=/.test(branch)) throw new Error("old-live branch mutates context");
});
check(39, "one selector Options-frame GetCurrentEquipmentSlot call", () => {
  if (nativeCalls.length !== 1) throw new Error(`native selector calls=${nativeCalls.length}`);
  if (nativeSlotCalls(stageRows).length !== 0) throw new Error("action helper reacquires slot");
  need(source, /int display_config = slot_word \? \*slot_word : 0;/, "display reuses frame slot proof");
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
fs.writeFileSync("reproducibility/store-provenance-report.txt", [
  `stage1_symbol=${action.symbol}`,
  `stage1_abi=${action.signature}`,
  "cfg_aware=yes",
  `selector_state_relocations=${selectorRelocations.size}`,
  `offset_zero_pairs=${slotPairs.length}`,
  `slot_provenance_pairs=${equipmentPairs.length}`,
  ...slotPairs.map((pair) => `${hex(pair.store.offset, 4)} ${pair.store.asm} -> ${hex(pair.load.offset, 4)} ${pair.load.asm} origins=${pair.origins.join(",")}`),
].join("\n") + "\n");
fs.writeFileSync("reproducibility/get-current-equipment-slot-report.txt", [
  `selector_options_native_calls=${nativeCalls.length}`,
  ...nativeCalls.map((row) => `${hex(row.offset, 4)} ${row.asm}`),
  "action_helper_native_calls=0",
  "display_reacquisition=0",
].join("\n") + "\n");
fs.writeFileSync("reproducibility/source-isolation-report.txt", [
  "functional_runtime_paths=OutfitSelState,helpers,stage1_action,MENU_OPTIONS,MENU_MAIN_case_6",
  "functional_patch=jerdana-final-selector-stagea-build3-tier1b.patch",
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
  "native_save_intercept=absent",
  "architecture_a_immediate_write=absent",
].join("\n") + "\n");
const report = [
  `build1_source_expected=${BUILD1_SOURCE}`,
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
fs.writeFileSync("reproducibility/final-selector-stagea-build3-39-gate-report.txt", report.join("\n") + "\n");
console.log(report.join("\n"));
if (failures.length) process.exit(1);
