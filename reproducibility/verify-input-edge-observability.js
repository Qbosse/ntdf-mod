const crypto = require("crypto");
const fs = require("fs");

const DATA_START = 0x3043B0;
const DATA_GUARD = 0x30809C;
const PREFERRED_MARGIN = 0xD8;
const PASS3_END = 0x307E74;
const PARENT_END = 0x307DCC;
const PASS3_PNACH_SHA256 = "2df67d2d394a30b9af794dc35f5b236f59f5c6498efc9c1ca7505621859f8d2f";
const PASS3_ELF_SHA256 = "87f706dedc750aad624f7bad017aacc88c40eb4389ee947f622584e22889426a";
const PARENT_PNACH_SHA256 = "b4834319ed768306aab777f14cdbd06857568c12b81b743d1d8f9384d0677cf6";
const PARENT_ELF_SHA256 = "3e0c4d679ce963a63d74602565faedf068f15b49475ea60eca71b4c6914b2534";
const PARENT_PATCH_C_SHA256 = "b8d052b99b460539907680c0cf30c42d094b17cc37741a1231335687cf81fd8e";

function sha256(path) {
  return crypto.createHash("sha256").update(fs.readFileSync(path)).digest("hex");
}

function parse(path) {
  const map = new Map();
  for (const line of fs.readFileSync(path, "utf8").split(/\r?\n/)) {
    const match = line.match(/^patch=0,EE,([0-9A-Fa-f]+),word,([0-9A-Fa-f]{8})$/);
    if (match) map.set(parseInt(match[1], 16), match[2].toUpperCase());
  }
  return map;
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
  return new Map([...map].filter(([address]) => !(address >= DATA_START && address <= end)));
}

function hex(value, width = 6) {
  return `0x${value.toString(16).toUpperCase().padStart(width, "0")}`;
}

function requireMatch(text, pattern, label) {
  if (!pattern.test(text)) throw new Error(`missing diagnostic requirement: ${label}`);
}

const pass3Pnach = "reproducibility/previous/pass3/mod/934F9081.pnach";
const pass3Elf = "reproducibility/previous/pass3/mod/df_hack.elf";
const parentPnach = "reproducibility/previous/input-parent/mod/934F9081.pnach";
const parentElf = "reproducibility/previous/input-parent/mod/df_hack.elf";
const parentPatchC = "reproducibility/previous/input-parent/mod/loader/patch.c";
if (sha256(pass3Pnach) !== PASS3_PNACH_SHA256) throw new Error("Pass-3 PNACH identity mismatch");
if (sha256(pass3Elf) !== PASS3_ELF_SHA256) throw new Error("Pass-3 ELF identity mismatch");
if (sha256(parentPnach) !== PARENT_PNACH_SHA256) throw new Error("input-observability parent PNACH identity mismatch");
if (sha256(parentElf) !== PARENT_ELF_SHA256) throw new Error("input-observability parent ELF identity mismatch");
if (sha256(parentPatchC) !== PARENT_PATCH_C_SHA256) throw new Error("input-observability parent patch.c identity mismatch");

const official = parse("reproducibility/official-v2.4-934F9081.pnach");
const pass3 = parse(pass3Pnach);
const parent = parse(parentPnach);
const candidate = parse("mod/934F9081.pnach");
if (dataEnd(pass3) !== PASS3_END) throw new Error("Pass-3 layout mismatch");
if (dataEnd(parent) !== PARENT_END) throw new Error("input-observability parent layout mismatch");

const officialHooks = hooks(official);
const parentHooks = hooks(parent);
const candidateHooks = hooks(candidate);
const expectedHooks = [...parentHooks.keys()].sort((a, b) => a - b);
const actualHooks = [...candidateHooks.keys()].sort((a, b) => a - b);
const missing = expectedHooks.filter((address) => !candidateHooks.has(address));
const unexpected = actualHooks.filter((address) => !parentHooks.has(address));
const changed = expectedHooks.filter((address) => candidateHooks.has(address) && parentHooks.get(address) !== candidateHooks.get(address));
const end = dataEnd(candidate);
const margin = DATA_GUARD - end;
const guardPass = end !== null && end <= DATA_GUARD;
const preferredPass = guardPass && margin >= PREFERRED_MARGIN;

fs.writeFileSync("reproducibility/official-patch-addresses.txt", [...official.keys()].sort((a, b) => a - b).map((address) => hex(address)).join("\n") + "\n");
fs.writeFileSync("reproducibility/pass3-patch-addresses.txt", [...pass3.keys()].sort((a, b) => a - b).map((address) => hex(address)).join("\n") + "\n");
fs.writeFileSync("reproducibility/parent-patch-addresses.txt", [...parent.keys()].sort((a, b) => a - b).map((address) => hex(address)).join("\n") + "\n");
fs.writeFileSync("reproducibility/candidate-patch-addresses.txt", [...candidate.keys()].sort((a, b) => a - b).map((address) => hex(address)).join("\n") + "\n");

const addressReport = [
  `data_start=${hex(DATA_START)}`,
  `pass3_end=${hex(PASS3_END)}`,
  `parent_end=${hex(PARENT_END)}`,
  `data_end=${hex(end)}`,
  `guard=${hex(DATA_GUARD)}`,
  `guard_pass=${guardPass ? "yes" : "no"}`,
  `margin_bytes=${margin}`,
  `margin_hex=${hex(margin, 1)}`,
  `delta_from_pass3_bytes=${end - PASS3_END}`,
  `delta_from_pass3_hex=${end === PASS3_END ? "0x0" : hex(Math.abs(end - PASS3_END), 1)}`,
  `preferred_margin=${hex(PREFERRED_MARGIN, 1)}`,
  `preferred_margin_pass=${preferredPass ? "yes" : "no"}`,
  `hook_sets_same=${missing.length === 0 && unexpected.length === 0 ? "yes" : "no"}`,
  `missing_hook_addresses=${missing.map(hex).join(",") || "none"}`,
  `unexpected_patch_addresses=${unexpected.map(hex).join(",") || "none"}`,
  "changed_hook_target_values:",
  ...(changed.length ? changed.map((address) => `${hex(address)} ${parentHooks.get(address)} -> ${candidateHooks.get(address)}`) : ["none"]),
];
fs.writeFileSync("reproducibility/address-report.txt", addressReport.join("\n") + "\n");
console.log(addressReport.join("\n"));

const source = fs.readFileSync("mod/mod.cpp", "utf8");
const optionsStart = source.indexOf("} else if(state == MENU_OPTIONS) {");
const optionsEnd = source.indexOf("\n\t} else {", optionsStart);
if (optionsStart < 0 || optionsEnd < 0) throw new Error("MENU_OPTIONS source block not found");
const options = source.slice(optionsStart, optionsEnd);
const stageStart = source.indexOf("static void stage1_action(bool restore) {");
const stageEnd = source.indexOf("\nvoid CancelLedgeFly", stageStart);
if (stageStart < 0 || stageEnd < 0) throw new Error("preserved Stage-1 action source not found");
const stageAction = source.slice(stageStart, stageEnd);

requireMatch(source, /enum InputCaptureState/, "private capture-state enum");
requireMatch(source, /int edge_instant = 0;/, "private edge-input latch");
requireMatch(source, /int last_instant = 0;/, "private last-input latch");
requireMatch(source, /int sample_frames = 0;/, "private sample counter");
requireMatch(source, /InputCaptureState input_capture_state = INPUT_WAIT_ZERO;/, "private capture state");
requireMatch(options, /if\(input_capture_state == INPUT_WAIT_ZERO\)/, "zero-frame arm state");
requireMatch(options, /if\(!cbi\) input_capture_state = INPUT_ARMED;/, "zero-frame re-arm");
requireMatch(options, /edge_instant = cbi;/, "first-sample edge capture");
requireMatch(options, /last_instant = cbi;/, "last-sample capture");
requireMatch(options, /sample_frames = 1;/, "first-sample frame count");
requireMatch(options, /sample_frames\+\+;/, "later-sample frame count");
requireMatch(options, /input_capture_state = INPUT_FROZEN;/, "Triangle capture freeze");
requireMatch(options, /sprintf\(line, "E:%x N:%x F:%d", edge_instant, last_instant, sample_frames\);/, "edge/last/frame display");
requireMatch(options, /\(cbi & 0x10\) && !OUTFIT_UNRESOLVED\(\)/, "existing safe Triangle-back gate");
if (options.indexOf("if(input_capture_state == INPUT_WAIT_ZERO)") > options.indexOf("if((cbi & 0x10)")) {
  throw new Error("capture handling no longer precedes Triangle-back handling");
}
if (/stage1_action\s*\(/.test(options)) throw new Error("MENU_OPTIONS still dispatches Stage-1 action");
if (/GetCurrentEquipmentSlot|GetItemManager|GetItemConfig/.test(options)) throw new Error("MENU_OPTIONS still performs equipment lookup");
if (/\*\(\(int\*\)slot\)\s*=/.test(options)) throw new Error("MENU_OPTIONS contains an equipment pointer write");
if ((source.match(/stage1_action\s*\(/g) || []).length !== 1) throw new Error("unexpected Stage-1 action call remains in source");
requireMatch(stageAction, /\*\(\(int\*\)slot\) = candidate;/, "preserved apply safety implementation");
requireMatch(stageAction, /\*\(\(int\*\)slot\) = outfit_test\.original_config;/, "preserved restore safety implementation");

const assembly = fs.readFileSync("mod/mod.s", "utf8");
if (/\bjal\s+_Z13stage1_actionb\b/.test(assembly)) throw new Error("generated input path still calls Stage-1 action");
requireMatch(assembly, /lw\s+\$[0-9]+,4543452/, "generated 32-bit 0x4553DC load");
for (const symbol of ["edge_instant", "last_instant", "sample_frames", "input_capture_state"]) {
  if (!assembly.includes(symbol)) throw new Error(`generated assembly omits ${symbol}`);
}

const observabilityReport = [
  "controller_instant_address=0x4553DC",
  "display=E:%x N:%x F:%d",
  "capture=first nonzero after observed zero; retain latest nonzero and nonzero-frame count",
  "triangle_back=preserved after capture; frozen result survives re-entry until a zero frame re-arms",
  "x_action=none",
  "square_action=none",
  "circle_action=none",
  "source_options_stage1_calls=none",
  "source_options_equipment_lookups=none",
  "source_options_equipment_writes=none",
  `generated_stage1_symbol=${assembly.includes("_Z13stage1_actionb") ? "present_but_unreachable" : "absent"}`,
  "generated_stage1_call_from_diagnostic=none",
  "generated_equipment_pointer_write_reachable=no",
  "generated_capture_symbols=edge_instant,last_instant,sample_frames,input_capture_state",
  "generated_0x4553dc_load=single_32_bit_lw",
  "config_plus_0x0c_write=none",
  "inventory_or_flag_write=none",
];
fs.writeFileSync("reproducibility/input-edge-observability-report.txt", observabilityReport.join("\n") + "\n");
console.log(observabilityReport.join("\n"));

if (!guardPass || !preferredPass || missing.length || unexpected.length) process.exit(1);
