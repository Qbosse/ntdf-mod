#!/usr/bin/env node

const fs = require("fs");

const DATA_START = 0x3043B0;
const DATA_GUARD = 0x30809C;

function parsePnach(path) {
  const text = fs.readFileSync(path, "utf8");
  const map = new Map();
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^patch=0,EE,([0-9A-Fa-f]+),word,([0-9A-Fa-f]{8})$/);
    if (match) map.set(parseInt(match[1], 16), match[2].toUpperCase());
  }
  return { text, map };
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

function hookMap(map) {
  const end = dataEnd(map);
  const hooks = new Map();
  for (const [addr, value] of map) {
    if (!(addr >= DATA_START && end !== null && addr <= end)) {
      hooks.set(addr, value);
    }
  }
  return hooks;
}

function hex(value, width = 6) {
  return `0x${value.toString(16).toUpperCase().padStart(width, "0")}`;
}

function summarize(label, parsed) {
  const end = dataEnd(parsed.map);
  const hooks = hookMap(parsed.map);
  console.log(`== ${label} ==`);
  console.log(`lines=${parsed.text.trimEnd().split(/\r?\n/).length}`);
  console.log(`words=${parsed.map.size}`);
  console.log(`data=${hex(DATA_START)}..${hex(end)} bytes=${end - DATA_START + 4}`);
  console.log(`guard=${hex(DATA_GUARD)} guard_pass=${end <= DATA_GUARD ? "yes" : "no"}`);
  console.log(`hooks=${[...hooks.keys()].sort((a, b) => a - b).map((addr) => hex(addr)).join(",")}`);
}

function compare(leftLabel, left, rightLabel, right) {
  const leftHooks = hookMap(left.map);
  const rightHooks = hookMap(right.map);
  const leftSet = [...leftHooks.keys()].sort((a, b) => a - b);
  const rightSet = [...rightHooks.keys()].sort((a, b) => a - b);
  const onlyLeft = leftSet.filter((addr) => !rightHooks.has(addr));
  const onlyRight = rightSet.filter((addr) => !leftHooks.has(addr));
  const changed = leftSet.filter((addr) => rightHooks.has(addr) && leftHooks.get(addr) !== rightHooks.get(addr));

  console.log(`== ${leftLabel} vs ${rightLabel} ==`);
  console.log(`hook_sets_same=${onlyLeft.length === 0 && onlyRight.length === 0 ? "yes" : "no"}`);
  console.log(`only_${leftLabel}=${onlyLeft.map((addr) => hex(addr)).join(",") || "none"}`);
  console.log(`only_${rightLabel}=${onlyRight.map((addr) => hex(addr)).join(",") || "none"}`);
  console.log("changed_hook_values:");
  if (changed.length === 0) {
    console.log("none");
  } else {
    for (const addr of changed) {
      console.log(`${hex(addr)} ${leftHooks.get(addr)} -> ${rightHooks.get(addr)}`);
    }
  }
}

if (process.argv.length !== 4) {
  console.error("usage: compare-pnach-layout.js <known-good.pnach> <candidate.pnach>");
  process.exit(2);
}

const knownGood = parsePnach(process.argv[2]);
const candidate = parsePnach(process.argv[3]);

summarize("known_good", knownGood);
summarize("candidate", candidate);
compare("known_good", knownGood, "candidate", candidate);
