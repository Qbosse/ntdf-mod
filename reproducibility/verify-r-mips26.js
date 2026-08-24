#!/usr/bin/env node

const fs = require("fs");
const { create_mod } = require("../elf_processor.js");

function readString(buffer, offset) {
  let end = offset;
  while (end < buffer.length && buffer[end] !== 0) end++;
  return buffer.toString("utf8", offset, end);
}

function parseNumber(value) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 0 || number > 0xffffffff) {
    throw new Error(`invalid 32-bit number: ${value}`);
  }
  return number >>> 0;
}

function parseSymbolAssignments(values) {
  const assignments = {};
  for (const value of values) {
    const match = value.match(/^([^=]+)=(0x[0-9a-f]+|[0-9]+)$/i);
    if (!match) throw new Error(`invalid symbol assignment: ${value}`);
    assignments[match[1]] = parseNumber(match[2]);
  }
  return assignments;
}

function parsePnach(path) {
  const words = new Map();
  for (const line of fs.readFileSync(path, "utf8").split(/\r?\n/)) {
    const match = line.match(/^patch=0,EE,([0-9A-Fa-f]+),word,([0-9A-Fa-f]{8})$/);
    if (match) words.set(parseInt(match[1], 16) >>> 0, parseInt(match[2], 16) >>> 0);
  }
  return words;
}

function parseElf(path) {
  const buffer = fs.readFileSync(path);
  if (buffer.toString("binary", 0, 4) !== "\x7fELF" || buffer[4] !== 1 || buffer[5] !== 1) {
    throw new Error("expected a 32-bit little-endian ELF");
  }

  const shoff = buffer.readUInt32LE(32);
  const shentsize = buffer.readUInt16LE(46);
  const shnum = buffer.readUInt16LE(48);
  const shstrndx = buffer.readUInt16LE(50);
  if (shentsize !== 40) throw new Error(`unexpected section-header size ${shentsize}`);

  const sections = [];
  let outputSize = 0;
  for (let index = 0; index < shnum; index++) {
    const base = shoff + index * shentsize;
    const section = {
      index,
      sh_name: buffer.readUInt32LE(base),
      sh_type: buffer.readUInt32LE(base + 0x04),
      sh_flags: buffer.readUInt32LE(base + 0x08),
      sh_offset: buffer.readUInt32LE(base + 0x10),
      sh_size: buffer.readUInt32LE(base + 0x14),
      sh_link: buffer.readUInt32LE(base + 0x18),
      sh_info: buffer.readUInt32LE(base + 0x1c),
      sh_addralign: buffer.readUInt32LE(base + 0x20),
      sh_entsize: buffer.readUInt32LE(base + 0x24),
    };
    if (section.sh_flags & 2) {
      const alignment = section.sh_addralign || 1;
      while (outputSize % alignment !== 0) outputSize++;
      section.buffer_offset = outputSize;
      outputSize += section.sh_size;
    }
    sections.push(section);
  }

  const sectionStrings = sections[shstrndx];
  for (const section of sections) {
    section.name = readString(buffer, sectionStrings.sh_offset + section.sh_name);
  }

  for (const section of sections) {
    if (section.sh_type !== 2) continue;
    const stringTable = sections[section.sh_link];
    section.symbols = [];
    for (let offset = 0; offset < section.sh_size; offset += 16) {
      const base = section.sh_offset + offset;
      const symbol = {
        index: offset / 16,
        name: readString(buffer, stringTable.sh_offset + buffer.readUInt32LE(base)),
        value: buffer.readUInt32LE(base + 0x04),
        size: buffer.readUInt32LE(base + 0x08),
        info: buffer[base + 0x0c],
        shndx: buffer.readUInt16LE(base + 0x0e),
      };
      section.symbols.push(symbol);
    }
  }
  return { buffer, sections };
}

function hex(value, width = 8) {
  return `0x${(value >>> 0).toString(16).toUpperCase().padStart(width, "0")}`;
}

async function main() {
  if (process.argv.length < 6) {
    throw new Error("usage: verify-r-mips26.js <mod.o> <out-offset> <pnach> <report> [symbol=address ...]");
  }
  const [, , elfPath, outOffsetText, pnachPath, reportPath, ...assignmentTexts] = process.argv;
  const outOffset = parseNumber(outOffsetText);
  const externalSymbols = parseSymbolAssignments(assignmentTexts);
  const elf = parseElf(elfPath);
  const pnach = parsePnach(pnachPath);
  const generated = await create_mod(elfPath, outOffset, { ...externalSymbols });
  const generatedData = generated.patches.find((patch) => patch.addr === outOffset && patch.data);
  if (!generatedData) throw new Error("create_mod did not return the injected data patch");

  const rows = [];
  for (const relocationSection of elf.sections) {
    if (relocationSection.sh_type !== 9) continue;
    const symbols = elf.sections[relocationSection.sh_link].symbols;
    const targetSection = elf.sections[relocationSection.sh_info];
    if (!symbols || targetSection.buffer_offset === undefined) continue;
    for (let offset = 0; offset < relocationSection.sh_size; offset += 8) {
      const base = relocationSection.sh_offset + offset;
      const relocationOffset = elf.buffer.readUInt32LE(base);
      const info = elf.buffer.readUInt32LE(base + 4);
      if ((info & 0xff) !== 4) continue;
      const symbol = symbols[info >>> 8];
      if (!symbol) throw new Error("R_MIPS_26 references a missing symbol");

      let symbolAddress;
      const symbolSection = elf.sections[symbol.shndx];
      if (symbolSection && symbolSection.buffer_offset !== undefined) {
        symbolAddress = (outOffset + symbolSection.buffer_offset + symbol.value) >>> 0;
      } else if (Object.prototype.hasOwnProperty.call(externalSymbols, symbol.name)) {
        symbolAddress = externalSymbols[symbol.name] >>> 0;
      } else {
        throw new Error(`no absolute address for R_MIPS_26 symbol ${symbol.name || `<section ${symbol.shndx}>`}`);
      }

      const objectOffset = targetSection.sh_offset + relocationOffset;
      const outputOffset = targetSection.buffer_offset + relocationOffset;
      const runtimeAddress = (outOffset + outputOffset) >>> 0;
      const original = elf.buffer.readUInt32LE(objectOffset);
      const addend = ((original & 0x03ffffff) << 2) >>> 0;
      const target = (symbolAddress + addend) >>> 0;
      const expected = ((original & 0xfc000000) | ((target >>> 2) & 0x03ffffff)) >>> 0;
      const actual = generatedData.data.readUInt32LE(outputOffset);
      const pnachWord = pnach.get(runtimeAddress);
      if (actual !== expected) throw new Error(`${hex(runtimeAddress)} create_mod mismatch: ${hex(actual)} != ${hex(expected)}`);
      if (pnachWord !== expected) throw new Error(`${hex(runtimeAddress)} PNACH mismatch: ${hex(pnachWord || 0)} != ${hex(expected)}`);
      if (((runtimeAddress + 4) & 0xf0000000) !== (target & 0xf0000000)) {
        throw new Error(`${hex(runtimeAddress)} target is outside the MIPS jump region: ${hex(target)}`);
      }

      let resolvedName = symbol.name || targetSection.name;
      if (!symbol.name && symbolSection) {
        const namedTarget = elf.sections
          .flatMap((section) => section.symbols || [])
          .find((candidate) => candidate.shndx === symbol.shndx && candidate.value === addend && candidate.name);
        if (namedTarget) resolvedName = `${symbolSection.name}+${hex(addend)} (${namedTarget.name})`;
      }
      rows.push({ runtimeAddress, original, addend, symbolAddress, target, expected, resolvedName });
    }
  }
  if (rows.length === 0) throw new Error("no R_MIPS_26 relocations found");

  const report = [
    `elf=${elfPath}`,
    `out_offset=${hex(outOffset)}`,
    `r_mips_26_count=${rows.length}`,
    "status=pass",
    "relocations:",
    ...rows.map((row) =>
      `${hex(row.runtimeAddress)} original=${hex(row.original)} addend=${hex(row.addend)} ` +
      `symbol=${hex(row.symbolAddress)} target=${hex(row.target)} word=${hex(row.expected)} ${row.resolvedName}`
    ),
  ];
  fs.writeFileSync(reportPath, report.join("\n") + "\n");
  console.log(report.join("\n"));
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});
