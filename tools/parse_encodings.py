#!/usr/bin/env python3
"""Parse SPRUFE8B section 3.12 instruction descriptions into a structured
encoding database.

For every instruction it captures:
  * mnemonic and syntax lines (including the `unit = ...` line)
  * for every "Opcode[ <unit>]" subsection: the bit-field layout (exact bit
    ranges incl. constant bits) and, when present, the opfield table
    (opfield value + unit cell + operand-type rows).

Output: .research/encodings.json
"""
import json
import re
import sys

SRC = sys.argv[1] if len(sys.argv) > 1 else "/tmp/c6000ref/sprufe8b.txt"
OUT = sys.argv[2] if len(sys.argv) > 2 else ".research/encodings.json"

lines = [x.replace("\x0c", "") for x in
         open(SRC, encoding="utf-8", errors="replace").read().split("\n")]
start = [i for i, l in enumerate(lines)
         if l.startswith("3.12 Instruction Descriptions") and i > 4000][0]
end = [i for i in range(start, len(lines))
       if lines[i].strip().startswith("Appendix A") and "www.ti.com" in lines[i]][0]
body = lines[start:end]

# --- instruction blocks -----------------------------------------------------
blocks = []
for i, l in enumerate(body):
    if l.startswith("Syntax"):
        for j in range(i - 1, max(0, i - 9), -1):
            m = re.match(r"^([A-Z][A-Z0-9_.]*)\s{2,}(\S.*)$", body[j])
            if m and not body[j].startswith("www.ti.com"):
                blocks.append((m.group(1), j))
                break

STOP_RE = re.compile(
    r"^(Opcode\b|Description\b|Execution\b|Pipeline\b|Instruction Type\b|"
    r"Delay Slots\b|See Also\b|Examples\b|Functional Unit Latency\b|"
    r"Compact Instruction Format\b|Register File Cross Path\b)")


def parse_layout(names_row, widths_row):
    names = names_row.split()
    widths = widths_row.split()
    fields = []
    wi = 0
    for tok in names:
        if tok in ("0", "1"):
            fields.append({"name": tok, "width": 1, "const": tok})
        else:
            w = None
            if wi < len(widths):
                try:
                    w = int(widths[wi])
                    wi += 1
                except ValueError:
                    w = None
            fields.append({"name": tok, "width": w, "const": None})
    # assign bit ranges from 31 down
    bit = 31
    for f in fields:
        if f["width"] is None:
            f["hi"] = f["lo"] = None
            continue
        f["hi"] = bit
        f["lo"] = bit - f["width"] + 1
        bit -= f["width"]
    return fields, bit


results = []
for n, (name, ti) in enumerate(blocks):
    stop = blocks[n + 1][1] if n + 1 < len(blocks) else len(body)
    chunk = body[ti:stop]
    syntax, unit_syntax = [], ""
    for l in chunk[:40]:
        s = l.strip()
        if s.startswith("Syntax"):
            syntax.append(s)
        elif s.startswith("or ") and len(syntax) < 12:
            syntax.append(s)
        elif s.startswith("unit ="):
            unit_syntax = s
        elif syntax and s.startswith("unit ="):  # continuation
            unit_syntax = s
        elif STOP_RE.match(s) and s != "Opcode":
            if syntax:
                break
    units = []
    for i2, l in enumerate(chunk):
        m = re.match(r"^Opcode\s*(.*?)\s*$", l)
        if not m or not l.startswith("Opcode"):
            continue
        heading = m.group(1).strip()
        lay, j2 = [], i2 + 1
        while j2 < len(chunk) and j2 < i2 + 9:
            if re.match(r"^\s*3[12]\b", chunk[j2]):
                lay = [chunk[j2], chunk[j2 + 1]]
                if j2 + 2 < len(chunk) and not chunk[j2 + 2].strip().startswith(
                        ("Opcode", "Description", "Execution")):
                    lay.append(chunk[j2 + 2])
                break
            j2 += 1
        if len(lay) < 2:
            continue
        fields, rem = parse_layout(lay[1], lay[2]) if len(lay) > 2 else (parse_layout(lay[1], ""), 31)
        th = None
        for j in range(j2, min(i2 + 30, len(chunk))):
            if "map field used" in chunk[j]:
                th = j
                break
        ops = []
        opf = [f for f in fields if f["name"] == "op"]
        if th is not None:
            blanks = 0
            for j in range(th + 1, min(th + 200, len(chunk))):
                t = chunk[j]
                if not t.strip():
                    blanks += 1
                    if blanks > 3:
                        break
                    continue
                blanks = 0
                if not t.startswith(" ") or STOP_RE.match(t.strip()):
                    break
                if "SPRUFE8B" in t or "Instruction Set" in t or "Copyright" in t:
                    break
                m2 = re.search(r"((?:[01]+\s+)*[01]+)\s*$", t)
                if m2 and len(m2.group(1).replace(" ", "")) >= 3 and (not opf or len(m2.group(1).replace(" ", "")) == opf[0]["width"]):
                    bits = m2.group(1).replace(" ", "")
                    mu = re.search(
                        r"(\.\w+)(?:\s*,\s*\.\w+)*\s*$", t[:m2.start()].rstrip())
                    ops.append({"opfield": bits,
                                "unit_cell": mu.group(0).strip() if mu else ""})
        units.append({"heading": heading, "fields": fields, "leftover_bits": rem,
                      "opcodes": ops})
    results.append({"name": name, "syntax": syntax, "unit_syntax": unit_syntax,
                    "units": units})

json.dump(results, open(OUT, "w"), indent=1)
nu = sum(len(r["units"]) for r in results)
no = sum(len(u["opcodes"]) for r in results for u in r["units"])
fix = sum(1 for r in results for u in r["units"] if not u["opcodes"])
print(f"instructions={len(results)} opcode_sections={nu} "
      f"with_opfield_table={nu-fix} fixed_encoding={fix} opfield_entries={no}")
