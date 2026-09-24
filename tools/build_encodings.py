#!/usr/bin/env python3
"""Build a resolved C6000 32-bit encoding table from SPRUFE8B section 3.12.

Steps:
 1. parse every instruction's opcode subsections (layout + opfield table)
 2. resolve unconstrained `op` fields from sibling subsections
 3. drop assembler aliases (instructions the manual says are encoded as another)
 4. report residual collisions

Output: .research/encodings_resolved.json
"""
import json
import re
import sys
from collections import defaultdict

SRC = "/tmp/c6000ref/sprufe8b.txt"
lines = [x.replace("\x0c", "") for x in
         open(SRC, encoding="utf-8", errors="replace").read().split("\n")]
start = [i for i, l in enumerate(lines)
         if l.startswith("3.12 Instruction Descriptions") and i > 4000][0]
end = [i for i in range(start, len(lines))
       if lines[i].strip().startswith("Appendix A") and "www.ti.com" in lines[i]][0]
body = lines[start:end]

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
    names, widths = names_row.split(), widths_row.split()
    fields, wi = [], 0
    for tok in names:
        if tok in ("0", "1"):
            fields.append({"name": tok, "width": 1, "const": tok})
        else:
            w = None
            if wi < len(widths):
                try:
                    w = int(widths[wi]); wi += 1
                except ValueError:
                    w = None
            fields.append({"name": tok, "width": w, "const": None})
    bit = 31
    for f in fields:
        if f["width"] is None:
            f["hi"] = f["lo"] = None
            continue
        f["hi"], f["lo"] = bit, bit - f["width"] + 1
        bit -= f["width"]
    return fields, bit + 1


results = []
for n, (name, ti) in enumerate(blocks):
    stop = blocks[n + 1][1] if n + 1 < len(blocks) else len(body)
    chunk = body[ti:stop]
    text = "\n".join(chunk)
    syntax, unit_syntax = [], ""
    for l in chunk[:40]:
        s = l.strip()
        if s.startswith("Syntax"):
            syntax.append(s)
        elif s.startswith("or ") and len(syntax) < 12:
            syntax.append(s)
        elif s.startswith("unit ="):
            unit_syntax = s
        elif STOP_RE.match(s) and s != "Opcode" and syntax:
            break
    units = []
    for i2, l in enumerate(chunk):
        if not l.startswith("Opcode"):
            continue
        heading = re.sub(r"^Opcode\s*", "", l).strip()
        lay, j2 = [], i2 + 1
        while j2 < len(chunk) and j2 < i2 + 9:
            if re.match(r"^\s*3[12]\b", chunk[j2]):
                lay = [chunk[j2]]
                if j2 + 1 < len(chunk):
                    lay.append(chunk[j2 + 1])
                if j2 + 2 < len(chunk) and not STOP_RE.match(chunk[j2 + 2].strip()):
                    lay.append(chunk[j2 + 2])
                break
            j2 += 1
        if len(lay) < 3:
            continue
        fields, rem = parse_layout(lay[1], lay[2])
        th = None
        for j in range(j2, min(i2 + 30, len(chunk))):
            if "map field used" in chunk[j]:
                th = j; break
        opf = [f for f in fields if f["name"] == "op"]
        ops = []
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
                if m2:
                    bits = m2.group(1).replace(" ", "")
                    if opf and len(bits) != opf[0]["width"]:
                        continue
                    mu = re.search(r"(\.\w+)(?:\s*,\s*\.\w+)*\s*$", t[:m2.start()].rstrip())
                    ops.append({"opfield": bits,
                                "unit_cell": mu.group(0).strip() if mu else ""})
        units.append({"heading": heading, "fields": fields, "leftover": rem,
                      "opcodes": ops})
    results.append({"name": name, "syntax": syntax, "unit_syntax": unit_syntax,
                    "units": units, "text": text})

# ---- 1. drop assembler aliases -------------------------------------------
ALIAS_RE = re.compile(r"The assembler uses the (?:operation )?([A-Z][A-Z0-9_]*)")
known = {r["name"] for r in results}
alias_of = {}
for r in results:
    for m in ALIAS_RE.finditer(r["text"]):
        t = m.group(1)
        if t in known and t != r["name"]:
            alias_of[r["name"]] = t
            break
# NOT/XOR is a genuine encoding alias only if the layouts are identical; keep
# NOT otherwise.  Decided after collision check below.

# ---- 2. field-name normalisation for signature comparison -----------------
def fldsig(u):
    opf = [f for f in u["fields"] if f["name"] == "op"]
    names = tuple(sorted(f["name"] for f in u["fields"]
                         if f["const"] is None and f["name"] != "op"))
    cbits = tuple(sorted((f["lo"], f["const"]) for f in u["fields"]
                         if f["const"] is not None))
    return names, cbits, tuple((f["hi"], f["lo"]) for f in opf)

# ---- 3. resolve unconstrained op fields from siblings ---------------------
by_instr = defaultdict(list)
for r in results:
    for u in r["units"]:
        by_instr[r["name"]].append(u)

for name, us in by_instr.items():
    # collect known op values keyed by (heading-ish signature)
    knownvals = {}
    for u in us:
        opf = [f for f in u["fields"] if f["name"] == "op"]
        if not opf:
            continue
        lo, hi = opf[0]["lo"], opf[0]["hi"]
        vals = set()
        if u["opcodes"]:
            for o in u["opcodes"]:
                vals.add(o["opfield"])
        else:
            c = {f["lo"]: f["const"] for f in u["fields"] if f["const"] is not None}
            if all(b in c for b in range(lo, hi + 1)):
                vals.add("".join(c[b] for b in range(hi, lo - 1, -1)))
        if vals:
            knownvals.setdefault((lo, hi), set()).update(vals)
    # apply: any section whose op is unconstrained and for which exactly one
    # value is known for that op range gets it
    for u in us:
        opf = [f for f in u["fields"] if f["name"] == "op"]
        if not opf or u["opcodes"]:
            continue
        lo, hi = opf[0]["lo"], opf[0]["hi"]
        c = {f["lo"]: f["const"] for f in u["fields"] if f["const"] is not None}
        if all(b in c for b in range(lo, hi + 1)):
            continue
        vals = knownvals.get((lo, hi))
        if vals and len(vals) == 1:
            v = next(iter(vals))
            for k, ch in enumerate(reversed(v)):
                # materialise as constants
                u["fields"] = [f for f in u["fields"] if not (f["lo"] == lo + k)]
                u["fields"].append({"name": ch, "width": 1, "const": ch,
                                    "hi": lo + k, "lo": lo + k})
            u["fields"].sort(key=lambda f: -(f["hi"] if f["hi"] is not None else -1))
            u["resolved_op"] = v

json.dump([{k: v for k, v in r.items() if k != "text"} for r in results],
          open(".research/encodings_resolved.json", "w"), indent=1)
json.dump(alias_of, open(".research/aliases.json", "w"), indent=1)
print("instructions", len(results), "aliases", len(alias_of))
print("alias_of:", alias_of)
