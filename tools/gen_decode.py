#!/usr/bin/env python3
"""Generate data/languages/c6000_decode.sinc from the SPRUFE8B-derived
encoding table (see tools/build_encodings.py).

The generated file contains one SLEIGH constructor per documented opcode.
Operands are rendered with the shared tables defined in c6000.sinc; the unit
suffix comes from the opcode-map section itself, not from guesswork.

Usage:  python3 tools/gen_decode.py
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, ".research/encodings_resolved.json")
ALIASES = os.path.join(ROOT, ".research/aliases.json")
OUT = os.path.join(ROOT, "data/languages/c6000_decode.sinc")

# Mnemonics with hand-written semantics, defined in c6000_semantics.sinc.
SEMANTIC_MNEMONICS = set()
# Encodings written by hand in c6000_manual.sinc.
HAND_WRITTEN = {"BNOP", "SPLOOP", "SPLOOPD", "SPLOOPW", "SPKERNEL",
                "SPKERNELR", "SPMASK", "SPMASKR", "CPKT"}
sem_path = os.path.join(ROOT, "data/languages/c6000_semantics.sinc")
if os.path.exists(sem_path):
    for line in open(sem_path):
        m = re.match(r"^#\s*SEM:\s*([A-Z0-9_]+)", line)
        if m:
            SEMANTIC_MNEMONICS.add(m.group(1))

WILD = {"creg", "z"}
UNIT_LETTERS = (".L", ".S", ".M", ".D")


def unit_letter(text):
    for u in UNIT_LETTERS:
        if u in text:
            return u[1]
    return None


def load():
    data = json.load(open(SRC))
    aliases = json.load(open(ALIASES))
    aliases.pop("NOT", None)  # NOT has its own unary encoding
    return data, aliases


def bitname(lo):
    return "i%d" % lo


def pattern_of(fields, opvalue):
    """Return the conjunction of constant bit constraints."""
    terms = []
    for f in sorted(fields, key=lambda f: f["lo"] if f["lo"] is not None else 99):
        if f["const"] is not None:
            terms.append("%s=%s" % (bitname(f["lo"]), f["const"]))
        elif f["name"] == "op" and opvalue is not None:
            hi, lo = f["hi"], f["lo"]
            if len(opvalue) != hi - lo + 1:
                return None
            for k, ch in enumerate(opvalue):
                terms.append("%s=%s" % (bitname(lo + (hi - lo) - k), ch))
    return terms


def operands_for(syntax, fields, mnem):
    """Map the manual's operand list onto SLEIGH operand symbols."""
    names = {f["name"] for f in fields}
    if "baseR" in names:
        mem = "MemLong" if ("off15" in names or "ucst15" in names) else "MemReg"
        reg = "Dst" if "dst" in names else "Src"
        return [mem, reg] if mnem.startswith("LD") else [reg, mem]
    op = re.search(r"\)\s*(.*)$", syntax)
    if not op:
        # unitless form: everything after the mnemonic is the operand list
        tail = syntax[len(mnem):].strip()
        if not tail:
            return []
        op = re.match(r"(.*)$", tail)
    ops = op.group(1).strip()
    ops = ops.split(" (")[0].strip()  # drop trailing "(if ...)" commentary
    if not ops:
        return []
    parts = [p.strip() for p in ops.split(",")]
    out = []
    for p in parts:
        if p.startswith("*"):
            if "ucst15" in names or "off15" in names:
                out.append("MemLong")
            else:
                out.append("MemReg")
            continue
        base = re.split(r"[:_]", p.replace("_o", "").replace("_e", ""))[0]
        base = base.strip()
        if base == "src1":
            out.append("Src1")
        elif base == "src2":
            out.append("Src2")
        elif base == "src":
            out.append("Src")
        elif base == "dst":
            out.append("Dst")
        elif base == "cst":
            out.append("Cst16" if "cst16" in names else "Cst5")
        elif base == "csta":
            out.append("Csta")
        elif base == "cstb":
            out.append("Cstb")
        elif base == "label":
            out.append("BranchTarget")
        elif base in ("A3/B3", "B3"):
            out.append('"B3"')   # display-only literal; B3 is written by the macro
        elif base == "A0/B0":
            out.append('"A0"')
        elif base == "[count]":
            out.append("Nbit")
        elif base == "unitmask":
            out.append("UCst5")
        else:
            return None
    return out


def main():
    data, aliases = load()
    lines = []
    w = lines.append
    w("#  GENERATED FILE - do not edit by hand.")
    w("#  Produced by tools/gen_decode.py from the SPRUFE8B section 3.12 opcode")
    w("#  tables (see tools/build_encodings.py and NOTICE.md).")
    w("#")
    w("#  One constructor per documented opcode.  Patterns carry the exact")
    w("#  constant bits of the opcode map; `c_is16=0` restricts them to")
    w("#  non-compact instruction slots.")
    w("")
    n = 0
    skipped = []
    placeholder_mnemonics = set()
    seen_patterns = {}
    dropped = []
    for rec in data:
        name = rec["name"]
        if name in aliases or name in HAND_WRITTEN:
            continue
        for u in rec["units"]:
            if u["leftover"] != 0:
                skipped.append((name, u["heading"], "leftover"))
                continue
            fields = u["fields"]
            heading = u["heading"]
            unit_syn = rec.get("unit_syntax", "")
            ul = unit_letter(heading) or unit_letter(unit_syn)
            has_s = any(f["name"] == "i1" or (f["name"] == "1" and f["lo"] == 1)
                        for f in fields) or any(
                f["const"] is None and f["name"] == "s" for f in fields)
            # The unit side comes from `s` (bit 1) on .L/.S/.M and from `y`
            # (bit 7) on the .D load/store formats.  Some .D opcode maps fold
            # the Y bit into the opfield (SPRUFE8B figure C-1), in which case
            # the opfield value already fixes the side.
            dyn_side = any(f["name"] == ("y" if ul == "D" else "s")
                           for f in fields)

            opf = [f for f in fields if f["name"] == "op"]
            variants = [None]
            if u["opcodes"] and opf:
                variants = [o["opfield"] for o in u["opcodes"]]

            # operand list from the primary syntax line
            syntax = None
            for i, s in enumerate(rec["syntax"]):
                if re.match(r"^Syntax\s", s):
                    cand = re.sub(r"^Syntax\s+", "", s).strip()
                    if not cand and i + 1 < len(rec["syntax"]):
                        cand = rec["syntax"][i + 1].strip()
                    syntax = cand
                    break
            if syntax is None:
                mnem = name
                ops = None
            else:
                mnem = re.split(r"[(\s]", syntax)[0]
                ops = operands_for(syntax, fields, mnem)
            if ops is None:
                names = {f["name"] for f in fields}
                if "baseR" in names:
                    mem = "MemLong" if ("off15" in names or "ucst15" in names) \
                        else "MemReg"
                    reg = "Dst" if "dst" in names else "Src"
                    ops = [mem, reg] if mnem.startswith("LD") else [reg, mem]
                elif syntax is None:
                    skipped.append((name, heading, "no-syntax"))
                    continue
                else:
                    skipped.append((name, heading, "operand-map"))
                    continue

            for v in variants:
                base = pattern_of(fields, v)
                if base is None:
                    continue
                # Only use the predicate field when creg/z are真 fields.
                b2831 = [f for f in fields if f["lo"] is not None and 28 <= f["lo"] <= 31]
                fixed_pred = all(f["const"] is not None for f in b2831) if b2831 else False
                # The unit side bit is s (bit 1) for .L/.S/.M and y (bit 7) for
                # .D.  When it is a field, emit one constructor per side so the
                # mnemonic can carry the resolved unit suffix.
                if ul and dyn_side:
                    sidefield = "i7" if ul == "D" else "i1"
                    sides = [("0", ".1"), ("1", ".2")]
                elif ul and ul == "D" and any(
                        f["name"] == "op" and f["lo"] <= 7 <= f["hi"] for f in fields):
                    # side is encoded inside the opfield
                    sidefield = None
                    bit7 = [(f["lo"], f["hi"]) for f in fields
                            if f["name"] == "op" and f["lo"] <= 7 <= f["hi"]][0]
                    if v is not None:
                        pos = bit7[1] - 7
                        sides = [(None, ".2" if v[pos] == "1" else ".1")]
                    else:
                        sides = [(None, ".1")]
                elif ul:
                    b1 = [f for f in fields if f["lo"] == 1]
                    fixed = ".2" if (b1 and b1[0]["const"] == "1") else ".1"
                    if ul == "D":
                        yb = [f for f in fields if f["lo"] == 7]
                        if yb and yb[0]["const"] == "1":
                            fixed = ".2"
                        elif yb and yb[0]["const"] == "0":
                            fixed = ".1"
                    sidefield = None
                    sides = [(None, fixed)]
                else:
                    sidefield = None
                    sides = [(None, "")]
                for sideval, suffix in sides:
                    pat = list(base)
                    if sidefield is not None:
                        pat.append("%s=%s" % (sidefield, sideval))
                    pat.append("c_is16=0")
                    if not fixed_pred:
                        pat.append("Cond")
                    # SLEIGH links a display operand to its family symbol only
                    # when the symbol also occurs in the bit pattern.
                    for op in ops or []:
                        if not op.startswith('"'):
                            pat.append(op)
                    disp = mnem + (("." + ul + suffix[1:]) if ul else "")
                    if ops:
                        disp += " " + ", ".join(ops)
                    if mnem in SEMANTIC_MNEMONICS:
                        args = ", ".join(o for o in (ops or []) if not o.startswith(chr(34)))
                        macro = "c6000_sem_%s" % mnem.lower()
                        if mnem == "B" and ops and ops[0] != "BranchTarget":
                            macro = "c6000_sem_b_ind"
                        sem = "%s(%s);" % (macro, args)
                    else:
                        sem = "c6000_unimpl_%s();" % mnem.lower()
                        placeholder_mnemonics.add(mnem)
                    key = tuple(sorted(pat))
                    if key in seen_patterns and seen_patterns[key] != mnem:
                        # Same encoding documented for two mnemonics; the
                        # manual lists one as the canonical form.  Keep the
                        # first (manual order) and record the alias.
                        dropped.append((mnem, seen_patterns[key]))
                        continue
                    seen_patterns[key] = mnem
                    w(":%s is %s { %s }" % (disp, " & ".join(pat), sem))
                    n += 1
        w("")
    open(OUT, "w").write("\n".join(lines))

    # declare one placeholder userop per unimplemented mnemonic
    ph = os.path.join(ROOT, "data/languages/c6000_placeholders.sinc")
    with open(ph, "w") as f:
        f.write("#  GENERATED FILE - do not edit by hand.\n")
        f.write("#  One user-defined p-code operation per instruction whose\n")
        f.write("#  semantics are not yet modelled.  tools/gen_decode.py emits a\n")
        f.write("#  call to the matching op so that unmodelled instructions are\n")
        f.write("#  explicit, greppable markers rather than silently wrong data\n")
        f.write("#  flow.  The corpus test counts how often each is reached.\n\n")
        for m in sorted(placeholder_mnemonics):
            f.write("define pcodeop c6000_unimpl_%s;\n" % m.lower())
    sys.stderr.write("wrote %s: %d constructors, %d skipped\n"
                     % (OUT, n, len(skipped)))
    for s in skipped:
        sys.stderr.write("  skipped %s %s (%s)\n" % s)
    for a, b in dropped:
        sys.stderr.write("  duplicate encoding: %s kept as %s\n" % (b, a))


if __name__ == "__main__":
    main()
