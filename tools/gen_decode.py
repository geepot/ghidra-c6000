#!/usr/bin/env python3
"""Generate data/languages/c6000_decode.sinc from the SPRUFE8B-derived
encoding table (see tools/build_encodings.py).

The generated file contains SLEIGH constructors for documented opcodes and
the legal short-memory addressing modes.
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
HAND_WRITTEN = {"BNOP", "MVC", "SPLOOP", "SPLOOPD", "SPLOOPW", "SPKERNEL",
                "SPKERNELR", "SPMASK", "SPMASKR", "CPKT"}
sem_path = os.path.join(ROOT, "data/languages/c6000_semantics.sinc")
if os.path.exists(sem_path):
    for line in open(sem_path):
        m = re.match(r"^#\s*SEM:\s*([A-Z0-9_]+)", line)
        if m:
            SEMANTIC_MNEMONICS.add(m.group(1))

WILD = {"creg", "z"}
UNIT_LETTERS = (".L", ".S", ".M", ".D")

MEMORY_SUFFIX = {
    "LDB": "B", "LDBU": "B", "STB": "B", "STBU": "B",
    "LDH": "H", "LDHU": "H", "STH": "H", "STHU": "H",
    "LDW": "W", "STW": "W", "LDDW": "D", "STDW": "D",
    "LDNW": "W", "STNW": "W", "LDNDW": "N", "STNDW": "N",
}


def memory_operand(mnem, fields):
    names = {f["name"] for f in fields}
    long_form = "off15" in names or "ucst15" in names
    return ("MemLong" if long_form else "MemReg") + MEMORY_SUFFIX.get(mnem, "W")


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
        mem = memory_operand(mnem, fields)
        reg = "Dst" if "dst" in names else "StoreSrc"
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
            out.append(memory_operand(mnem, fields))
            continue
        base = re.split(r"[:_]", p.replace("_o", "").replace("_e", ""))[0]
        base = base.strip()
        if base == "src1":
            out.append("Src1")
        elif base == "src2":
            out.append("Src2")
        elif base == "src":
            out.append("StoreSrc" if mnem.startswith("ST") else "Src2")
        elif base == "dst":
            out.append("Dst")
        elif base == "cst":
            if "cst16" in names:
                out.append("Cst16")
            else:
                field = next((f for f in fields if f["name"] == "cst5"), None)
                out.append("Cst5Hi" if field and field["lo"] == 18 else "Cst5")
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
    w("#  Constructors cover documented opcodes and legal short-memory modes.")
    w("#  Patterns carry the exact")
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
            names = {f["name"] for f in fields}
            if "baseR" in names and not name.startswith(("LD", "ST")):
                raise ValueError(
                    f"{name}: memory opcode diagram attached to a nonmemory "
                    "instruction; check grouped headings in build_encodings.py")
            memory = name.startswith(("LD", "ST")) and ul == "D"
            short_memory = memory and "baseR" in names
            long_memory = memory and ("ucst15" in names or "off15" in names)
            # Short .D memory instructions use y for the unit and s for the
            # data register file. Long memory instructions execute on .D2;
            # their y bit chooses B14 or B15. .D arithmetic uses s for the
            # unit side (SPRUFE8B Table C-2 and the instruction formats).
            side_name = "y" if short_memory else "s"
            dyn_side = any(f["name"] == side_name for f in fields)

            opf = [f for f in fields if f["name"] == "op"]
            if opf and not u["opcodes"]:
                raise ValueError(
                    f"{name}: unconstrained op field would decode reserved "
                    "opcodes as valid instructions")
            variants = [None]
            if u["opcodes"] and opf:
                variants = [o["opfield"] for o in u["opcodes"]]
            if short_memory:
                variants = [(v, mode) for v in variants for mode in
                            (0x0, 0x1, 0x4, 0x5, 0x8, 0x9,
                             0xA, 0xB, 0xC, 0xD, 0xE, 0xF)]
            else:
                variants = [(v, None) for v in variants]

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
            if mnem == "SADDSU2":
                # TI lists this reversed-operand pseudo-operation before
                # the encoded SADDUS2 form. Display the canonical opcode.
                mnem = "SADDUS2"
                ops = ["Src1", "Src2", "Dst"]
            if name in {"CLR", "EXT", "EXTU", "SET"} and "src1" in names:
                # The primary syntax line is the immediate form; the sibling
                # opcode diagram uses a packed register instead of csta/cstb.
                ops = ["Src2", "Src1", "Dst"]
            if mnem in {"BDEC", "BPOS"}:
                ops = ["BdecTgt", "Dst"]
            if mnem == "MPYLI":
                ops = ["Src1", "Src2", "DstPair"]
            if mnem in {"MPY2", "SMPY2"}:
                ops = ["Src1", "Src2", "DstPair"]
            if mnem == "MPYHI":
                ops = ["Src1", "Src2", "DstPair"]
            if mnem in {"MPYSU4", "MPYU4"}:
                ops = ["Src1", "Src2", "DstPair"]
            if mnem in {"ADDSUB", "ADDSUB2", "SADDSUB", "SADDSUB2", "DMV"}:
                ops = ["Src1", "Src2", "DstPair"]
            if mnem == "DDOTP4":
                ops = ["Src1", "Src2", "DstPair"]
            if mnem in {"DDOTPH2", "DDOTPL2"}:
                ops = ["Src1Pair", "Src2", "DstPair"]
            if mnem in {"DDOTPH2R", "DDOTPL2R"}:
                ops = ["Src1Pair", "Src2", "Dst"]
            if mnem == "CMPY":
                ops = ["Src1", "Src2", "DstPair"]
            if mnem == "MPYID":
                ops = ["Src1", "Src2", "DstPair"]
            if mnem in {"MPY32U", "MPY32SU", "MPY32US"}:
                ops = ["Src1", "Src2", "DstPair"]
            if mnem == "SUBU":
                # Both opfield variants produce a signed 40-bit result in a
                # long register pair, despite the primary syntax omitting
                # the explicit dst_h:dst_l spelling.
                ops = ["Src1", "Src2", "DstPair"]
            if mnem == "MPY32" and any(f["lo"] == 9 and f["const"] == "1" for f in fields):
                ops = ["Src1", "Src2", "DstPair"]
            if mnem in {"INTDP", "INTDPU", "SPDP"}:
                ops = ["Src2", "DstPair"]
            if mnem in {"DPINT", "DPTRUNC"}:
                ops = ["Src2PairDpsp", "Dst"]
            if mnem == "DPSP":
                ops = ["Src2PairDpsp", "Dst"]
            if mnem in {"ADDDP", "MPYDP"}:
                ops = ["Src1Pair", "Src2Pair", "DstPair"]
            if mnem == "SUBDP":
                ops = ["Src1Pair", "Src2Pair", "DstPair"]
            if mnem in {"CMPEQDP", "CMPGTDP", "CMPLTDP"}:
                ops = ["Src1Pair", "Src2Pair", "Dst"]
            if ops is None:
                names = {f["name"] for f in fields}
                if "baseR" in names:
                    mem = memory_operand(mnem, fields)
                    reg = "Dst" if "dst" in names else "StoreSrc"
                    ops = [mem, reg] if mnem.startswith("LD") else [reg, mem]
                elif syntax is None:
                    skipped.append((name, heading, "no-syntax"))
                    continue
                else:
                    skipped.append((name, heading, "operand-map"))
                    continue
            if mnem in {"LDDW", "STDW", "LDNDW", "STNDW"} and "baseR" in names:
                pair = ("DstPair" if mnem.startswith("LD") else "StoreSrcPair")
                if mnem in {"LDNDW", "STNDW"}:
                    pair += "N"
                mem = memory_operand(mnem, fields)
                ops = [mem, pair] if mnem.startswith("LD") else [pair, mem]
            if mnem == "ADDKPC":
                ops = ["AKPCDisp", "Dst", "AKPCNop"]
            if mnem in {"ADDAB", "ADDAH", "ADDAW"} and "ucst15" in names:
                ops = ["BaseLong", "UCst15", "Dst"]
            if mnem in {"SHR2", "SHRU2"} and "cst form" in heading:
                ops[1] = "UCst5"

            base_ops = ops
            for v, mem_mode in variants:
                ops = list(base_ops) if base_ops is not None else None
                if mnem == "NORM" and v == "1100000":
                    # This opfield is the 64-bit src2_h:src2_l form.
                    ops = ["Src2Pair", "Dst"]
                if mnem in {"MPY", "MPYSU"} and v in {"11000", "11110"}:
                    ops[0] = "SCst5"
                if mnem == "MPYID":
                    ops[0] = "SCst5" if v == "01100" else "Src1"
                if mnem == "SADD":
                    if v == "0110001":
                        ops = ["Src1X", "Src2PairLocal", "DstPair"]
                    elif v == "0110000":
                        ops = ["SCst5", "Src2PairLocal", "DstPair"]
                    elif v == "0010010":
                        ops = ["SCst5", "Src2", "Dst"]
                if mnem == "SSUB":
                    if v == "0011111":
                        ops = ["Src1X", "Src2Local", "Dst"]
                    elif v == "0001110":
                        ops = ["SCst5", "Src2", "Dst"]
                    elif v == "0101100":
                        ops = ["SCst5", "Src2PairLocal", "DstPair"]
                if mnem == "DOTP2" and v == "01011":
                    ops = ["Src1", "Src2", "DstPair"]
                if mnem == "ROTL" and v == "11110":
                    ops[1] = "UCst5"
                if mnem == "LMBD" and v == "1101010":
                    ops[0] = "Cst5"
                if mnem == "SUBDP" and v == "0011101":
                    ops = ["Src2PairLocal", "Src1PairX", "DstPair"]
                if mnem == "SUBDP" and v == "1110111":
                    ops = ["Src2Pair", "Src1Pair", "DstPair"]
                base = pattern_of(fields, v)
                if base is None:
                    continue
                if mnem in {"DPSP", "DPINT", "DPTRUNC"}:
                    # SPRUFE8B's printed opcode diagram shows zeros in
                    # bits 17..13, but its execution text uses both source
                    # ports. GNU tic6x's 1_or_2_src encoding stores the low
                    # word of the double in src1. Src2PairDpsp checks both
                    # halves of the register pair.
                    base = [bit for bit in base if not any(
                        bit.startswith(f"i{i}=") for i in range(13, 18))]
                if mnem in {"SADD", "SSUB"} and ops[-1] == "DstPair" \
                        and ops[0] == "SCst5":
                    base.append("i12=0")
                if short_memory:
                    base.append("mode=0x%x" % mem_mode)
                # Only use the predicate field when creg/z are真 fields.
                b2831 = [f for f in fields if f["lo"] is not None and 28 <= f["lo"] <= 31]
                fixed_pred = all(f["const"] is not None for f in b2831) if b2831 else False
                if long_memory:
                    sidefield = None
                    sides = [(None, ".2")]
                elif ul and dyn_side:
                    sidefield = "i7" if short_memory else "i1"
                    sides = [("0", ".1"), ("1", ".2")]
                elif ul:
                    b1 = [f for f in fields if f["lo"] == 1]
                    fixed = ".2" if (b1 and b1[0]["const"] == "1") else ".1"
                    if short_memory:
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
                if mnem == "ADDKPC":
                    sidefield = "i1"
                    sides = [("1", ".2")]
                for sideval, suffix in sides:
                    pat = list(base)
                    if sidefield is not None:
                        pat.append("%s=%s" % (sidefield, sideval))
                    pat.append("c_is16=0")
                    if not fixed_pred:
                        pat.append("Cond")
                        # The predication table reserves creg=7. If the
                        # root opcode still matches those bits, SLEIGH may
                        # select it before CPKT and then fail inside Cond,
                        # instead of trying the packet-header constructor.
                        pat.append("creg!=7")
                    # SLEIGH links a display operand to its family symbol only
                    # when the symbol also occurs in the bit pattern.
                    for op in ops or []:
                        if not op.startswith('"'):
                            pat.append(op)
                    if short_memory and mem_mode >= 0x8:
                        # The operand computes an update candidate; commit it
                        # after the transfer so src == baseR reads the old
                        # value.  Post modes use the old base as the address.
                        pat.append("BaseReg")
                    disp = mnem + (("." + ul + suffix[1:]) if ul else "")
                    if ops:
                        disp += " " + ", ".join(ops)
                    if mnem in {"BDEC", "BPOS"}:
                        if mnem == "BDEC":
                            sem = "if (Dst s< 0) goto <done>; Dst = Dst - 1; goto BdecTgt; <done>"
                        else:
                            sem = "if (Dst s< 0) goto <done>; goto BdecTgt; <done>"
                    elif mnem in SEMANTIC_MNEMONICS:
                        args = ", ".join(o for o in (ops or []) if not o.startswith(chr(34)))
                        macro = "c6000_sem_%s" % mnem.lower()
                        if mnem in {"SPINT", "SPTRUNC"}:
                            macro = "c6000_sem_sp_to_int"
                            args += ", %d, %d" % (
                                0 if suffix == ".1" else 16,
                                0 if mnem == "SPINT" else 1)
                        if mnem in {"DPINT", "DPTRUNC"}:
                            macro = "c6000_sem_dp_to_int"
                            args += ", %d, %d" % (
                                0 if suffix == ".1" else 16,
                                0 if mnem == "DPINT" else 1)
                        if mnem == "MPY32":
                            macro += "_64" if ops[-1] == "DstPair" else "_32"
                        if mnem == "DOTP2":
                            macro += "_64" if ops[-1] == "DstPair" else "_32"
                        if mnem in {"SADD", "SSUB"}:
                            macro += "40" if ops[-1] == "DstPair" else "32"
                        if mnem == "SADDSUB":
                            args += ", %d" % (1 if suffix == ".1" else 2)
                        if mnem in {"CMPY", "DDOTPH2", "DDOTPH2R", "DDOTPL2", "DDOTPL2R"}:
                            args += ", %d" % (0x10 if suffix == ".1" else 0x20)
                        if mnem in {"CLR", "EXT", "EXTU", "SET"} and "src1" in names:
                            macro += "_r"
                        if mnem == "NORM":
                            macro += "40" if v == "1100000" else "32"
                        if mnem == "B" and ops and ops[0] != "BranchTarget":
                            macro = "c6000_sem_b_ind"
                        sem = "%s(%s);" % (macro, args)
                        # A branch hidden inside a macro is emitted as a
                        # computed jump by SLEIGH. Keep direct targets in
                        # the constructor so Ghidra records branch flow.
                        if mnem == "B" and ops and ops[0] == "BranchTarget":
                            sem = "goto BranchTarget;"
                        elif mnem == "CALLP" and ops and ops[0] == "BranchTarget":
                            sem = "B3 = inst_start + 24; call BranchTarget;"
                        elif mnem == "MVK" and ops:
                            width = "5" if ops[0] == "Cst5" else "16"
                            sem = "c6000_sem_mvk%s(%s);" % (width, args)
                    else:
                        sem = "c6000_unimpl_%s();" % mnem.lower()
                        placeholder_mnemonics.add(mnem)
                    if short_memory:
                        mem = memory_operand(mnem, fields)
                        if mem_mode in (0xA, 0xB, 0xE, 0xF):
                            sem = sem.replace(mem, "BaseReg")
                        if mem_mode >= 0x8:
                            sem += f" BaseReg = {mem};"
                    if not fixed_pred:
                        sem = "if (Cond == 0) goto <skip>; %s <skip>" % sem
                    key = tuple(sorted(pat))
                    if key in seen_patterns:
                        # Same encoding can be listed again as a pseudo-op.
                        # Keep the first (manual order), even when both
                        # spellings were normalized to the same mnemonic.
                        if seen_patterns[key] != mnem:
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
