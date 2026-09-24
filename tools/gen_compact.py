#!/usr/bin/env python3
# Generator for data/languages/c6000_compact.sinc (TMS320C674x compact, 16-bit).
#
# Every constructor below is traceable to a figure in SPRUFE8B appendices
# C.4 (D), D.4 (L), E.4 (M), F.4 (S), G.3 (D/L/S) and H.4 (no unit), or to
# section 3.10 (compact header).  The figure is named in the comment above
# each group.
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "data/languages/c6000_compact.sinc")
TOKENOUT = os.path.join(ROOT, "scratch/token_add.txt")

A = ["A%d" % i for i in range(32)]
B = ["B%d" % i for i in range(32)]

# slot -> (lo, hi, kind)
SLOTS = {
    "1513": (13, 15, "r3"),
    "97":   (7, 9, "r3"),
    "64":   (4, 6, "r3"),
    "1110": (10, 11, "r2e"),
    "65":   (5, 6, "r2e"),
    "4":    (4, 4, "r1"),
    "710":  (7, 10, "r4t"),
    "710b": (7, 10, "r4b"),
    "87":   (7, 8, "ptr"),
}

LISTS = {}
for suf in ("a0", "b0", "a1", "b1"):
    regs = A if suf[0] == "a" else B
    base = 0 if suf[1] == "0" else 16
    LISTS[("1513", suf)] = regs[base:base + 8]
    LISTS[("97", suf)] = regs[base:base + 8]
    LISTS[("64", suf)] = regs[base:base + 8]
    LISTS[("1110", suf)] = [regs[base + 2 * i] for i in range(4)]
    LISTS[("65", suf)] = [regs[base + 2 * i] for i in range(4)]
    LISTS[("4", suf)] = regs[base:base + 2]
    LISTS[("87", suf)] = regs[base + 4:base + 8]
for suf in ("a", "b"):
    regs = A if suf == "a" else B
    LISTS[("710", suf)] = regs[0:16]
for suf in ("b0", "b1"):
    base = 0 if suf[1] == "0" else 16
    LISTS[("710b", suf)] = B[base:base + 16]

SUFFIXES = {
    "1513": ("a0", "b0", "a1", "b1"),
    "97":   ("a0", "b0", "a1", "b1"),
    "64":   ("a0", "b0", "a1", "b1"),
    "1110": ("a0", "b0", "a1", "b1"),
    "65":   ("a0", "b0", "a1", "b1"),
    "4":    ("a0", "b0", "a1", "b1"),
    "87":   ("a0", "b0", "a1", "b1"),
    "710":  ("a", "b"),
    "710b": ("b0",),   # 4-bit field, header RS ignored (Figure F-32 note)
}


def fld(slot, suf):
    return "cq_%s_%s" % (slot, suf)


# ---------------------------------------------------------------------------
# Token-field and attach-variables text (hand-inserted into c6000.sinc).
# ---------------------------------------------------------------------------
def token_text():
    out = []
    out.append("  # --- compact (16-bit) register slots -------------------------------")
    out.append("  # The header RS bit selects the low (A0-A7/B0-B7) or high")
    out.append("  # (A16-A23/B16-B23) data register set, and the opcode side bit (t or")
    out.append("  # s) selects the A or B file.  SLEIGH can attach only one register")
    out.append("  # list to a field, so every compact register slot is declared once")
    out.append("  # per (file, register set) combination: _a0 = A side low, _b0 = B")
    out.append("  # side low, _a1 = A side high, _b1 = B side high.")
    for slot in ("1513", "97", "64", "1110", "65", "4", "710", "710b", "87"):
        lo, hi, _ = SLOTS[slot]
        parts = []
        for suf in SUFFIXES[slot]:
            parts.append("%s=(%d,%d)" % (fld(slot, suf), lo, hi))
        out.append("  " + " ".join(parts))
    out.append("")
    out.append("  # compact immediates / opcode sub-fields")
    out.append("  cq_uc43=(11,12)  cq_uc98=(8,9)   cq_uc65=(5,6)   cq_u21=(13,14)")
    out.append("  cq_scst7=(6,12) signed   cq_scst10=(6,15) signed   cq_ucst8=(6,13)")
    out.append("  cq_ii3=(14,14)   cq_spk43=(14,15)")
    out.append("  cq_acc=(0,0)     cq_ret=(0,0)")
    return "\n".join(out) + "\n"


def attach_text():
    groups = {}
    for slot in ("1513", "97", "64", "1110", "65", "4", "710", "710b", "87"):
        for suf in SUFFIXES[slot]:
            key = tuple(LISTS[(slot, suf)])
            groups.setdefault(key, []).append(fld(slot, suf))
    out = []
    out.append("# Compact-instruction register fields.  Each (slot, file, register-set)")
    out.append("# combination has its own attached 8/4/2/16-entry list; the comment in")
    out.append("# the token above explains why.")
    for key, fields in groups.items():
        out.append("attach variables [ %s ]" % " ".join(fields))
        out.append("  [ %s ];" % " ".join(key))
        out.append("")
    return "\n".join(out)


L = []

TABLES = set("""CUnitS CUnitL CUnitM CUnitD CUnitLSD
RA15 RB15 RA97 RB97 RA64 RA1110 RA4 RX97 RT64 RT65Pair RPTR RT710 RT710Pair RB710
CAcc CRet Cucst4 Cucst2 Cucst2pp Cucst5stk Cucst5d Cucst5p Cucst5f23
Cucst8f24 Cucst3d9 Cucst1f CN3 Cii Cspk Cmask CimmL3i CimmLx5 CimmS3i
CTgt7 CTgt8 CTgt10 CPred20 CPredCC""".split())


def w(s=""):
    L.append(s)


def display_tables(disp):
    """Names of sub-tables referenced (outside quoted strings) by a display."""
    out = []
    inq = False
    cur = ""
    for c in disp:
        if c == '"':
            inq = not inq
            if not inq and cur:
                out.append(cur)
            cur = ""
        elif inq:
            pass
        elif c in "^ \t":
            if cur:
                out.append(cur)
            cur = ""
        else:
            cur += c
    if cur:
        out.append(cur)
    return [t for t in out if t in TABLES]


def con(disp, pat, sem):
    if disp.startswith(("LDDW", "STDW", "LDNDW", "STNDW")):
        disp = disp.replace("RT65", "RT65Pair")
        pat = [term.replace("RT65", "RT65Pair") for term in pat]
        sem = sem.replace("RT65", "RT65Pair")
        disp = disp.replace("RT710", "RT710Pair")
        pat = [term.replace("RT710", "RT710Pair") for term in pat]
    # A concatenated literal space remains part of Ghidra's mnemonic field.
    # Start the operands with a separate display token instead.
    disp = disp.replace('^" "^', ' " " ', 1)
    terms = ["c_is16=1"]
    for t in display_tables(disp):
        if t not in pat:
            terms.append(t)
    for t in pat:
        if t not in terms:
            terms.append(t)
    w(":%s is %s { %s }" % (disp, " & ".join(terms), sem))


def reg_table(name, slot, side):
    """Emit a sub-table that exports the register selected by a compact slot.

    side == 's'  : file selected by q_s (bit 0)
    side == 't'  : file selected by q_t (bit 12)
    side == 'tn' : file selected by q_t, header RS ignored (C-21 / Dpp)
    side == 'br' : fixed B file, header RS applied (F-32)
    """
    for suf in SUFFIXES[slot]:
        f = fld(slot, suf)
        if side == "s":
            ctx = {"a0": "q_s=0 & c_rs=0", "b0": "q_s=1 & c_rs=0",
                   "a1": "q_s=0 & c_rs=1", "b1": "q_s=1 & c_rs=1"}[suf]
        elif side == "t":
            ctx = {"a0": "q_t=0 & c_rs=0", "b0": "q_t=1 & c_rs=0",
                   "a1": "q_t=0 & c_rs=1", "b1": "q_t=1 & c_rs=1"}[suf]
        elif side == "tn":
            ctx = {"a": "q_t=0", "b": "q_t=1"}[suf]
        elif side == "br":
            # 4-bit compact register fields span the whole 16-register file
            # and ignore the header RS bit (cf. Figure C-21 note 4).
            ctx = ""
        else:
            raise ValueError(side)
        if ctx:
            w("%s: %s is %s & %s { export %s; }" % (name, f, f, ctx, f))
        else:
            w("%s: %s is %s { export %s; }" % (name, f, f, f))
    w("")


def cross_table(name, slot):
    """src2 with the cross-path bit x (bit 12): side is q_s, x = q_t."""
    combos = [
        ("a0", "q_s=0 & q_t=0 & c_rs=0"),
        ("b0", "q_s=0 & q_t=1 & c_rs=0"),
        ("b0", "q_s=1 & q_t=0 & c_rs=0"),
        ("a0", "q_s=1 & q_t=1 & c_rs=0"),
        ("a1", "q_s=0 & q_t=0 & c_rs=1"),
        ("b1", "q_s=0 & q_t=1 & c_rs=1"),
        ("b1", "q_s=1 & q_t=0 & c_rs=1"),
        ("a1", "q_s=1 & q_t=1 & c_rs=1"),
    ]
    for suf, ctx in combos:
        f = fld(slot, suf)
        if ctx:
            w("%s: %s is %s & %s { export %s; }" % (name, f, f, ctx, f))
        else:
            w("%s: %s is %s { export %s; }" % (name, f, f, f))
    w("")


def imm1(name, export, ctx=""):
    v = name + "v"
    w("%s: %s is %s [ %s = %s; ] { export *[const]:4 %s; }" %
      (name, v, ctx, v, export, v))
    w("")


def plain1(name, field):
    w("%s: %s is %s { export *[const]:4 %s; }" %
      (name, field, field, field))
    w("")


def imm_table(name, rules):
    """rules: list of (export_expression, pattern_string)"""
    v = name + "v"
    for val, pat in rules:
        w("%s: %s is %s [ %s = %s; ] { export *[const]:4 %s; }" %
          (name, v, pat, v, val, v))
    w("")


# ===========================================================================
# Header
# ===========================================================================
w("#  TMS320C6000 16-bit compact instruction definitions.")
w("#")
w("#  Part of the ghidra-c6000 processor extension, Apache License 2.0.")
w("#  Written independently from the public Texas Instruments documentation;")
w("#  every encoding and semantic rule is traceable to a figure, table or")
w("#  section of")
w("#")
w("#      SPRUFE8B - TMS320C674x CPU and Instruction Set Reference Guide")
w("#                 (literature number SPRUFE8B, July 2010)")
w("#")
w("#  The 16-bit opcodes are mapped in appendices C.4 (D), D.4 (L), E.4 (M),")
w("#  F.4 (S), G.3 (D/L/S) and H.4 (no unit).  Parameters that the 16-bit")
w("#  opcode cannot express (register-set base, LD/ST data sizes, saturation")
w("#  and the S-unit branch mode) come from the compact fetch-packet header")
w("#  word described in section 3.10 and are supplied through the context")
w("#  register by the packet analyzer.")
w("#")
w("#  LENGTH: every constructor here consumes exactly the insn16 token, i.e.")
w("#  two bytes.  No constructor references insn32.")
w("#")
w("#  Register-base scheme: compact register fields are 3 bits and index")
w("#  within the register set selected by the header RS bit (context c_rs):")
w("#  low = A0-A7 / B0-B7, high = A16-A23 / B16-B23.  The opcode side bit")
w("#  (q_s for arithmetic, q_t for LD/ST data) selects the A or B file.  Since")
w("#  SLEIGH allows only one register list per field, each slot is declared")
w("#  once per (file, set) pair in c6000.sinc (_a0/_b0/_a1/_b1) and the small")
w("#  sub-tables below select the right one from q_s/q_t and c_rs.")
w("")
w("#  Conventions used below:")
w("#")
w("#  * c_dsz is the header DSZ field packed as")
w("#      (DSZ[18] << 2) | (DSZ[17] << 1) | DSZ[16],")
w("#    exactly as SPRUFE8B Table 3-15 indexes it (C6000PacketContext writes")
w("#    it as (header >>> 16) & 7).  Table 3-15 selects the primary and")
w("#    secondary LD/ST data size from it.")
w("#  * A bracketed compact offset is scaled by the access size, as for the")
w("#    32-bit addressing modes (SPRUFE8B section 3.9.3): <<0 byte, <<1")
w("#    halfword, <<2 word, <<3 doubleword.")
w("#  * Figure C-12 Dinc (\"*ptr[ucst2]++\") is a post-increment: the access")
w("#    uses ptr and ptr is then advanced by the scaled offset.  Figure C-14")
w("#    Ddec (\"*--ptr[ucst2]\") is a pre-decrement: ptr is advanced first and")
w("#    the access uses the new ptr.  Figure C-21 Dpp pairs \"*B15--[ucst2]\"")
w("#    (post-decrement) with \"*++B15[ucst2]\" (pre-increment).")
w("#  * Doubleword (DW/NDW) forms name a register pair. The transfer is")
w("#    decoded but left as a placeholder operation.")
w("")
w("#  This file is generated by tools/gen_compact.py; edit the generator.")
w("")
w("#  `c6000_unimplemented` is the catch-all userop called for every compact")
w("#  instruction whose semantics are not lifted to real p-code below.")
w("define pcodeop c6000_unimplemented;")
w("")

# ===========================================================================
# Display helpers: functional-unit suffixes
# ===========================================================================
w("# ---------------------------------------------------------------------------")
w("# Functional-unit suffixes.  In a compact instruction the opcode side bit")
w("# (bit 0, q_s) selects both the register file and the unit side, exactly as")
w("# the s bit does for 32-bit instructions (SPRUFE8B Table C-2).")
w("# ---------------------------------------------------------------------------")
w("")
for unit, tbl in (("S", "CUnitS"), ("L", "CUnitL"), ("M", "CUnitM"), ("D", "CUnitD")):
    w('%s: ".%s1" is q_s=0 { }' % (tbl, unit))
    w('%s: ".%s2" is q_s=1 { }' % (tbl, unit))
    w("")
w("# Figure G-1..G-4 carry an explicit 2-bit unit field: 00 = .L, 01 = .S,")
w("# 10 = .D (Figure G-4 unit selection table).")
w('CUnitLSD: ".L1" is q_unit=0 & q_s=0 { }')
w('CUnitLSD: ".L2" is q_unit=0 & q_s=1 { }')
w('CUnitLSD: ".S1" is q_unit=1 & q_s=0 { }')
w('CUnitLSD: ".S2" is q_unit=1 & q_s=1 { }')
w('CUnitLSD: ".D1" is q_unit=2 & q_s=0 { }')
w('CUnitLSD: ".D2" is q_unit=2 & q_s=1 { }')
w("")

# ===========================================================================
# Register operand tables
# ===========================================================================
w("# ---------------------------------------------------------------------------")
w("# Register operands.  RA/ RB are two independent symbols over the same")
w("# field so that a constructor can print both src2 and dst for the")
w("# two-address forms.")
w("# ---------------------------------------------------------------------------")
w("")
reg_table("RA15", "1513", "s")
reg_table("RB15", "1513", "s")
reg_table("RA97", "97", "s")
reg_table("RB97", "97", "s")
reg_table("RA64", "64", "s")
reg_table("RA1110", "1110", "s")
reg_table("RA4", "4", "s")
cross_table("RX97", "97")
reg_table("RT64", "64", "t")
for suf in SUFFIXES["65"]:
    regs = A if suf[0] == "a" else B
    base = 0 if suf[1] == "0" else 16
    side = 0 if suf[0] == "a" else 1
    rs = int(suf[1])
    for index in range(4):
        even = base + 2 * index
        w('RT65Pair: "%s%d:%s%d" is q_r2b=%d & q_t=%d & c_rs=%d '
          '{ export %s%d_%s%d; }' %
          (suf[0].upper(), even + 1, suf[0].upper(), even,
           index, side, rs, suf[0].upper(), even + 1, suf[0].upper(), even))
w("")
reg_table("RPTR", "87", "s")
reg_table("RT710", "710", "tn")
for file, side in (("A", 0), ("B", 1)):
    for even in range(0, 16, 2):
        w('RT710Pair: "%s%d:%s%d" is q_pair710=%d & q_t=%d '
          '{ export %s%d_%s%d; }' %
          (file, even + 1, file, even, even, side, file, even + 1, file, even))
w("")
reg_table("RB710", "710b", "br")
w("# Accumulator (A0/B0) and link register (A3/B3) named by the s bit.")
w("CAcc: cq_acc is cq_acc { export cq_acc; }")
w("")
w("CRet: cq_ret is cq_ret { export cq_ret; }")
w("")
w("# Predicate prefixes for the predicated compact forms (Figures F-20/F-21")
w("# and G-3).  A display-only table must start the display, hence the table.")
w('CPred20: "[A0] " is q_s=0 & j4=0 { }')
w('CPred20: "[!A0] " is q_s=0 & j4=1 { }')
w('CPred20: "[B0] " is q_s=1 & j4=0 { }')
w('CPred20: "[!B0] " is q_s=1 & j4=1 { }')
w("")
w('CPredCC: "[A0] " is j15=0 & j14=0 { }')
w('CPredCC: "[!A0] " is j15=0 & j14=1 { }')
w('CPredCC: "[B0] " is j15=1 & j14=0 { }')
w('CPredCC: "[!B0] " is j15=1 & j14=1 { }')
w("")

# ===========================================================================
# Immediate operand tables
# ===========================================================================
w("# ---------------------------------------------------------------------------")
w("# Immediate operands.  Compact immediate fields are scattered across the")
w("# opcode, so each one is composed here.")
w("# ---------------------------------------------------------------------------")
w("")
imm1("Cucst4", "(j11 << 3) | q_r3", "j11 & q_r3")            # Figure C-8..C-15
imm1("Cucst2", "q_uc2 + 1", "q_uc2")                        # Figures C-12..C-15
imm1("Cucst2pp", "q_uc2 + 1", "q_uc2")                      # Figure C-21
imm1("Cucst5stk", "(cq_u21 << 3) | q_r3b", "cq_u21 & q_r3b")  # Figure C-16
imm1("Cucst5d", "(cq_uc43 << 3) | q_r3", "cq_uc43 & q_r3")  # Figures C-18/F-25/F-27/F-30
imm1("Cucst5p", "(cq_uc98 << 3) | q_r3", "cq_uc98 & q_r3")  # Figure C-19
imm1("Cucst5f23", "(cq_uc43 << 3) | q_r3", "cq_uc43 & q_r3")
imm1("Cucst8f24", "(cq_uc65 << 5) | (j10 << 7) | (cq_uc43 << 3) | q_r3",
     "cq_uc65 & j10 & cq_uc43 & q_r3")                      # Figure F-24
plain1("Cucst3d9", "q_r3")                            # Figure D-9
plain1("Cucst1f", "q_uc2")                           # Figures D-10/G-3
plain1("CN3", "q_r3")                                 # F-17/F-20/F-32/H-9
imm1("Cii", "((cq_ii3 << 3) | q_r3b) + 1", "cq_ii3 & q_r3b") # Figures H-5/H-6
imm1("Cspk", "(cq_spk43 << 3) | q_r3b | (j0 << 5)", "cq_spk43 & q_r3b & j0")
imm1("Cmask", "(j15 << 5) | (j14 << 4) | (j9 << 3) | (j8 << 2) | (j7 << 1) | j0",
     "j15 & j14 & j9 & j8 & j7 & j0")

# Figure D-5 L3i constant table (sn | cst3 -> scst5).
w("# Figure D-5 constant translation (the opcode is sign-magnitude with 0 -> 8).")
l3i = []
for sn in (0, 1):
    for c3 in range(8):
        # Figure D-5: sn=0 encodes {8,1,2,3,4,5,6,7} and sn=1 encodes
        # {-8,-7,-6,-5,-4,-3,-2,-1}.
        if sn == 0:
            val = 8 if c3 == 0 else c3
        else:
            val = c3 - 8
        l3i.append((str(val), "j11=%d & q_r3=%d" % (sn, c3)))
imm_table("CimmL3i", l3i)

# Figure D-8 Lx5 signed 5-bit constant (bits 12,11 are the high two bits).
w("# Figure D-8 scst5 (bit 12 is the sign, bit 11 is scst4, bits 15..13 are scst2-0).")
lx5 = []
for raw in range(32):
    val = raw - 32 if raw >= 16 else raw
    lx5.append((str(val), "j12=%d & j11=%d & q_r3=%d" % ((raw >> 4) & 1, (raw >> 3) & 1, raw & 7)))
imm_table("CimmLx5", lx5)

# Figure F-23 cst3 -> ucst5.
w("# Figure F-23 cst3 -> ucst5 translation (000 encodes 16, 111 encodes 8).")
s3i = []
for c3 in range(8):
    val = 16 if c3 == 0 else (8 if c3 == 7 else c3)
    s3i.append((str(val), "q_r3=%d" % c3))
imm_table("CimmS3i", s3i)

# Figure C-18/C-19 use Cucst5d/Cucst5p defined above.

w("# ---------------------------------------------------------------------------")
w("# Branch targets for the compact S-unit branch forms (Figures F-17..F-21).")
w("#")
w("# Compact fetch packets scale the displacement by one bit, not two:")
w("# SPRUFE8B BNOP execution block, 'if instruction is within compact")
w("# instruction fetch packet':  PFC = PCE1 + (se(scst12) << 1), where PCE1 =")
w("# inst_start & 0xFFFFFFE0 is the first instruction of the containing fetch")
w("# packet.  The compact forms use the same rule with their own displacement")
w("# widths (Figures F-17/F-18/F-20/F-21 carry scst7 or ucst8, Figure F-19")
w("# carries scst10).")
w("# ---------------------------------------------------------------------------")
w("")
w("CTgt7: reloc is cq_scst7 [ reloc = (inst_start & 0xffffffe0) + (cq_scst7 << 1); ]")
w("  { export *[const]:4 reloc; }")
w("")
w("CTgt8: reloc is cq_ucst8 [ reloc = (inst_start & 0xffffffe0) + (cq_ucst8 << 1); ]")
w("  { export *[const]:4 reloc; }")
w("")
w("CTgt10: reloc is cq_scst10 [ reloc = (inst_start & 0xffffffe0) + (cq_scst10 << 1); ]")
w("  { export *[const]:4 reloc; }")
w("")

# ===========================================================================
# Helpers for the LD/ST section
# ===========================================================================
SHIFT = {1: 0, 2: 1, 4: 2, 8: 3}


def ldst_info(v, sz, na=None):
    """Map (DSZ, sz, na) to (name, size, sign, pair) or None.

    c_dsz is the header DSZ field packed as (DSZ[18] << 2) | (DSZ[17] << 1) | DSZ[16],
    exactly as SPRUFE8B Table 3-15 indexes it.
    """
    dszp = (v >> 2) & 1
    dszs = v & 3
    if sz == 0:
        if dszp == 0:
            return ("W", 4, "u", False)
        if na is None:
            return None
        return ("DW" if na == 0 else "NDW", 8, "u", True)
    if dszp == 0:
        return [("BU", 1, "u", False), ("B", 1, "s", False),
                ("HU", 2, "u", False), ("H", 2, "s", False)][dszp * 0 + dszs]
    return [("W", 4, "u", False), ("B", 1, "s", False),
            ("NW", 4, "u", False), ("H", 2, "s", False)][dszs]


def ld_sem(reg, addr, size, sign):
    if size >= 4:
        return "%s = *[ram]:%d %s;" % (reg, size, addr)
    if sign == "s":
        return "%s = sext(*[ram]:%d %s);" % (reg, size, addr)
    return "%s = zext(*[ram]:%d %s);" % (reg, size, addr)


def st_sem(reg, addr, size):
    return "*[ram]:%d %s = %s;" % (size, addr, reg)


def unimpl():
    return "c6000_unimplemented();"


# ===========================================================================
# Figures C-8..C-15: offset / indirect / post-increment / pre-decrement
# ===========================================================================
def emit_dformat(fig, pat, mem_kind, imm, has_na, dwonly):
    """Emit all DSZ-selected constructors for one D-unit memory format.

    mem_kind: 'off'   -> *ptr[imm]      (no pointer update)
              'ind'   -> *ptr[RA15]     (no pointer update)
              'inc'   -> *ptr[imm]++    (post-increment by imm)
              'dec'   -> *--ptr[imm]    (pre-decrement by imm)
    """
    w("# ---------------------------------------------------------------------------")
    w("# %s" % fig)
    w("# ---------------------------------------------------------------------------")
    w("")
    for v in range(8):
        for sz in (0, 1):
            naref = (None,) if not has_na else (0, 1)
            if has_na:
                if sz != 0:
                    continue
                if ((v >> 2) & 1) == 0:
                    # The *DW figures only exist for DSZ[18] = 1.
                    continue
                for na in (0, 1):
                    info = ldst_info(v, sz, na)
                    if info is None:
                        continue
                    emit_one(pat, mem_kind, imm, v, info, na, sz)
            else:
                info = ldst_info(v, sz, None)
                if info is None:
                    continue
                emit_one(pat, mem_kind, imm, v, info, None, sz)


def emit_one(pat, mem_kind, imm, v, info, na, sz):
    name, size, sign, pair = info
    for ldst in (0, 1):
        mn = ("LD" if ldst else "ST") + name
        terms = list(pat) + ["c_dsz=%d" % v, "q_ldst=%d" % ldst]
        if na is not None:
            terms.append("q_na=%d" % na)
        newpat = list(pat) + ["c_dsz=%d" % v, "q_ldst=%d" % ldst]
        if not any(t.startswith("q_sz=") for t in pat):
            newpat.append("q_sz=%d" % sz)
        if na is not None:
            newpat.append("q_na=%d" % na)
        shift = SHIFT[size]
        if mem_kind == "off":
            memdisp = '"*"^RPTR^"["^%s^"]"' % imm
            addr = "(RPTR + (%s << %d))" % (imm, shift)
            pre = []
            post = []
            tabs = ["RPTR", imm]
            reg = "RT64" if size <= 4 else "RT65"
            tabs.append(reg)
            sto = reg
            if size <= 4:
                if ldst:
                    sem = ld_sem(reg, addr, size, sign)
                else:
                    sem = st_sem(reg, addr, size)
            else:
                sem = ld_sem(reg, addr, size, sign) if ldst else st_sem(reg, addr, size)
            if ldst:
                disp = "%s^CUnitD^\" \"^%s^\", \"^%s" % (mn, memdisp, reg)
            else:
                disp = "%s^CUnitD^\" \"^%s^\", \"^%s" % (mn, reg, memdisp)
        elif mem_kind == "ind":
            memdisp = '"*"^RPTR^"["^RA15^"]"'
            addr = "(RPTR + (RA15 << %d))" % shift
            tabs = ["RPTR", "RA15"]
            reg = "RT64" if size <= 4 else "RT65"
            tabs.append(reg)
            if size <= 4:
                sem = ld_sem(reg, addr, size, sign) if ldst else st_sem(reg, addr, size)
            else:
                sem = ld_sem(reg, addr, size, sign) if ldst else st_sem(reg, addr, size)
            if ldst:
                disp = "%s^CUnitD^\" \"^%s^\", \"^%s" % (mn, memdisp, reg)
            else:
                disp = "%s^CUnitD^\" \"^%s^\", \"^%s" % (mn, reg, memdisp)
        elif mem_kind == "inc":
            memdisp = '"*"^RPTR^"["^%s^"]++"' % imm
            tabs = ["RPTR", imm]
            reg = "RT64" if size <= 4 else "RT65"
            tabs.append(reg)
            if size <= 4:
                if ldst:
                    sem = "%s RPTR = RPTR + (%s << %d);" % (
                        ld_sem(reg, "RPTR", size, sign), imm, shift)
                else:
                    sem = "%s RPTR = RPTR + (%s << %d);" % (
                        st_sem(reg, "RPTR", size), imm, shift)
            else:
                if ldst:
                    sem = "%s RPTR = RPTR + (%s << %d);" % (
                        ld_sem(reg, "RPTR", size, sign), imm, shift)
                else:
                    sem = "%s RPTR = RPTR + (%s << %d);" % (
                        st_sem(reg, "RPTR", size), imm, shift)
            if ldst:
                disp = "%s^CUnitD^\" \"^%s^\", \"^%s" % (mn, memdisp, reg)
            else:
                disp = "%s^CUnitD^\" \"^%s^\", \"^%s" % (mn, reg, memdisp)
        elif mem_kind == "dec":
            memdisp = '"*--"^RPTR^"["^%s^"]"' % imm
            tabs = ["RPTR", imm]
            reg = "RT64" if size <= 4 else "RT65"
            tabs.append(reg)
            if size <= 4:
                if ldst:
                    sem = "RPTR = RPTR - (%s << %d); %s" % (
                        imm, shift, ld_sem(reg, "RPTR", size, sign))
                else:
                    sem = "RPTR = RPTR - (%s << %d); %s" % (
                        imm, shift, st_sem(reg, "RPTR", size))
            else:
                if ldst:
                    sem = "RPTR = RPTR - (%s << %d); %s" % (
                        imm, shift, ld_sem(reg, "RPTR", size, sign))
                else:
                    sem = "RPTR = RPTR - (%s << %d); %s" % (
                        imm, shift, st_sem(reg, "RPTR", size))
            if ldst:
                disp = "%s^CUnitD^\" \"^%s^\", \"^%s" % (mn, memdisp, reg)
            else:
                disp = "%s^CUnitD^\" \"^%s^\", \"^%s" % (mn, reg, memdisp)
        else:
            raise ValueError(mem_kind)
        con(disp, newpat + tabs, sem)
    w("")


# Figure C-8 Doff4
emit_dformat("Figure C-8. Doff4 - SPRUFE8B appendix C.4.",
             ["j10=0", "j2=1", "j1=0"], "off", "Cucst4", False, False)
# Figure C-9 Doff4DW
emit_dformat("Figure C-9. Doff4DW - SPRUFE8B appendix C.4.",
             ["j10=0", "j2=1", "j1=0", "q_sz=0"], "off", "Cucst4", True, True)
# Figure C-10 Dind
emit_dformat("Figure C-10. Dind - SPRUFE8B appendix C.4.",
             ["j11=0", "j10=1", "j2=1", "j1=0"], "ind", None, False, False)
# Figure C-11 DindDW
emit_dformat("Figure C-11. DindDW - SPRUFE8B appendix C.4.",
             ["j11=0", "j10=1", "j2=1", "j1=0", "q_sz=0"], "ind", None, True, True)
# Figure C-12 Dinc
emit_dformat("Figure C-12. Dinc - SPRUFE8B appendix C.4.",
             ["j15=0", "j14=0", "j11=1", "j10=1", "j2=1", "j1=0"], "inc", "Cucst2", False, False)
# Figure C-13 DincDW
emit_dformat("Figure C-13. DincDW - SPRUFE8B appendix C.4.",
             ["j15=0", "j14=0", "j11=1", "j10=1", "j2=1", "j1=0", "q_sz=0"], "inc", "Cucst2", True, True)
# Figure C-14 Ddec
emit_dformat("Figure C-14. Ddec - SPRUFE8B appendix C.4.",
             ["j15=0", "j14=1", "j11=1", "j10=1", "j2=1", "j1=0"], "dec", "Cucst2", False, False)
# Figure C-15 DdecDW
emit_dformat("Figure C-15. DdecDW - SPRUFE8B appendix C.4.",
             ["j15=0", "j14=1", "j11=1", "j10=1", "j2=1", "j1=0", "q_sz=0"], "dec", "Cucst2", True, True)

# Figure C-16 Dstk
w("# ---------------------------------------------------------------------------")
w("# Figure C-16. Dstk - SPRUFE8B appendix C.4.  ptr is B15 and s is fixed to 1")
w("# (so the unit is always .D2); the 5-bit offset is scaled by the word size.")
w("# ---------------------------------------------------------------------------")
w("")
for ldst in (0, 1):
    mn = "LDW" if ldst else "STW"
    disp = "%s^CUnitD^\" \"^RT64^\", *B15[\"^Cucst5stk^\"]\"" % mn if ldst is False else \
           "%s^CUnitD^\" *B15[\"^Cucst5stk^\"], \"^RT64" % mn
    sem = ld_sem("RT64", "(B15 + (Cucst5stk << 2))", 4, "u") if ldst else \
          st_sem("RT64", "(B15 + (Cucst5stk << 2))", 4)
    con(disp, ["j15=1", "j11=1", "j10=1", "j2=1", "j1=0", "q_s=1", "q_ldst=%d" % ldst,
               "RT64", "Cucst5stk"], sem)
w("")

# Figure C-17 Dx2op
w("# ---------------------------------------------------------------------------")
w("# Figure C-17. Dx2op - SPRUFE8B appendix C.4.")
w("# ---------------------------------------------------------------------------")
w("")
for op, mn, sem in ((0, "ADD", "RB15 = RA15 + RX97;"),
                    (1, "SUB", "RB15 = RA15 - RX97;")):
    con("%s^CUnitD RA15, RX97, RB15" % mn,
        ["j10=0", "j6=0", "j5=1", "j4=1", "j3=0", "j2=1", "j1=1", "j11=%d" % op,
         "RA15", "RX97", "RB15"], sem)
w("")

# Figure C-18 Dx5
w("# ---------------------------------------------------------------------------")
w("# Figure C-18. Dx5 - SPRUFE8B appendix C.4.  src2 is B15; ADDAW shifts the")
w("# 5-bit constant left by two (word addressing mode).")
w("# ---------------------------------------------------------------------------")
w("")
con("ADDAW^CUnitD^\" B15, \"^Cucst5d^\", \"^RA97",
    ["j10=1", "j6=0", "j5=1", "j4=1", "j3=0", "j2=1", "j1=1", "RA97", "Cucst5d"],
    "RA97 = B15 + (Cucst5d << 2);")
w("")

# Figure C-19 Dx5p
w("# ---------------------------------------------------------------------------")
w("# Figure C-19. Dx5p - SPRUFE8B appendix C.4.  src2 = dst = B15.")
w("# ---------------------------------------------------------------------------")
w("")
for op, mn, sem in ((0, "ADDAW", "B15 = B15 + (Cucst5p << 2);"),
                    (1, "SUBAW", "B15 = B15 - (Cucst5p << 2);")):
    con('%s^CUnitD^" B15, "^Cucst5p^", B15"' % mn,
        ["j12=0", "j11=1", "j10=1", "j6=1", "j5=1", "j4=1", "j3=0", "j2=1", "j1=1",
         "j7=%d" % op, "Cucst5p"], sem)
w("")

# Figure C-20 Dx1
w("# ---------------------------------------------------------------------------")
w("# Figure C-20. Dx1 - SPRUFE8B appendix C.4.  op = 010, 100 and 110 are")
w("# reserved by the figure; op = 000/001/101/111 are the LSDx1 forms of")
w("# Figure G-4 and are decoded there.")
w("# ---------------------------------------------------------------------------")
w("")
con("SUB^CUnitD RA97, 1, RB97",
    ["j12=1", "j11=1", "j10=0", "j6=1", "j5=1", "j4=1", "j3=0", "j2=1", "j1=1",
     "j15=0", "j14=1", "j13=1", "RA97", "RB97"], "RB97 = RA97 - 1;")
w("")

# Figure C-21 Dpp
w("# ---------------------------------------------------------------------------")
w("# Figure C-21. Dpp - SPRUFE8B appendix C.4.  ptr is B15, the header RS bit")
w("# is ignored and src/dst is a 4-bit register number from A0-A15/B0-B15")
w("# selected by t (SPRUFE8B Figure C-21 notes 1-4).")
w("# ---------------------------------------------------------------------------")
w("")
for dw, ldst, suf, upd in ((0, 0, "W", "B15 = B15 - (Cucst2pp << 2);"),
                           (0, 1, "W", "B15 = B15 + (Cucst2pp << 2);"),
                           (1, 0, "DW", "B15 = B15 - (Cucst2pp << 3);"),
                           (1, 1, "DW", "B15 = B15 + (Cucst2pp << 3);")):
    mn = ("LD" if ldst else "ST") + suf
    post = (dw == 0 and ldst == 0) or (dw == 1 and ldst == 0)
    if post:
        memdisp = '"*B15--["^Cucst2pp^"]"'
    else:
        memdisp = '"*++B15["^Cucst2pp^"]"'
    if dw == 0:
        if ldst:
            sem = "B15 = B15 + (Cucst2pp << 2); RT710 = *[ram]:4 B15;"
        else:
            sem = "*[ram]:4 B15 = RT710; B15 = B15 - (Cucst2pp << 2);"
        if ldst:
            disp = "%s^CUnitD^\" \"^%s^\", \"^RT710" % (mn, memdisp)
        else:
            disp = "%s^CUnitD^\" \"^RT710^\", \"^%s" % (mn, memdisp)
    else:
        if ldst:
            sem = "B15 = B15 + (Cucst2pp << 3); RT710Pair = *[ram]:8 B15;"
        else:
            sem = "*[ram]:8 B15 = RT710Pair; B15 = B15 - (Cucst2pp << 3);"
        if ldst:
            disp = "%s^CUnitD^\" \"^%s^\", \"^RT710" % (mn, memdisp)
        else:
            disp = "%s^CUnitD^\" \"^RT710^\", \"^%s" % (mn, memdisp)
    con(disp, ["j11=0", "j6=1", "j5=1", "j4=1", "j3=0", "j2=1", "j1=1", "j0=1",
               "j15=%d" % dw, "j14=%d" % ldst, "RT710", "Cucst2pp"], sem)
w("")

# ===========================================================================
# Figures D-4..D-11: .L unit
# ===========================================================================
w("# ---------------------------------------------------------------------------")
w("# Figure D-4. L3 - SPRUFE8B appendix D.4.")
w("# ---------------------------------------------------------------------------")
w("")
for sat in (0, 1):
    for op, base, sem in ((0, "ADD", "RA64 = RA15 + RX97;"), (1, "SUB", "RA64 = RA15 - RX97;")):
        mn = ("S" + base) if sat else base
        used = sem if sat == 0 else unimpl()
        con("%s^CUnitL RA15, RX97, RA64" % mn,
            ["j10=0", "j3=0", "j2=0", "j1=0", "j11=%d" % op, "c_sat=%d" % sat,
             "RA15", "RX97", "RA64"], used)
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure D-5. L3i - SPRUFE8B appendix D.4.")
w("# ---------------------------------------------------------------------------")
w("")
for sat in (0, 1):
    mn = "SADD" if sat else "ADD"
    sem = unimpl() if sat else "RA64 = RX97 + CimmL3i;"
    con("%s^CUnitL CimmL3i, RX97, RA64" % mn,
        ["j10=1", "j3=0", "j2=0", "j1=0", "c_sat=%d" % sat, "CimmL3i", "RX97", "RA64"],
        sem)
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure D-6. Ltbd - SPRUFE8B appendix D.4.  The figure leaves its fields")
w("# blank and no instruction description in SPRUFE8B references it, so no")
w("# constructor is emitted.")
w("# ---------------------------------------------------------------------------")
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure D-7. L2c - SPRUFE8B appendix D.4.  dst is a single bit selecting")
w("# A0/A1 or B0/B1 (note under the figure).")
w("# ---------------------------------------------------------------------------")
w("")
l2c = [(0, 0, 0, "AND", "RA4 = RA15 & RX97;"),
       (0, 0, 1, "OR", "RA4 = RA15 | RX97;"),
       (0, 1, 0, "XOR", "RA4 = RA15 ^ RX97;"),
       (0, 1, 1, "CMPEQ", "RA4 = zext(RA15 == RX97);"),
       (1, 0, 0, "CMPLT", "RA4 = zext(RA15 s< RX97);"),
       (1, 0, 1, "CMPGT", "RA4 = zext(RA15 s> RX97);"),
       (1, 1, 0, "CMPLTU", "RA4 = zext(RA15 < RX97);"),
       (1, 1, 1, "CMPGTU", "RA4 = zext(RA15 > RX97);")]
for op2, op1, op0, mn, sem in l2c:
    con("%s^CUnitL RA15, RX97, RA4" % mn,
        ["j10=1", "j3=1", "j2=0", "j1=0", "j11=%d" % op2, "j6=%d" % op1, "j5=%d" % op0,
         "RA15", "RX97", "RA4"], sem)
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure D-8. Lx5 - SPRUFE8B appendix D.4.")
w("# ---------------------------------------------------------------------------")
w("")
con("MVK^CUnitL CimmLx5, RA97",
    ["j10=1", "j6=0", "j5=1", "j4=0", "j3=0", "j2=1", "j1=1", "CimmLx5", "RA97"],
    "RA97 = CimmLx5;")
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure D-9. Lx3c - SPRUFE8B appendix D.4.")
w("# ---------------------------------------------------------------------------")
w("")
con("CMPEQ^CUnitL Cucst3d9, RA97, RA4",
    ["j12=0", "j10=0", "j6=0", "j5=1", "j4=0", "j3=0", "j2=1", "j1=1",
     "Cucst3d9", "RA97", "RA4"], "RA4 = zext(Cucst3d9 == RA97);")
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure D-10. Lx1c - SPRUFE8B appendix D.4.")
w("# ---------------------------------------------------------------------------")
w("")
for op, mn, sem in ((0, "CMPLT", "RA4 = zext(Cucst1f s< RA97);"),
                    (1, "CMPGT", "RA4 = zext(Cucst1f s> RA97);"),
                    (2, "CMPLTU", "RA4 = zext(Cucst1f < RA97);"),
                    (3, "CMPGTU", "RA4 = zext(Cucst1f > RA97);")):
    con("%s^CUnitL Cucst1f, RA97, RA4" % mn,
        ["j12=1", "j10=0", "j6=0", "j5=1", "j4=0", "j3=0", "j2=1", "j1=1",
         "j15=%d" % ((op >> 1) & 1), "j14=%d" % (op & 1), "Cucst1f", "RA97", "RA4"], sem)
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure D-11. Lx1 - SPRUFE8B appendix D.4.  op = 100 and 110 are reserved;")
w("# op = 000/001/101/111 are LSDx1 (Figure G-4).")
w("# ---------------------------------------------------------------------------")
w("")
con('SUB^CUnitL^" 0, "^RA97^", "^RB97',
    ["j12=1", "j11=1", "j10=0", "j6=1", "j5=1", "j4=0", "j3=0", "j2=1", "j1=1",
     "j15=0", "j14=1", "j13=0", "RA97", "RB97"], "RB97 = 0 - RA97;")
con('ADD^CUnitL^" -1, "^RA97^", "^RB97',
    ["j12=1", "j11=1", "j10=0", "j6=1", "j5=1", "j4=0", "j3=0", "j2=1", "j1=1",
     "j15=0", "j14=1", "j13=1", "RA97", "RB97"], "RB97 = RA97 - 1;")
w("")

# ===========================================================================
# Figure E-5: .M unit
# ===========================================================================
w("# ---------------------------------------------------------------------------")
w("# Figure E-5. M3 - SPRUFE8B appendix E.4.  dst is an even register; with")
w("# RS = 1 it is A16/A18/A20/A22 or B16/B18/B20/B22 (figure note).")
w("# ---------------------------------------------------------------------------")
w("")
for sat in (0, 1):
    for op, base in ((0, "MPY"), (1, "MPYH"), (2, "MPYLH"), (3, "MPYHL")):
        mn = ("S" + base) if sat else base
        if sat:
            sem = unimpl()
        elif op == 0:
            sem = ("local a:4 = (RA15 << 16) s>> 16; "
                   "local b:4 = (RX97 << 16) s>> 16; RA1110 = a * b;")
        elif op == 1:
            sem = "RA1110 = (RA15 s>> 16) * (RX97 s>> 16);"
        elif op == 2:
            sem = ("local a:4 = (RA15 << 16) s>> 16; "
                   "RA1110 = a * (RX97 s>> 16);")
        else:
            sem = ("local b:4 = (RX97 << 16) s>> 16; "
                   "RA1110 = (RA15 s>> 16) * b;")
        con("%s^CUnitM RA15, RX97, RA1110" % mn,
            ["j4=1", "j3=1", "j2=1", "j1=1", "j6=%d" % ((op >> 1) & 1), "j5=%d" % (op & 1),
             "c_sat=%d" % sat, "RA15", "RX97", "RA1110"], sem)
w("")

# ===========================================================================
# Figures F-17..F-32: .S unit
# ===========================================================================
w("# ---------------------------------------------------------------------------")
w("# Figures F-17/F-18. Sbs7 / Sbu8 - SPRUFE8B appendix F.4.  BR = 1 decodes")
w("# the S unit as branches; the target uses the compact <<1 displacement")
w("# scale (see the CTgt tables above).")
w("# ---------------------------------------------------------------------------")
w("")
con("BNOP^CUnitS CTgt7, CN3",
    ["j5=0", "j4=0", "j3=1", "j2=0", "j1=1", "c_br=1", "CTgt7", "CN3"], "goto CTgt7;")
con("BNOP^CUnitS CTgt8, 5",
    ["j15=1", "j14=1", "j5=0", "j4=0", "j3=1", "j2=0", "j1=1", "c_br=1", "CTgt8"], "goto CTgt8;")
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure F-19. Scs10 (CALLP) - SPRUFE8B appendix F.4.  The return address")
w("# goes to A3 or B3 as selected by s (figure note 'NextPC > B3, A3').")
w("# ---------------------------------------------------------------------------")
w("")
con("CALLP^CUnitS CTgt10, CRet",
    ["j5=0", "j4=1", "j3=1", "j2=0", "j1=1", "c_br=1", "CTgt10", "CRet"],
    "CRet = inst_start + 24; call CTgt10;")
w("")

w("# ---------------------------------------------------------------------------")
w("# Figures F-20/F-21. Sbs7c / Sbu8c - SPRUFE8B appendix F.4.  Predicated")
w("# BNOP; the predicate register is [A0]/[B0] as selected by s and the test")
w("# is inverted when z = 1.")
w("# ---------------------------------------------------------------------------")
w("")
for z in (0, 1):
    for sp in (0, 1):
        r = "A0" if sp == 0 else "B0"
        neg = "!" if z else ""
        for fig, pat, tgt, ndisp, ntab in (
                ("F-20", ["j5=1", "j3=1", "j2=0", "j1=1"], "CTgt7", "CN3", ["CN3"]),
                ("F-21", ["j15=1", "j14=1", "j5=1", "j3=1", "j2=0", "j1=1"], "CTgt8", "5", [])):
            condition = "%s %s 0" % (r, "==" if z else "!=")
            con('CPred20^"BNOP"^CUnitS %s, %s' % (tgt, ndisp),
                ["c_br=1", "q_s=%d" % sp, "j4=%d" % z] + pat + [tgt] + ntab,
                "if (%s) goto %s;" % (condition, tgt))
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure F-22. S3 - SPRUFE8B appendix F.4.  BR must be 0 for the")
w("# non-branch S-unit opcodes (Table 3-14).")
w("# ---------------------------------------------------------------------------")
w("")
for sat in (0, 1):
    for op, base, sem in ((0, "ADD", "RA64 = RA15 + RX97;"), (1, "SUB", "RA64 = RA15 - RX97;")):
        if op == 1:
            mn = "SUB"
            used = sem
        else:
            mn = ("S" + base) if sat else base
            used = sem if sat == 0 else unimpl()
        con("%s^CUnitS RA15, RX97, RA64" % mn,
            ["j10=0", "j3=1", "j2=0", "j1=1", "c_br=0", "j11=%d" % op,
             "c_sat=%d" % sat, "RA15", "RX97", "RA64"], used)
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure F-23. S3i - SPRUFE8B appendix F.4.  cst3 translates to ucst5 per")
w("# the figure table (000 -> 16, 111 -> 8).")
w("# ---------------------------------------------------------------------------")
w("")
for sat in (0, 1):
    for op, base, shift in ((0, "SHL", "<<"), (1, "SHR", "s>>")):
        mn = ("S" + base) if (sat and op == 0) else base
        sem = unimpl() if (sat and op == 0) else "RA64 = RX97 %s CimmS3i;" % shift
        con("%s^CUnitS RX97, CimmS3i, RA64" % mn,
            ["j10=1", "j3=1", "j2=0", "j1=1", "c_br=0", "j11=%d" % op,
             "c_sat=%d" % sat, "CimmS3i", "RX97", "RA64"], sem)
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure F-24. Smvk8 - SPRUFE8B appendix F.4.")
w("# ---------------------------------------------------------------------------")
w("")
con("MVK^CUnitS Cucst8f24, RA97",
    ["j4=1", "j3=0", "j2=0", "j1=1", "c_br=0", "Cucst8f24", "RA97"], "RA97 = Cucst8f24;")
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure F-25. Ssh5 - SPRUFE8B appendix F.4.  The SAT header bit turns SHL")
w("# into SSHL and SHRU into SSHL (SPRUFE8B Table 3-14).")
w("# ---------------------------------------------------------------------------")
w("")
for sat in (0, 1):
    for op, base, shift in ((0, "SHL", "<<"), (1, "SHR", "s>>"), (2, "SHRU", ">>")):
        if sat == 1 and op == 1:
            # SHR is not affected by SAT
            pass
        mn = base
        if sat and op in (0, 2):
            mn = "SSHL"
        sem = unimpl() if mn == "SSHL" else "RB97 = RA97 %s Cucst5f23;" % shift
        con("%s^CUnitS RA97, Cucst5f23, RB97" % mn,
            ["j10=1", "j4=0", "j3=0", "j2=0", "j1=1", "c_br=0",
             "j6=%d" % ((op >> 1) & 1), "j5=%d" % (op & 1), "c_sat=%d" % sat,
             "RA97", "Cucst5f23", "RB97"], sem)
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure F-26. S2sh - SPRUFE8B appendix F.4.  x = 0: src and dst are on the")
w("# same side.  The SAT header bit turns SHL into SSHL (Table 3-14).")
w("# ---------------------------------------------------------------------------")
w("")
for op, mn, shift in ((0, "SHL", "<<"), (1, "SHR", "s>>"),
                      (2, "SHRU", ">>"), (3, "SSHL", None)):
    sats = (0, 1) if op == 0 else (None,)
    for sat in sats:
        name = "SSHL" if (op == 0 and sat == 1) else mn
        sem = unimpl() if shift is None or name == "SSHL" else "RB97 = RB97 %s RA15;" % shift
        pat = ["j10=1", "j6=1", "j5=1", "j4=0", "j3=0", "j2=0", "j1=1", "c_br=0",
               "j12=%d" % ((op >> 1) & 1), "j11=%d" % (op & 1),
               "RA97", "RA15", "RB97"]
        if sat is not None:
            pat.append("c_sat=%d" % sat)
        con("%s^CUnitS RA97, RA15, RB97" % name, pat, sem)
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure F-27. Sc5 - SPRUFE8B appendix F.4.  op = 11 selects S2ext")
w("# (Figure F-28).  SET/CLR take csta = cstb = ucst5, i.e. a single bit.")
w("# ---------------------------------------------------------------------------")
w("")
con("EXTU^CUnitS RA97, Cucst5f23, 31, CAcc",
    ["j10=0", "j4=0", "j3=0", "j2=0", "j1=1", "c_br=0", "j6=0", "j5=0",
     "RA97", "Cucst5f23", "CAcc"],
    "CAcc = (RA97 << Cucst5f23) >> 31;")
con("SET^CUnitS RA97, Cucst5d, Cucst5f23, RB97",
    ["j10=0", "j4=0", "j3=0", "j2=0", "j1=1", "c_br=0", "j6=0", "j5=1",
     "RA97", "Cucst5d", "Cucst5f23", "RB97"],
    "local b = 1; b = b << Cucst5d; RB97 = RA97 | b;")
con("CLR^CUnitS RA97, Cucst5d, Cucst5f23, RB97",
    ["j10=0", "j4=0", "j3=0", "j2=0", "j1=1", "c_br=0", "j6=1", "j5=0",
     "RA97", "Cucst5d", "Cucst5f23", "RB97"],
    "local b = 1; b = b << Cucst5d; RB97 = RA97 & ~b;")
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure F-28. S2ext - SPRUFE8B appendix F.4.")
w("# ---------------------------------------------------------------------------")
w("")
for op, mn, a, b in ((0, "EXT", 16, 16), (1, "EXT", 24, 24),
                     (2, "EXTU", 16, 16), (3, "EXTU", 24, 24)):
    shift = "s>>" if mn == "EXT" else ">>"
    con("%s^CUnitS RA97, %d, %d, RA15" % (mn, a, b),
        ["j10=0", "j6=1", "j5=1", "j4=0", "j3=0", "j2=0", "j1=1", "c_br=0",
         "j12=%d" % ((op >> 1) & 1), "j11=%d" % (op & 1), "RA97", "RA15"],
        "RA15 = (RA97 << %d) %s %d;" % (a, shift, b))
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure F-29. Sx2op - SPRUFE8B appendix F.4.  src1 = dst.")
w("# ---------------------------------------------------------------------------")
w("")
for op, mn, sem in ((0, "ADD", "RB15 = RA15 + RX97;"), (1, "SUB", "RB15 = RA15 - RX97;")):
    con("%s^CUnitS RA15, RX97, RB15" % mn,
        ["j10=0", "j6=0", "j5=1", "j4=0", "j3=1", "j2=1", "j1=1", "c_br=0",
         "j11=%d" % op, "RA15", "RX97", "RB15"], sem)
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure F-30. Sx5 (ADDK) - SPRUFE8B appendix F.4.")
w("# ---------------------------------------------------------------------------")
w("")
con("ADDK^CUnitS Cucst5d, RA97",
    ["j10=1", "j6=0", "j5=1", "j4=0", "j3=1", "j2=1", "j1=1", "c_br=0",
     "Cucst5d", "RA97"], "RA97 = RA97 + Cucst5d;")
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure F-31. Sx1 - SPRUFE8B appendix F.4.  op = 100 is reserved;")
w("# op = 000/001/101/111 are LSDx1 (Figure G-4); op = 110 is MVC src, ILC")
w("# and is only defined for s = 1.")
w("# ---------------------------------------------------------------------------")
w("")
con('SUB^CUnitS^" 0, "^RA97^", "^RB97',
    ["j12=1", "j11=1", "j10=0", "j6=1", "j5=1", "j4=0", "j3=1", "j2=1", "j1=1",
     "c_br=0", "j15=0", "j14=1", "j13=0", "RA97", "RB97"], "RB97 = 0 - RA97;")
con('ADD^CUnitS^" -1, "^RA97^", "^RB97',
    ["j12=1", "j11=1", "j10=0", "j6=1", "j5=1", "j4=0", "j3=1", "j2=1", "j1=1",
     "c_br=0", "j15=0", "j14=1", "j13=1", "RA97", "RB97"], "RB97 = RA97 - 1;")
con('MVC^CUnitS RA97^", ILC"',
    ["j12=1", "j11=1", "j10=0", "j6=1", "j5=1", "j4=0", "j3=1", "j2=1", "j1=1",
     "c_br=0", "j15=1", "j14=1", "j13=0", "q_s=1", "RA97"], "ILC = RA97;")
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure F-32. Sx1b (BNOP register form) - SPRUFE8B appendix F.4.  src2 is")
w("# a 4-bit register from B0-B15 (figure note).  The opcode space is unique")
w("# to this form, so it is decoded regardless of the header BR bit.")
w("# ---------------------------------------------------------------------------")
w("")
con("BNOP^CUnitS RB710, CN3",
    ["j12=0", "j11=0", "j6=1", "j5=1", "j4=0", "j3=1", "j2=1", "j1=1",
     "RB710", "CN3"], "goto [RB710];")
w("")

# ===========================================================================
# Figures G-1..G-4: .D/.L/.S shared
# ===========================================================================
w("# ---------------------------------------------------------------------------")
w("# Figures G-1/G-2. LSDmvto / LSDmvfr - SPRUFE8B appendix G.3.  The srcms /")
w("# dstms fields are not defined by Table G-1 and are not used by the")
w("# mnemonic, so they are left unconstrained here.")
w("# ---------------------------------------------------------------------------")
w("")
con("MV^CUnitLSD RX97, RA15",
    ["j6=0", "j5=0", "j2=1", "j1=1", "RX97", "RA15"], "RA15 = RX97;")
con("MV^CUnitLSD RX97, RA15",
    ["j6=1", "j5=0", "j2=1", "j1=1", "RX97", "RA15"], "RA15 = RX97;")
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure G-3. LSDx1c - SPRUFE8B appendix G.3.  Predicated MVK with a")
w("# 1-bit constant; CC selects [A0], [!A0], [B0] or [!B0].")
w("# ---------------------------------------------------------------------------")
w("")
for cc, pred, cond in ((0, "[A0]", "A0 != 0"), (1, "[!A0]", "A0 == 0"),
                       (2, "[B0]", "B0 != 0"), (3, "[!B0]", "B0 == 0")):
    con('CPredCC^"MVK"^CUnitLSD^" "^Cucst1f^", "^RA97',
        ["j12=0", "j11=1", "j10=0", "j6=1", "j5=1", "j2=1", "j1=1",
         "j15=%d" % ((cc >> 1) & 1), "j14=%d" % (cc & 1), "Cucst1f", "RA97"],
        "if (%s) goto <cskip>; RA97 = Cucst1f; <cskip>" % cond)
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure G-4. LSDx1 - SPRUFE8B appendix G.3.  op = 010/011/100/110 defer")
w("# to the per-unit Figures C-20 (.D), D-11 (.L) and F-31 (.S); only the")
w("# unit-independent operations are constructed here.")
w("# ---------------------------------------------------------------------------")
w("")
con('MVK^CUnitLSD^" 0, "^RA97',
    ["j12=1", "j11=1", "j10=0", "j6=1", "j5=1", "j2=1", "j1=1",
     "j15=0", "j14=0", "j13=0", "RA97"], "RA97 = 0;")
con('MVK^CUnitLSD^" 1, "^RA97',
    ["j12=1", "j11=1", "j10=0", "j6=1", "j5=1", "j2=1", "j1=1",
     "j15=0", "j14=0", "j13=1", "RA97"], "RA97 = 1;")
con('ADD^CUnitLSD^" 1, "^RB97',
    ["j12=1", "j11=1", "j10=0", "j6=1", "j5=1", "j2=1", "j1=1",
     "j15=1", "j14=0", "j13=1", "RA97", "RB97"], "RB97 = RA97 + 1;")
con('XOR^CUnitLSD^" 1, "^RB97',
    ["j12=1", "j11=1", "j10=0", "j6=1", "j5=1", "j2=1", "j1=1",
     "j15=1", "j14=1", "j13=1", "RA97", "RB97"], "RB97 = RA97 ^ 1;")
w("")

# ===========================================================================
# Figures H-5..H-9: no unit
# ===========================================================================
w("# ---------------------------------------------------------------------------")
w("# Figures H-5/H-6. Uspl / Uspldr (SPLOOP / SPLOOPD) - appendix H.4.")
w("# Cii displays the actual initiation interval, one more than the field.")
w("# ---------------------------------------------------------------------------")
w("")
con("SPLOOP Cii",
    ["j15=0", "j13=0", "j12=0", "j11=1", "j10=1", "j6=1", "j5=1", "j4=0",
     "j3=0", "j2=1", "j1=1", "j0=0", "Cii"],
    "c6000_sploop(Cii, 0:4); if (ILC == 0) goto <done>; ILC = ILC - 1; <done>")
con("SPLOOPD Cii",
    ["j15=0", "j13=0", "j12=0", "j11=1", "j10=1", "j6=1", "j5=1", "j4=0",
     "j3=0", "j2=1", "j1=1", "j0=1", "Cii"], "c6000_sploopd(Cii, 0:4);")
con('"[A0]"^"SPLOOPD" Cii',
    ["j15=1", "j13=0", "j12=0", "j11=1", "j10=1", "j6=1", "j5=1", "j4=0",
     "j3=0", "j2=1", "j1=1", "j0=0", "Cii"], "c6000_sploopd(Cii, 12:4);")
con('"[B0]"^"SPLOOPD" Cii',
    ["j15=1", "j13=0", "j12=0", "j11=1", "j10=1", "j6=1", "j5=1", "j4=0",
     "j3=0", "j2=1", "j1=1", "j0=1", "Cii"], "c6000_sploopd(Cii, 2:4);")
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure H-7. Uspk (SPKERNEL) - SPRUFE8B appendix H.4.")
w("# ---------------------------------------------------------------------------")
w("")
con("SPKERNEL Cspk",
    ["j13=0", "j12=1", "j11=1", "j10=1", "j6=1", "j5=1", "j4=0",
     "j3=0", "j2=1", "j1=1", "Cspk"], "c6000_spkernel(Cspk);")
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure H-8. Uspm (SPMASK / SPMASKR) - SPRUFE8B appendix H.4.  The")
w("# unitmask bit order is not given by the figure; D2 D1 S2 S1 L2 L1 are")
w("# placed in bits 5..0 in that order.")
w("# ---------------------------------------------------------------------------")
w("")
con("SPMASK Cmask",
    ["j13=1", "j12=0", "j11=1", "j10=1", "j6=1", "j5=1", "j4=0",
     "j3=0", "j2=1", "j1=1", "Cmask"], "c6000_spmask(Cmask);")
con("SPMASKR Cmask",
    ["j13=1", "j12=1", "j11=1", "j10=1", "j6=1", "j5=1", "j4=0",
     "j3=0", "j2=1", "j1=1", "Cmask"], "c6000_spmaskr(Cmask, ILC, RILC);")
w("")

w("# ---------------------------------------------------------------------------")
w("# Figure H-9. Unop (NOP) - SPRUFE8B appendix H.4.  A NOP has no")
w("# architectural effect.")
w("# ---------------------------------------------------------------------------")
w("")
con("NOP CN3",
    ["j12=0", "j11=1", "j10=1", "j9=0", "j8=0", "j7=0", "j6=1", "j5=1",
     "j4=0", "j3=1", "j2=1", "j1=1", "j0=0", "CN3"], "")
w("")

# fix the D-11/C-20/F-31 op constraints: these used j13 etc. above; ok.

text = "\n".join(L) + "\n"
with open(OUT, "w") as f:
    f.write(text)
with open(TOKENOUT, "w") as f:
    f.write(token_text())
    f.write("\n")
    f.write(attach_text())
print("wrote %s (%d lines)" % (OUT, len(L)))
print("wrote %s" % TOKENOUT)
