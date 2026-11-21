#!/usr/bin/env python3
"""Build TI-style switch dispatch images. Usage: IMAGE [be].

Load at 0x1000 with entry 0x1000 and auto-analysis. Each dispatch loads a table
entry and branches to it; a table's bound comes only from an unsigned compare of
the table's index whose result keeps the dispatch from issuing out of range
(SPRUFE8B 3.12 CMPLTU, 3.5, 4.2.6):

  1000  guard by default branch     1200  decoy compare             1400  predicated dispatch
  MVK/MVKH  0x1100,B5               MVK/MVKH  0x1300,B5             MVK/MVKH  0x1500,B5
  CMPLTU.L2 2,B4,B0                 CMPLTU.L2 2,B4,B0               CMPLTU.L2 2,B4,B0
  [B0] B.S1 0x10a0  (default)       CMPLTU.L2 5,B6,B1  (not B4)     [!B0] LDW *+B5[B4],B4
  [!B0] LDW *+B5[B4],B4             [B0] B.S1 0x12a0  (default)     NOP 4
  NOP 4                             [!B0] LDW *+B5[B4],B4           [!B0] B.S2 B4  (dispatch)
  B.S2 B4  (dispatch, at 1018)      NOP 4 ; B.S2 B4 (121c)          NOP 5 ; 1420 default
  cases 1020/1040/1060              cases 1240/1260/1280            cases 1440/1460/1480

In each, the default branch lands, or the predicate fails, before an index past 2
reaches the dispatch, so the table has three cases. 1600 is a known-bad: CMPLTU
2,B4,B0 whose B0 nothing reads, so no bound is proven and no table is read. Each
table continues with valid code addresses past the bound, and 1300 to five, the
decoy's bound. The CMPLTU and LDW words are firmware encodings with operands
changed.

Compilers also build the entry address with SHL and ADD, and bias the index of a
switch whose cases don't start at zero: they compare a biased copy and fold the bias
into the address (SPRUFE8B 3.12 ADD, SHL, LDW, CMPLTU):

  1800  biased index                1a00  address by SHL            1c00  biased decoy
  MVK/MVKH  0x1900,B5               MVK/MVKH  0x1b00,B5             as 1800, but
  ADD.L2 -3,B4,B6                   CMPLTU.L2 2,B4,B0               ADD.L2 -3,B9,B6:
  CMPLTU.L2 2,B6,B0                 [B0] B.S1 0x1aa0                the compared copy
  [B0] B.S1 0x18a0                  SHL.S2 B4,2,B7                  is not of the index
  SHL.S2 B4,2,B7                    ADD.L2 B5,B7,B7                 (no table)
  ADD.L2 -12,B7,B7                  [!B0] LDW *+B7(0),B4
  ADD.L2 B7,B5,B7                   NOP 4 ; B.S2 B4 (1a20)          1e00  as 1800, but
  [!B0] LDW *+B7(0),B4              cases 1a40/1a60/1a80            ADD.L2 -8,B7,B7: the
  NOP 4 ; B.S2 B4 (1828)                                            entry read is one past
  cases 1840/1860/1880                                              the compared value, so
                                                                    cases 1e60/1e80/1ec0
2000 shifts the index in place in the packet that takes the biased copy (SHL B4,2,B4 ||
ADD -3,B4,B6: the copy reads the old B4) and folds the bias with ADDK -12,B4; 2200 holds
the bias in a register (MVK 3,B8; SUB B4,B8,B6). Both have cases at their table's first
three entries. The ADD, ADDK, SUB, SHL, MVK and LDW words were assembled with cl6x 8.5.0
and checked with GNU objdump.
"""

from pathlib import Path
import struct
import sys


def mvk(cst, reg):
    return 0x2A | ((cst & 0xFFFF) << 7) | (reg << 23)


def mvkh(cst, reg):
    return 0x6A | ((cst & 0xFFFF) << 7) | (reg << 23)


def nop(count):
    return (count - 1) << 13


def b_s1(at, target):
    """B.S1 to target, relative to the fetch packet holding at."""
    return 0x10 | ((((target - (at & ~31)) >> 2) & 0x1FFFFF) << 7)


def cmpltu(cst, src, dst):
    """CMPLTU.L2 cst,src,dst: dst = cst < src."""
    return (0x0014EBDA & ~(0x1F << 13) & ~(0x1F << 18) & ~(0x1F << 23)) | (cst << 13) | (src << 18) | (dst << 23)


B_B3 = 0x362 | (3 << 18)
B_B4 = 0x362 | (4 << 18)
LDW = 0x02148AE6                            # LDW.D2T2 *+B5[B4],B4
B0, NOT_B0 = 0x20000000, 0x30000000

WORDS = {}


def routine(at):
    WORDS[at] = B_B3
    WORDS[at + 4] = nop(5)


def table(at, entries):
    for i, target in enumerate(entries):
        WORDS[at + 4 * i] = target


# Guarded by a default branch that lands before the dispatch would issue.
WORDS.update({
    0x1000: mvk(0x1100, 5), 0x1004: mvkh(0, 5), 0x1008: cmpltu(2, 4, 0),
    0x100C: B0 | b_s1(0x100C, 0x10A0), 0x1010: NOT_B0 | LDW, 0x1014: nop(4),
    0x1018: B_B4, 0x101C: nop(5),
})
for case in (0x1020, 0x1040, 0x1060, 0x1080, 0x10A0):
    routine(case)
table(0x1100, (0x1020, 0x1040, 0x1060, 0x1080))

# The same with a later compare of another register: its bound is not the table's.
WORDS.update({
    0x1200: mvk(0x1300, 5), 0x1204: mvkh(0, 5), 0x1208: cmpltu(2, 4, 0), 0x120C: cmpltu(5, 6, 1),
    0x1210: B0 | b_s1(0x1210, 0x12A0), 0x1214: NOT_B0 | LDW, 0x1218: nop(4),
    0x121C: B_B4, 0x1220: nop(5),
})
for case in (0x1240, 0x1260, 0x1280, 0x12A0, 0x12C0, 0x12E0):
    routine(case)
table(0x1300, (0x1240, 0x1260, 0x1280, 0x12C0, 0x12E0, 0x12C0))

# Guarded by the dispatch's own predicate; out of range falls through to 1420.
WORDS.update({
    0x1400: mvk(0x1500, 5), 0x1404: mvkh(0, 5), 0x1408: cmpltu(2, 4, 0),
    0x140C: NOT_B0 | LDW, 0x1410: nop(4), 0x1414: NOT_B0 | B_B4, 0x1418: nop(5),
})
for case in (0x1420, 0x1440, 0x1460, 0x1480, 0x14C0):
    routine(case)
table(0x1500, (0x1440, 0x1460, 0x1480, 0x14C0))

# Known-bad: the compare's result guards nothing.
WORDS.update({
    0x1600: mvk(0x1700, 5), 0x1604: mvkh(0, 5), 0x1608: cmpltu(2, 4, 0),
    0x160C: LDW, 0x1610: nop(4), 0x1614: B_B4, 0x1618: nop(5),
})
for case in (0x1620, 0x1640, 0x1660, 0x1680):
    routine(case)
table(0x1700, (0x1620, 0x1640, 0x1660, 0x1680))


ADD_M3_B4_B6, ADD_M3_B9_B6 = 0x0313A05A, 0x0327A05A     # ADD.L2 -3,B4,B6 / -3,B9,B6
SHL_B4_2_B7 = 0x03904CA2                                # SHL.S2 B4,2,B7
ADD_M12_B7, ADD_M8_B7 = 0x039E805A, 0x039F005A          # ADD.L2 -12,B7,B7 / -8,B7,B7
ADD_B7_B5_B7, ADD_B5_B7_B7 = 0x0394E07A, 0x039CA07A     # ADD.L2 B7,B5,B7 / B5,B7,B7
LDW_B7 = 0x021C02E6                                     # LDW.D2T2 *+B7(0),B4


def biased(at, copy, fold, entries):
    """A dispatch comparing a biased copy, its bias folded into the table address."""
    WORDS.update({
        at: mvk(at + 0x100, 5), at + 4: mvkh(0, 5), at + 8: copy, at + 0xC: cmpltu(2, 6, 0),
        at + 0x10: B0 | b_s1(at + 0x10, at + 0xA0), at + 0x14: SHL_B4_2_B7, at + 0x18: fold,
        at + 0x1C: ADD_B7_B5_B7, at + 0x20: NOT_B0 | LDW_B7, at + 0x24: nop(4),
        at + 0x28: B_B4, at + 0x2C: nop(5),
    })
    for case in (0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0):
        routine(at + case)
    table(at + 0x100, [at + e for e in entries])


biased(0x1800, ADD_M3_B4_B6, ADD_M12_B7, (0x40, 0x60, 0x80, 0xC0))
biased(0x1C00, ADD_M3_B9_B6, ADD_M12_B7, (0x40, 0x60, 0x80, 0xC0))
biased(0x1E00, ADD_M3_B4_B6, ADD_M8_B7, (0x40, 0x60, 0x80, 0xC0, 0xE0))

SHL_B4_2_B4_PAR, ADDK_M12_B4 = 0x02104CA3, 0x027FFA52     # SHL.S2 B4,2,B4 || ; ADDK.S2 -12,B4
ADD_B4_B5_B7, MVK_3_B8, SUB_B4_B8_B6 = 0x0394807A, 0x040001AA, 0x032080FA

# The index shifted in place beside its biased copy, the bias folded by ADDK.
WORDS.update({
    0x2000: mvk(0x2100, 5), 0x2004: mvkh(0, 5), 0x2008: SHL_B4_2_B4_PAR, 0x200C: ADD_M3_B4_B6,
    0x2010: cmpltu(2, 6, 0), 0x2014: B0 | b_s1(0x2014, 0x20A0), 0x2018: ADDK_M12_B4,
    0x201C: ADD_B4_B5_B7, 0x2020: NOT_B0 | LDW_B7, 0x2024: nop(4), 0x2028: B_B4, 0x202C: nop(5),
})
for case in (0x2040, 0x2060, 0x2080, 0x20A0, 0x20C0):
    routine(case)
table(0x2100, (0x2040, 0x2060, 0x2080, 0x20C0))

# The bias held in a register.
WORDS.update({
    0x2200: mvk(0x2300, 5), 0x2204: mvkh(0, 5), 0x2208: MVK_3_B8, 0x220C: SUB_B4_B8_B6,
    0x2210: cmpltu(2, 6, 0), 0x2214: B0 | b_s1(0x2214, 0x22A0), 0x2218: SHL_B4_2_B7,
    0x221C: ADD_M12_B7, 0x2220: ADD_B7_B5_B7, 0x2224: NOT_B0 | LDW_B7, 0x2228: nop(4),
    0x222C: B_B4, 0x2230: nop(5),
})
for case in (0x2240, 0x2260, 0x2280, 0x22A0, 0x22C0):
    routine(case)
table(0x2300, (0x2240, 0x2260, 0x2280, 0x22C0))

# The entry address built by SHL and ADD from the compared index itself.
WORDS.update({
    0x1A00: mvk(0x1B00, 5), 0x1A04: mvkh(0, 5), 0x1A08: cmpltu(2, 4, 0),
    0x1A0C: B0 | b_s1(0x1A0C, 0x1AA0), 0x1A10: SHL_B4_2_B7, 0x1A14: ADD_B5_B7_B7,
    0x1A18: NOT_B0 | LDW_B7, 0x1A1C: nop(4), 0x1A20: B_B4, 0x1A24: nop(5),
})
for case in (0x1A40, 0x1A60, 0x1A80, 0x1AA0, 0x1AC0):
    routine(case)
table(0x1B00, (0x1A40, 0x1A60, 0x1A80, 0x1AC0))


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x1320)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
