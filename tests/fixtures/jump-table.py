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


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x720)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
