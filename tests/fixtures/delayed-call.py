#!/usr/bin/env python3
"""Build a B-with-B3 call image. Usage: IMAGE [be].

Load at 0x1000 with entry 0x1000 and auto-analysis. Words are encoded from
SPRUFE8B's MVK/MVKH, B, BNOP, ADDKPC and NOP opcode diagrams:

  1000  MVK.S2  0x1100,B5        1018  B.S1    0x1100        (call)
  1004  MVKH.S2 0x0,B5           101c  ADDKPC.S2 0x1020,B3,4
  1008  B.S2    B5      (call)   1020  B.S2    B3            (return)
  100c  MVK.S2  0x1018,B3        1024  NOP     5
  1010  MVKH.S2 0x0,B3           ...
  1014  NOP     3                1100  B.S2 B3 ; NOP 5       (callee)

An if/else call pair, B3 set before the first arm:

  1040  MVK.S2  0x1054,B3        104c  [A1]B.S1  0x1100      (call)
  1044  MVKH.S2 0x0,B3           1050  NOP     5
  1048  [!A1]B.S1 0x1100 (call)  1054  B.S2 B3 ; NOP 5

A call-or-jump pair: call 0x1100 if A1, else jump to the local block 0x1080.
Only the far arm is a call:

  1060  MVK.S2  0x1074,B3        106c  [A1]B.S1  0x1100      (call)
  1064  MVKH.S2 0x0,B3           1070  NOP     5
  1068  [!A1]B.S1 0x1080 (jump)  1074  B.S2 B3 ; ...  1080  B.S2 B3

B3 set in a jump's delay slots is the next call's (10b8); 10a0 stays a jump:

  10a0  [A1]B.S1  0x10e0 (jump)  10b0  MVKH.S2 0x0,B5
  10a4  MVK.S2  0x10c0,B3        10b4  NOP
  10a8  MVK.S2  0x1100,B5        10b8  B.S2    B5      (call)
  10ac  MVKH.S2 0x0,B3           10bc  NOP     5       10c0, 10e0  B.S2 B3

B3 set before a conditional jump survives its fall-through to the call at 1150:

  1140  MVK.S2  0x1158,B3        1150  B.S1    0x11c0  (call)
  1144  MVKH.S2 0x0,B3           1154  NOP     5
  1148  [A1]B.S1  0x1180 (jump)  1158, 1180, 11c0  B.S2 B3
  114c  NOP     5

A predicated B inside another's delay slots (120c) stays a jump:

  1200  MVK.S2  0x1214,B3        120c  [!A1]B.S1 0x1240 (jump)
  1204  MVKH.S2 0x0,B3           1210  NOP     4
  1208  [B0]B.S1  0x1260         1214, 1240, 1260  B.S2 B3

A B whose window ends 4 bytes short of B3 (1290) stays a jump:

  1280  MVK.S2  0x12a0,B3        1294  NOP     4
  1284  MVKH.S2 0x0,B3           1298  NOP           (window ends 129c)
  1288  [A1]B.S1  0x12c0 (jump)  129c  NOP
  128c  NOP     5                12a0, 12c0, 12e0  B.S2 B3
  1290  B.S1    0x12e0 (jump)

A call nothing falls into (1308) takes B3 from the one jump reaching it:

  1300  B.S1    0x1340 (jump)    1340  MVK.S2  0x1310,B3
  1304  NOP     5                1344  MVKH.S2 0x0,B3
  1308  B.S1    0x1100  (call)   1348  [A1]B.S1  0x1308 (jump)
  130c  NOP     5                134c  NOP     5
  1310  B.S2 B3 ; NOP 5          1350  B.S2 B3 ; NOP 5

The same through an unconditional jump:

  1380  B.S1    0x13c0 (jump)    13c0  MVK.S2  0x1390,B3
  1388  B.S1    0x1100  (call)   13c4  MVKH.S2 0x0,B3
  1390  B.S2 B3                  13c8  B.S1    0x1388 (jump)

B3 set in the reaching jump's delay slots:

  1400  B.S1    0x1440 (jump)    1440  B.S1    0x1408 (jump)
  1408  B.S1    0x1100  (call)   1444  MVK.S2  0x1410,B3
  1410  B.S2 B3                  1448  MVKH.S2 0x0,B3 ; 144c  NOP 3

An if/else pair whose jump arm (1924) issues 3 cycles but 28 bytes after its call arm
(1908), past two wide packets; and one (19a8/19ac) whose call target, the helper function
at 19c0, is nearer than the jump arm's target, the caller's loop head at 1984:

  1900  MVK/MVKH 0x192c,B3       1924  [!A1]B.S1 0x1940 (jump) 192c  B.S2 B3
  1908  [A1]B.S1 0x1100 (call) || three MVKs; 1918 two MVKs; 1920 MVK; 1928 NOP 5
  19a0  MVK/MVKH 0x19b4,B3       19ac  [!A1]B.S1 0x1984 (jump)
  19a8  [A1]B.S1 0x19c0 (call)   19b0  NOP 5 ; 19b4 B.S2 B3 ; 19c0 B.S2 B3

A call whose B3 is finished by ADDK in its window returns past the window (1a08):

  1a00  MVK/MVKH 0x1a10,B3       1a0c  ADDK.S2 4,B3   1a14  B.S2 B3
  1a08  B.S1    0x1100  (call)   1a10  NOP 4

A B whose B3 points into its own window is not a call (1a48); its slots would run twice:

  1a40  MVK/MVKH 0x1a54,B3       1a4c  NOP ; NOP      1a54  MVK 1,A9 ; MVK 2,A9 ; NOP
  1a48  B.S1    0x1100  (jump)                        1a60  B.S2 B3

A predicated reaching jump; the write under the opposite predicate does not count:

  1480  B.S1    0x14c0 (jump)    14c0  [A1]B.S1  0x1488 (jump)
  1488  B.S1    0x1100  (call)   14c4  [A1]MVK.S2  0x1490,B3
  1490  B.S2 B3                  14c8  [!A1]MVK.S2 0x1500,B3
                                 14cc  NOP 3 ; 14d0  B.S2 B3

Not calls: 1508 is also fallen into:

  1500  [A2]B.S1  0x1540 (jump)  1540  MVK.S2  0x1510,B3
  1508  B.S1    0x1100           1544  MVKH.S2 0x0,B3
  1510  B.S2 B3                  1548  [A1]B.S1  0x1508 (jump)

158c is fallen into from 1588:

  1580  B.S1    0x15c0 (jump)    15c0  [A2]B.S1  0x1588 (jump)
  1588  MVK.S2  0x5,B4           15c8  MVK.S2  0x1594,B3
  158c  B.S1    0x1100           15cc  MVKH.S2 0x0,B3
  1594  B.S2 B3                  15d0  [A1]B.S1  0x158c (jump)

Two jumps reach 1608:

  1600  B.S1    0x1640 (jump)    1644  [A1]B.S1  0x1608 (jump)
  1608  B.S1    0x1100           164c  MVK.S2  0x1610,B3
  1610  B.S2 B3                  1650  MVKH.S2 0x0,B3
  1640  MVK.S2  0x1700,B3        1654  [A2]B.S1  0x1608 (jump)

1698 is the return point of the call at 1690:

  1680  [A2]B.S1  0x16c0 (jump)  1698  B.S1    0x1100
  1688  MVK.S2  0x1698,B3        16a0  B.S2 B3
  168c  MVKH.S2 0x0,B3           16c0  MVK.S2  0x16a0,B3 ; MVKH.S2 0x0,B3
  1690  B.S1    0x1100  (call)   16c8  [A1]B.S1  0x1698 (jump)

A BNOP reaches 1708:

  1700  B.S1    0x1740 (jump)    1740  BNOP.S1 0x1708,5 (jump)
  1708  B.S1    0x1100           1744  MVK.S2  0x1710,B3
  1710  B.S2 B3                  1748  MVKH.S2 0x0,B3 ; 174c  NOP 3

A slot under a fallen-through jump's own predicate does not run: 1798 is a call;
with that write unpredicated, 1818 is not:

  1780  [!A1]B.S1 0x17c0 (jump)  1798  B.S2 B4  (call)
  1784  MVK.S2  0x1100,B4        179c  NOP 5
  1788  MVK.S2  0x17a0,B3        17a0  B.S2 B3 ; NOP 5
  178c  MVKH.S2 0x0,B4           17c0  B.S2 B3 ; NOP 5
  1790  MVKH.S2 0x0,B3
  1794  [!A1]MV.S2 B13,B3

A window ending at a compact header returns past it: 1888 is a call (B3 = window end + 4):

  1880  MVK.S2  0x1100,B5        1890  NOP ; 1894  NOP ; 1898  NOP
  1884  MVKH.S2 0x0,B5           189c  header, all words 32-bit
  1888  B.S2    B5      (call)   18a0  B.S2 B3 ; NOP 5
  188c  ADDKPC.S2 0x18a0,B3,1

Both arms of an if/else call pair return at the later arm's window end, 4
bytes past the earlier arm's (1c00, 1c08 calls):

  1c00  [A1]B.S1  0x1100 (call)  1c10  NOP
  1c04  NOP                      1c14  ADDKPC.S2 0x1c1c,B3,1
  1c08  [!A1]B.S1 0x1100 (call)  1c18  NOP
  1c0c  NOP                      1c1c  B.S2 B3 ; NOP 5

Register arms in a same-predicate BNOP's window (1c4c, 1c58 calls). The BNOP lands
in 1c4c's slot 4, so 1c4c's slots 4-5 run at 0x1c80, which sets its B3 (1c88):

  1c40  MVK.S2  0x1100,B4        1c5c  MVK.S2  0x1c68,B3
  1c44  MVKH.S2 0x0,B4           1c60  MVKH.S2 0x0,B3
  1c48  [!A1]BNOP.S1 0x1c80,1    1c64  NOP     3
  1c4c  [!A1]B.S2 B4  (call)     1c68  B.S2 B3 ; NOP 5
  1c50  NOP ; 1c54  NOP          1c80  MVK.S2  0x1c88,B3 ; 1c84  MVKH.S2 0x0,B3
  1c58  [A1]B.S2  B4   (call)    1c88  B.S2 B3 ; NOP 5

The compiler's predicate-nullify idiom: A1 copies the call's predicate A0, a write under
the copy keeps A0's truth, and a branch under A0's opposite is never taken on the call
path (1d08, 1d88 calls; returns 1d1c, 1d9c):

  1d00  [!A0]B.S1 0x1d40 || MV.L1 A0,A1     1d80  [A0]B.S1 0x1dc0 || MV.L1 A0,A1
  1d08  [A0]B.S1  0x1100 (call)             1d88  [!A0]B.S1 0x1100 (call)
        || [!A0]CMPGT.L1 A10,10,A0                || [A0]SUB.L1 A10,1,A0
  1d10  [A1]MVK.L1 1,A0                     1d90  [!A1]ZERO.L1 A0
  1d14  [!A0]BNOP.S1 0x1d60,2               1d94  [A0]BNOP.S1 0x1de0,2
  1d18  ADDKPC.S2 0x1d1c,B3,0               1d98  ADDKPC.S2 0x1d9c,B3,0

A nullified jump one packet after a call returns at that call's B3, not its own (1e14 jump):

  1e00  MV.L1 A0,A1 || [A0]B.S1 0x1e40      1e14  [A0]B.S1  0x1e60 (jump)
  1e08  [!A0]B.S1 0x1100 || [A0]ZERO.L1 A0  1e18  NOP ; 1e1c  NOP
  1e10  [!A1]ZERO.L1 A0                     1e20  ADDKPC.S2 0x1e24,B3,0

1f08 is 1d08 with the write under A2: A0 becomes 1 or stays nonzero, so it is a call too.
Controls that are not calls: 1e88 is 1d08 with [A1]ZERO.L1 A0 and 1f88 with [A2]ZERO.L1 A0;
either write can clear A0, so the BNOP may run on the call path.
2008 is 1d88 with ZERO in its SUB A0,A0,A0 form, a call; the control 2088 writes
SUB A0,A2,A0, which can set A0 on the call path, so it is not a call.
210c is not a call either: MVK 1,A0 makes A0 true whatever it held, so B3, set under A0
before it, is not known on the call path:

  2100  [A0]MVK.S2  0x2114,B3          210c  [A0]B.S1 0x1100 (not a call)
  2104  [A0]MVKH.S2 0x0,B3             2110  NOP 5
  2108  MVK.L1 1,A0                    2114  B.S2 B3 ; NOP 5
Every return point and jump target in these routines is B.S2 B3 ; NOP 5.

C6000DelayedCallTest.java checks every B form becomes a call that falls
through into its delay slots and that 0x1100 becomes a function.
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


B_B3 = 0x362 | (3 << 18)
A1, NOT_A1, A2 = 0x80000000, 0x90000000, 0xA0000000
A0, NOT_A0, PAR = 0xC0000000, 0xD0000000, 1
MV_A0_A1 = 0x00800FD8  # MV.L1 A0,A1
CMPGT_A10_10_A0 = 0x00294AD8  # CMPGT.L1 A10,10,A0
SUB_A10_1_A0 = 0x002BE058  # SUB.L1 A10,1,A0
SUB_A0_A0_A0 = 0x000000F8  # SUB.L1 A0,A0,A0 (dis6x: ZERO.L1 A0)
SUB_A0_A2_A0 = 0x000800F8  # SUB.L1 A0,A2,A0


def mvk_l1(cst, reg):
    """MVK.L1 cst,reg (5-bit constant); cst 0 is ZERO.L1 reg."""
    return 0xA358 | ((cst & 0x1F) << 18) | (reg << 23)


def addkpc(at, ret, count):
    """ADDKPC.S2 ret,B3,count, relative to the fetch packet holding at."""
    return 0x162 | (((ret - (at & ~31)) >> 2) << 16) | (count << 13) | (3 << 23)


def b_s1(at, target):
    """B.S1 to target, relative to the fetch packet holding at."""
    return 0x10 | ((((target - (at & ~31)) >> 2) & 0x1FFFFF) << 7)


def bnop_s1(at, target, count):
    return 0x120 | (count << 13) | ((((target - (at & ~31)) >> 2) & 0xFFF) << 16)


CALLEE = 0x1100
B_B4 = 0x362 | (4 << 18)
MV_B13_B3 = 0x01B401A2  # MV.S2 B13,B3


def nullify(base, guard):
    """[A0] call with A1 = A0; guard is the word written after the call packet."""
    return {
        base: NOT_A0 | b_s1(base, base + 0x40) | PAR, base + 0x4: MV_A0_A1,
        base + 0x8: A0 | b_s1(base + 0x8, CALLEE) | PAR, base + 0xC: NOT_A0 | CMPGT_A10_10_A0,
        base + 0x10: guard, base + 0x14: NOT_A0 | bnop_s1(base + 0x14, base + 0x60, 2),
        base + 0x18: addkpc(base + 0x18, base + 0x1C, 0), base + 0x1C: B_B3, base + 0x20: nop(5),
        base + 0x40: B_B3, base + 0x44: nop(5), base + 0x60: B_B3, base + 0x64: nop(5),
    }


def nullify_zero(base, guard):
    """[!A0] call with A1 = A0; guard is the word written after the call packet."""
    return {
        base: A0 | b_s1(base, base + 0x40) | PAR, base + 0x4: MV_A0_A1,
        base + 0x8: NOT_A0 | b_s1(base + 0x8, CALLEE) | PAR, base + 0xC: A0 | SUB_A10_1_A0,
        base + 0x10: guard, base + 0x14: A0 | bnop_s1(base + 0x14, base + 0x60, 2),
        base + 0x18: addkpc(base + 0x18, base + 0x1C, 0), base + 0x1C: B_B3, base + 0x20: nop(5),
        base + 0x40: B_B3, base + 0x44: nop(5), base + 0x60: B_B3, base + 0x64: nop(5),
    }


def taken_only(base, predicate):
    """[!A1] jump setting B4 and B3 in its slots, then MV B13,B3 under predicate."""
    return {
        base: NOT_A1 | b_s1(base, base + 0x40), base + 0x4: mvk(CALLEE, 4),
        base + 0x8: mvk(base + 0x20, 3), base + 0xC: mvkh(0, 4), base + 0x10: mvkh(0, 3),
        base + 0x14: predicate | MV_B13_B3, base + 0x18: B_B4, base + 0x1C: nop(5),
        base + 0x20: B_B3, base + 0x24: nop(5), base + 0x40: B_B3, base + 0x44: nop(5),
    }


# Issue cycles, not bytes, decide an if/else pair: the jump arm at 1924 issues three
# cycles after the call arm at 1908 but 28 bytes later, past two wide packets.
PARTNER_FAR = {
    0x1900: mvk(0x192C, 3), 0x1904: mvkh(0, 3),
    0x1908: A1 | b_s1(0x1908, CALLEE) | PAR, 0x190C: mvk(0x11, 5) | PAR,
    0x1910: mvk_l1(3, 7) | PAR, 0x1914: mvk_l1(4, 7) | 2,
    0x1918: (mvk(0x22, 5) & ~2) | PAR, 0x191C: mvk(0x33, 6),
    0x1920: mvk_l1(5, 8),
    0x1924: NOT_A1 | b_s1(0x1924, 0x1940), 0x1928: nop(5),
    0x192C: B_B3, 0x1930: nop(5), 0x1940: B_B3, 0x1944: nop(5),
}

# Where the targets lie decides which arm is the call: the helper at 19c0, a function of
# its own, sits closer to the pair than the caller's loop head at 1984.
NEAR_HELPER = {
    0x1980: mvk_l1(1, 9), **{0x1984 + 4 * k: mvk_l1(2 + k, 9) for k in range(7)},
    0x19A0: mvk(0x19B4, 3), 0x19A4: mvkh(0, 3),
    0x19A8: A1 | b_s1(0x19A8, 0x19C0), 0x19AC: NOT_A1 | b_s1(0x19AC, 0x1984), 0x19B0: nop(5),
    0x19B4: B_B3, 0x19B8: nop(5), 0x19C0: B_B3, 0x19C4: nop(5),
}

# B3 finished by arithmetic in the call's window: MVK/MVKH 0x1a10, then ADDK 4,B3 (ADDK.S2,
# SPRUFE8B 3.12 ADDK). Constants come from each instruction's p-code, not a list of mnemonics.
ADDK_RETURN = {
    0x1A00: mvk(0x1A10, 3), 0x1A04: mvkh(0, 3), 0x1A08: b_s1(0x1A08, CALLEE),
    0x1A0C: 0x01800252, 0x1A10: nop(4), 0x1A14: B_B3, 0x1A18: nop(5),
}

# Known-bad: B3 points into the B's own window (1a54 issues in its third delay cycle), so a
# return there would run 1a54-1a5c a second time. A tail call's epilogue looks like this.
INSIDE_WINDOW = {
    0x1A40: mvk(0x1A54, 3), 0x1A44: mvkh(0, 3), 0x1A48: b_s1(0x1A48, CALLEE),
    0x1A4C: nop(1), 0x1A50: nop(1), 0x1A54: mvk_l1(1, 9), 0x1A58: mvk_l1(2, 9), 0x1A5C: nop(1),
    0x1A60: B_B3, 0x1A64: nop(5),
}

CASES = {
    **PARTNER_FAR, **NEAR_HELPER, **ADDK_RETURN, **INSIDE_WINDOW,
    0x1300: b_s1(0x1300, 0x1340), 0x1304: nop(5),
    0x1308: b_s1(0x1308, CALLEE), 0x130C: nop(5), 0x1310: B_B3, 0x1314: nop(5),
    0x1340: mvk(0x1310, 3), 0x1344: mvkh(0, 3),
    0x1348: A1 | b_s1(0x1348, 0x1308), 0x134C: nop(5), 0x1350: B_B3, 0x1354: nop(5),

    0x1380: b_s1(0x1380, 0x13C0), 0x1384: nop(5),
    0x1388: b_s1(0x1388, CALLEE), 0x138C: nop(5), 0x1390: B_B3, 0x1394: nop(5),
    0x13C0: mvk(0x1390, 3), 0x13C4: mvkh(0, 3),
    0x13C8: b_s1(0x13C8, 0x1388), 0x13CC: nop(5),

    0x1400: b_s1(0x1400, 0x1440), 0x1404: nop(5),
    0x1408: b_s1(0x1408, CALLEE), 0x140C: nop(5), 0x1410: B_B3, 0x1414: nop(5),
    0x1440: b_s1(0x1440, 0x1408), 0x1444: mvk(0x1410, 3), 0x1448: mvkh(0, 3), 0x144C: nop(3),

    0x1480: b_s1(0x1480, 0x14C0), 0x1484: nop(5),
    0x1488: b_s1(0x1488, CALLEE), 0x148C: nop(5), 0x1490: B_B3, 0x1494: nop(5),
    0x14C0: A1 | b_s1(0x14C0, 0x1488), 0x14C4: A1 | mvk(0x1490, 3),
    0x14C8: NOT_A1 | mvk(0x1500, 3), 0x14CC: nop(3), 0x14D0: B_B3, 0x14D4: nop(5),

    0x1500: A2 | b_s1(0x1500, 0x1540), 0x1504: nop(5),
    0x1508: b_s1(0x1508, CALLEE), 0x150C: nop(5), 0x1510: B_B3, 0x1514: nop(5),
    0x1540: mvk(0x1510, 3), 0x1544: mvkh(0, 3),
    0x1548: A1 | b_s1(0x1548, 0x1508), 0x154C: nop(5), 0x1550: B_B3, 0x1554: nop(5),

    0x1580: b_s1(0x1580, 0x15C0), 0x1584: nop(5), 0x1588: mvk(5, 4),
    0x158C: b_s1(0x158C, CALLEE), 0x1590: nop(5), 0x1594: B_B3, 0x1598: nop(5),
    0x15C0: A2 | b_s1(0x15C0, 0x1588), 0x15C4: nop(5),
    0x15C8: mvk(0x1594, 3), 0x15CC: mvkh(0, 3),
    0x15D0: A1 | b_s1(0x15D0, 0x158C), 0x15D4: nop(5), 0x15D8: B_B3, 0x15DC: nop(5),

    0x1600: b_s1(0x1600, 0x1640), 0x1604: nop(5),
    0x1608: b_s1(0x1608, CALLEE), 0x160C: nop(5), 0x1610: B_B3, 0x1614: nop(5),
    0x1640: mvk(0x1700, 3), 0x1644: A1 | b_s1(0x1644, 0x1608), 0x1648: nop(5),
    0x164C: mvk(0x1610, 3), 0x1650: mvkh(0, 3),
    0x1654: A2 | b_s1(0x1654, 0x1608), 0x1658: nop(5), 0x165C: B_B3, 0x1660: nop(5),

    0x1680: A2 | b_s1(0x1680, 0x16C0), 0x1684: nop(5),
    0x1688: mvk(0x1698, 3), 0x168C: mvkh(0, 3),
    0x1690: b_s1(0x1690, CALLEE), 0x1694: nop(5),
    0x1698: b_s1(0x1698, CALLEE), 0x169C: nop(5), 0x16A0: B_B3, 0x16A4: nop(5),
    0x16C0: mvk(0x16A0, 3), 0x16C4: mvkh(0, 3),
    0x16C8: A1 | b_s1(0x16C8, 0x1698), 0x16CC: nop(5), 0x16D0: B_B3, 0x16D4: nop(5),

    0x1700: b_s1(0x1700, 0x1740), 0x1704: nop(5),
    0x1708: b_s1(0x1708, CALLEE), 0x170C: nop(5), 0x1710: B_B3, 0x1714: nop(5),
    0x1740: bnop_s1(0x1740, 0x1708, 5), 0x1744: mvk(0x1710, 3), 0x1748: mvkh(0, 3), 0x174C: nop(3),
    **taken_only(0x1780, NOT_A1), **taken_only(0x1800, 0),

    0x1880: mvk(CALLEE, 5), 0x1884: mvkh(0, 5), 0x1888: 0x362 | (5 << 18),
    0x188C: 0x162 | (8 << 16) | (1 << 13) | (3 << 23), 0x1890: nop(1), 0x1894: nop(1), 0x1898: nop(1),
    0x189C: 0xE0000000, 0x18A0: B_B3, 0x18A4: nop(5),  # header: layout and p-bits zero

    0x1C00: A1 | b_s1(0x1C00, CALLEE), 0x1C04: nop(1), 0x1C08: NOT_A1 | b_s1(0x1C08, CALLEE),
    0x1C0C: nop(1), 0x1C10: nop(1), 0x1C14: 0x162 | (7 << 16) | (1 << 13) | (3 << 23),  # ADDKPC.S2 0x1c1c,B3,1
    0x1C18: nop(1), 0x1C1C: B_B3, 0x1C20: nop(5),

    0x1C40: mvk(CALLEE, 4), 0x1C44: mvkh(0, 4), 0x1C48: NOT_A1 | bnop_s1(0x1C48, 0x1C80, 1),
    0x1C4C: NOT_A1 | B_B4, 0x1C50: nop(1), 0x1C54: nop(1), 0x1C58: A1 | B_B4,
    0x1C5C: mvk(0x1C68, 3), 0x1C60: mvkh(0, 3), 0x1C64: nop(3), 0x1C68: B_B3, 0x1C6C: nop(5),
    0x1C80: mvk(0x1C88, 3), 0x1C84: mvkh(0, 3), 0x1C88: B_B3, 0x1C8C: nop(5),

    **nullify(0x1D00, A1 | mvk_l1(1, 0)),
    0x1D80: A0 | b_s1(0x1D80, 0x1DC0) | PAR, 0x1D84: MV_A0_A1,
    0x1D88: NOT_A0 | b_s1(0x1D88, CALLEE) | PAR, 0x1D8C: A0 | SUB_A10_1_A0,
    0x1D90: NOT_A1 | mvk_l1(0, 0), 0x1D94: A0 | bnop_s1(0x1D94, 0x1DE0, 2),
    0x1D98: addkpc(0x1D98, 0x1D9C, 0), 0x1D9C: B_B3, 0x1DA0: nop(5),
    0x1DC0: B_B3, 0x1DC4: nop(5), 0x1DE0: B_B3, 0x1DE4: nop(5),

    0x1E00: MV_A0_A1 | PAR, 0x1E04: A0 | b_s1(0x1E04, 0x1E40),
    0x1E08: NOT_A0 | b_s1(0x1E08, CALLEE) | PAR, 0x1E0C: A0 | mvk_l1(0, 0),
    0x1E10: NOT_A1 | mvk_l1(0, 0), 0x1E14: A0 | b_s1(0x1E14, 0x1E60), 0x1E18: nop(1), 0x1E1C: nop(1),
    0x1E20: addkpc(0x1E20, 0x1E24, 0), 0x1E24: B_B3, 0x1E28: nop(5),
    0x1E40: B_B3, 0x1E44: nop(5), 0x1E60: B_B3, 0x1E64: nop(5),

    **nullify(0x1E80, A1 | mvk_l1(0, 0)),
    **nullify(0x1F00, A2 | mvk_l1(1, 0)),
    **nullify(0x1F80, A2 | mvk_l1(0, 0)),
    **nullify_zero(0x2000, NOT_A1 | SUB_A0_A0_A0),
    **nullify_zero(0x2080, NOT_A1 | SUB_A0_A2_A0),
    0x2100: A0 | mvk(0x2114, 3), 0x2104: A0 | mvkh(0, 3), 0x2108: mvk_l1(1, 0),
    0x210C: A0 | b_s1(0x210C, CALLEE), 0x2110: nop(5), 0x2114: B_B3, 0x2118: nop(5),
}

WORDS = {
    0x1000: mvk(0x1100, 5),
    0x1004: mvkh(0, 5),
    0x1008: 0x362 | (5 << 18),              # B.S2 B5
    0x100C: mvk(0x1018, 3),
    0x1010: mvkh(0, 3),
    0x1014: nop(3),
    0x1018: 0x10 | (0x40 << 7),             # B.S1 packet+0x100
    0x101C: 0x162 | (8 << 16) | (4 << 13) | (3 << 23),  # ADDKPC.S2 0x1020,B3,4
    0x1020: B_B3,
    0x1024: nop(5),
    0x1040: mvk(0x1054, 3),
    0x1044: mvkh(0, 3),
    0x1048: 0x90000010 | (0x30 << 7),       # [!A1] B.S1 packet+0xc0
    0x104C: 0x80000010 | (0x30 << 7),       # [A1] B.S1 packet+0xc0
    0x1050: nop(5),
    0x1054: B_B3,
    0x1058: nop(5),
    0x1060: mvk(0x1074, 3),
    0x1064: mvkh(0, 3),
    0x1068: 0x90000010 | (0x08 << 7),       # [!A1] B.S1 packet+0x20 (jump)
    0x106C: 0x80000010 | (0x28 << 7),       # [A1] B.S1 packet+0xa0 (call)
    0x1070: nop(5),
    0x1074: B_B3,
    0x1078: nop(5),
    0x1080: B_B3,
    0x1084: nop(5),
    0x10A0: 0x80000010 | (0x10 << 7),       # [A1] B.S1 packet+0x40 (jump)
    0x10A4: mvk(0x10C0, 3),
    0x10A8: mvk(0x1100, 5),
    0x10AC: mvkh(0, 3),
    0x10B0: mvkh(0, 5),
    0x10B4: nop(1),
    0x10B8: 0x362 | (5 << 18),              # B.S2 B5 (call)
    0x10BC: nop(5),
    0x10C0: B_B3,
    0x10C4: nop(5),
    0x10E0: B_B3,
    0x10E4: nop(5),
    0x1100: B_B3,
    0x1104: nop(5),
    0x1140: mvk(0x1158, 3),
    0x1144: mvkh(0, 3),
    0x1148: 0x80000010 | (0x10 << 7),       # [A1] B.S1 packet+0x40 (jump)
    0x114C: nop(5),
    0x1150: 0x10 | (0x20 << 7),             # B.S1 packet+0x80 (call)
    0x1154: nop(5),
    0x1158: B_B3,
    0x115C: nop(5),
    0x1180: B_B3,
    0x1184: nop(5),
    0x11C0: B_B3,
    0x11C4: nop(5),
    0x1200: mvk(0x1214, 3),
    0x1204: mvkh(0, 3),
    0x1208: 0x20000010 | (0x18 << 7),       # [B0] B.S1 packet+0x60
    0x120C: 0x90000010 | (0x10 << 7),       # [!A1] B.S1 packet+0x40 (jump)
    0x1210: nop(4),
    0x1214: B_B3,
    0x1218: nop(5),
    0x1240: B_B3,
    0x1244: nop(5),
    0x1260: B_B3,
    0x1264: nop(5),
    0x1280: mvk(0x12A0, 3),
    0x1284: mvkh(0, 3),
    0x1288: 0x80000010 | (0x10 << 7),       # [A1] B.S1 packet+0x40 (jump)
    0x128C: nop(5),
    0x1290: 0x10 | (0x18 << 7),             # B.S1 packet+0x60 (jump)
    0x1294: nop(4),
    0x1298: nop(1),
    0x129C: nop(1),
    0x12A0: B_B3,
    0x12A4: nop(5),
    0x12C0: B_B3,
    0x12C4: nop(5),
    0x12E0: B_B3,
    0x12E4: nop(5),
    **CASES,
}


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x1120)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
