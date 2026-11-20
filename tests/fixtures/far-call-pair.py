#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build an if/else call pair whose arms call two different functions. Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000FarCallPairTest.java prepare declares
the three functions, as symbols would. Words are encoded from SPRUFE8B's
opcode diagrams for MVK p.381, MVKH p.383, B p.151 and NOP p.388, as in delayed-call.py:

  1000  MVK.S2  0x1014,B3        100c  [A1]B.S1  0x1200      (call)
  1004  MVKH.S2 0x0,B3           1010  NOP     5
  1008  [!A1]B.S1 0x1100 (call)  1014  B.S2 B3 ; NOP 5
  1100  B.S2 B3 ; NOP 5          (one callee)
  1200  B.S2 B3 ; NOP 5          (the other)

Both targets are function entries, so neither arm is a local else-block,
although 0x1100 is the nearer one. C6000FarCallPairTest.java checks both
arms become calls.
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


B_B3 = 0x362 | (3 << 18)
A1, NOT_A1 = 0x80000000, 0x90000000

WORDS = {
    0x1000: mvk(0x1014, 3),
    0x1004: mvkh(0, 3),
    0x1008: NOT_A1 | b_s1(0x1008, 0x1100),
    0x100C: A1 | b_s1(0x100C, 0x1200),
    0x1010: nop(5),
    0x1014: B_B3,
    0x1018: nop(5),
    0x1100: B_B3,
    0x1104: nop(5),
    0x1200: B_B3,
    0x1204: nop(5),
}


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x220)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
