#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a function that saves a callee-saved pair with STDW. Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000SavedPairsTest.java prepare declares the
function. Independent manual fields (SPRUFE8B LDDW p.284, STDW p.510, 2.2 and Table 2-1 register pairs),
no firmware bytes:

  1000  STDW.D2T1 A11:A10,*B15--[1]
  1004  MV.L1     A4,A10
  1008  B.S1      1040
  100c  ADDKPC.S2 1010,B3,4
  1010  ADD.L1    A10,A10,A4
  1014  LDDW.D2T1 *++B15[1],A11:A10
  1018  NOP 4
  101c  B.S2      B3
  1020  NOP 5
  1040  B.S2 B3 ; NOP 5                 (the callee)

Compiled prologues save A10-A15 and B10-B15 in pairs like this. The pair's
halves are unaffected by a call, so the pair is too.
"""

from pathlib import Path
import struct
import sys


def load_store(register, base, offset, mode, op):
    """A .D2T1 doubleword access: the A-side pair at register, the B-side base."""
    return register << 23 | base << 18 | offset << 13 | mode << 9 | 1 << 8 | 1 << 7 | op << 4 | 1 << 2


WORDS = [
    load_store(10, 15, 1, 0b1010, 0b100),       # STDW A11:A10,*B15--[1]
    10 << 23 | 4 << 18 | 0xFD8,                 # MV A4,A10
    0x10 | (0x40 >> 2) << 7,                    # B 1040
    3 << 23 | (0x10 >> 2) << 16 | 4 << 13 | 0x162,  # ADDKPC 1010,B3,4
    4 << 23 | 10 << 18 | 10 << 13 | 3 << 5 | 0x18,  # ADD A10,A10,A4
    load_store(10, 15, 1, 0b1001, 0b110),       # LDDW *++B15[1],A11:A10
    3 << 13,                                    # NOP 4
    3 << 18 | 0x362,                            # B B3
    4 << 13,                                    # NOP 5
]
CALLEE = [3 << 18 | 0x362, 4 << 13]


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x60)
    for index, word in enumerate(WORDS):
        struct.pack_into(endian + "I", image, 4 * index, word)
    for index, word in enumerate(CALLEE):
        struct.pack_into(endian + "I", image, 0x40 + 4 * index, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
