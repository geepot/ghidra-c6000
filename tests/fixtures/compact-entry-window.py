#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a function whose entry packet issues a jump with compact delay slots. Usage: IMAGE [be].

Load at 0x1000 with entry 0x1000 and auto-analysis. Independent manual fields
(SPRUFE8B B pp.151, 153, MVK p.381, MV p.375, NOP p.388, the 16-bit opcode maps
in F.4 and the header word, 3.10.2 and Figure 3-5), checked against
GNU objdump; no firmware bytes:

  1000  B.S1    1040
  1004  MVK.L1  3,A4        (16-bit)
  1006  MV.L1   A0,A4       (16-bit)
  1008  NOP     3
  101c  fetch packet header: word 1 compact
  1040  B.S2    B3
  1044  NOP     5

The jump's native window is 8 bytes and three instructions, but Ghidra's delay-slot
depth counts them otherwise. C6000CompactEntryWindowTest.java enables the
exact schedule and runs it: A4 ends as A0, and it returns to B3.
"""

from pathlib import Path
import struct
import sys
import compact_order

compact_order.big_endian_on_exit()


def b_s1(at, target):
    """B.S1 to target, relative to the fetch packet holding at."""
    return 0x10 | ((((target - (at & ~31)) >> 2) & 0x1FFFFF) << 7)


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x60)
    words = {0x1000: b_s1(0x1000, 0x1040), 0x1008: 2 << 13, 0x101C: 0xE0000000 | 1 << 22,
             0x1040: 3 << 18 | 0x362, 0x1044: 4 << 13}
    for address, word in words.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    struct.pack_into(endian + "HH", image, 0x4, 0x6626, 0x8046)  # MVK.L1 3,A4 ; MV.L1 A0,A4
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
