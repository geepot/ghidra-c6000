#!/usr/bin/env python3
"""Code after a register branch's delay slots, issue #32. Usage: IMAGE [be].

Load at 0x1000 with entries 0x1000, 0x1040 and 0x1080 and auto-analysis.
Words are cl6x 8.3.15 -mv6740 --no_compress output; DATA is MVK.L1 0,A4.

  1000 q1:  B.S1 q1t   ; NOP 5 ; DATA ; DATA
  1010 q1t: B.S2 B3    ; NOP 5 ; DATA ; DATA ; NOP padding
  1040 rk1: B.S2 B5    ; NOP 5 ; DATA ; NOP padding
  1080 rk2: BNOP.S2 B3,5 ; DATA
"""

from pathlib import Path
import struct
import sys

DATA = 0x0200a358
B_B3, B_B5, NOP5, BNOP_B3_5 = 0x000c0362, 0x00140362, 0x00008000, 0x008ca362
WORDS = {0x1000: 0x00000210, 0x1004: NOP5, 0x1008: DATA, 0x100c: DATA,
         0x1010: B_B3, 0x1014: NOP5, 0x1018: DATA, 0x101c: DATA,
         0x1040: B_B5, 0x1044: NOP5, 0x1048: DATA,
         0x1080: BNOP_B3_5, 0x1084: DATA}

if __name__ == "__main__":
    endian = ">" if len(sys.argv) > 2 and sys.argv[2] == "be" else "<"
    image = bytearray(0xa0)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)
