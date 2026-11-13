#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build B calls with and without a parallel companion. Usage: IMAGE [be].

Load at 0x1000 with entry 0x1000 and auto-analysis. Words are GNU tic6x-as 2.47
output (-march=c674x), checked against TI dis6x 8.3.15 (SPRUFE8B 3.5, 4.2.6):

  1000  B.S1    0x1200  (call)     1020  MVK.S2  0x102c,B3
  1004  ADDKPC.S2 0x1008,B3,4      1024  MVKH.S2 0x0,B3
  1008  B.S1    0x1100  (call)     1028  NOP     3
  100c  ADDKPC.S2 0x1010,B3,4      102c  B.S1    0x1200  (call)
  1010  B.S1    0x1140  (call)     1030  || MV.L1  A4,A5
  1014  ADDKPC.S2 0x1018,B3,4      1034  ADDKPC.S2 0x1038,B3,4
  1018  B.S1    0x1200  (call)     1038  B.S2    B3 ; NOP 5
  101c  || STW.D2T2 B3,*B15--[2]
  1100  B.S1    0x1200 ; LDW *++B15[2],B3 ; MV A10,A4 ; NOP 3   (callee)
  1140  B.S1    0x1200 ; NOP 5     1200  B.S2 B3 ; NOP 5          (callees)
"""

from pathlib import Path
import struct
import sys

WORDS = {
    0x1000: 0x00004010, 0x1004: 0x01828162, 0x1008: 0x00002010, 0x100C: 0x01848162,
    0x1010: 0x00002810, 0x1014: 0x01868162, 0x1018: 0x00004011, 0x101C: 0x01BC54F6,
    0x1020: 0x0188162A, 0x1024: 0x0180006A, 0x1028: 0x00004000, 0x102C: 0x00003C11,
    0x1030: 0x02900FD8, 0x1034: 0x01868162, 0x1038: 0x000C0362, 0x103C: 0x00008000,
    0x1100: 0x00002010, 0x1104: 0x01BC52E6, 0x1108: 0x02280FD8, 0x110C: 0x00004000,
    0x1140: 0x00001810, 0x1144: 0x00008000,
    0x1200: 0x000C0362, 0x1204: 0x00008000,
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
