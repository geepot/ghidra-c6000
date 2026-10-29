#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build B tail calls and B/BNOP calls that keep or set B3. Usage: IMAGE [be].

Load at 0x1000 with entry 0x1000 and auto-analysis; C6000TailCallSlotsTest.java
prepare marks 0x11c0 as a no-return function, as an ELF exit() would be, and enters
0x1300. Words are GNU tic6x-as 2.47 output (-march=c674x), and from 0x1300 TI cl6x
8.3.15 output, all checked against TI dis6x 8.3.15 (SPRUFE8B 4.2.6, B, BNOP, ADDKPC):

  1000  B.S1 0x1200 ; ADDKPC 0x1008,B3,4       calls to callee and both tail callers
  1008  B.S1 0x1100 ; ADDKPC 0x1010,B3,4
  1010  B.S1 0x1140 ; ADDKPC 0x1018,B3,4
  1018  MVK/MVKH 0x1180,A3 ; NOP               B.S2X A3 at 0x1024, ADDKPC 0x102c,B3,4
  102c  MVK/MVKH 0x11c0,A3 ; MVK.L1 1,A4       B.S2X A3 at 0x1038, ADDKPC 0x1040,B3,4 (no-return callee)
  1040  MVK/MVKH 0x105c,B3 ; MVK/MVKH 0x11c0,A3 ; NOP   B.S2X A3 at 0x1054 ; NOP 5 (link set before the packet)
  105c  B.S1 0x1240 ; ADDKPC 0x1064,B3,4      1064  B.S2 B3 ; NOP 5
  1100  B.S1 0x1200 ; LDW *++B15[2],B3 ; MV A10,A4 ; NOP 3   tail call restoring B3
  1140  B.S1 0x1200 ; NOP 5                                  tail call
  1180  B.S2 B3 ; NOP 5    11c0  B.S1 0x11c0 ; NOP 5    1200  B.S2 B3 ; NOP 5
  1240  MV A4,A6 ; B.S1 0x1200 ; ADDKPC 0x1254,B3,4 ; NOP ; NOP   a call returning past its window
  1254  B.S2 B3 ; NOP 5
  1300  MVK/MVKH 0x1314,B3 ; BNOP.S1 0x1200,3 ; MVK.S1 7,A4 ; MVK.S1 8,A5   a BNOP call, link set before
  1314  MVK.S1 3,A6 ; B.S2 B3 ; NOP 5
"""

from pathlib import Path
import struct
import sys

WORDS = {
    0x1000: 0x00004010, 0x1004: 0x01828162, 0x1008: 0x00002010, 0x100C: 0x01848162,
    0x1010: 0x00002810, 0x1014: 0x01868162, 0x1018: 0x0188C028, 0x101C: 0x01800068,
    0x1024: 0x000C1362, 0x1028: 0x01838162, 0x102C: 0x0188E028, 0x1030: 0x01800068,
    0x1034: 0x0204A358, 0x1038: 0x000C1362, 0x103C: 0x01888162, 0x1040: 0x01882E2A,
    0x1044: 0x0180006A, 0x1048: 0x0188E028, 0x104C: 0x01800068, 0x1054: 0x000C1362,
    0x1058: 0x00008000, 0x105C: 0x00004010, 0x1060: 0x01818162, 0x1064: 0x000C0362,
    0x1068: 0x00008000, 0x1100: 0x00002010, 0x1104: 0x01BC52E6, 0x1108: 0x02280FD8,
    0x110C: 0x00004000, 0x1140: 0x00001810, 0x1144: 0x00008000, 0x1180: 0x000C0362,
    0x1184: 0x00008000, 0x11C0: 0x00000010, 0x11C4: 0x00008000, 0x1200: 0x000C0362,
    0x1204: 0x00008000, 0x1240: 0x03100FD8, 0x1244: 0x0FFFF810, 0x1248: 0x01858162,
    0x1254: 0x000C0362, 0x1258: 0x00008000,
    0x1300: 0x01898A2A, 0x1304: 0x0180006A, 0x1308: 0x0FC06120, 0x130C: 0x020003A8,
    0x1310: 0x02800428, 0x1314: 0x030001A8, 0x1318: 0x000C0362, 0x131C: 0x00008000,
}


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x320)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
