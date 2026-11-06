#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build B calls whose B3 returns to earlier code of the caller. Usage: IMAGE [be].

Load at 0x1000 with entry 0x1000 and auto-analysis; C6000IdleCallTest.java
prepare declares the ten functions, as ELF symbols would. Words are TI cl6x
8.3.15 output (-mv6740 --no_compress), listed by dis6x (SPRUFE8B 4.2.6, B, MVK/MVKH):

  1000 idle     MVK tbl,A4 ; B run || MVKH ; LDW *A4,A4 || MVK 0x1000,B3 ; MVKH ; NOP 3
                call, returns to idle: for (;;) run(*tbl)
  1020 loopmid  MVK 1,A4 ; 1024 ADD 1,A4,A4 ; B run || MVK 0x1024,B3 ; MVKH ; NOP 4
                call, returns to 0x1024
  1040 tail     MVK 5,A4 ; B run ; NOP 5                       B3 untouched: tail call
  1060 other    MVK tbl,A4 ; B run || MVKH ; MVK 0x1040,B3 ; MVKH ; NOP 3
                B3 names another function: not a call
  1080 jlocal   MVK tbl,A4 ; B 0x109c || MVKH ; LDW || MVK 0x1080,B3 ; MVKH ; NOP 3
                local target: a jump that sets B3 for the call at 0x109c
       109c     B run ; NOP 5                                 call, returns to jlocal
  10c0 stale    B run ; MVK 0x10d0,B3 ; MVKH ; NOP 3          call, returns to 0x10d0
       10d0     MVK 1,A4 ; B run ; NOP 5                      B3 still the call's link: tail call
  10e0 pred     MVK 1,A1 ; 10e4 ADD 1,A4,A4 ; [A1] B run || MVK 0x10e4,B3 ; MVKH ; NOP 4
                predicated: not a call returning to 0x10e4 ; 10f8 B B3 ; NOP 5
  1100 run      B B3 ; NOP 5
  1120 tbl      .word 0
  1140 regcall  MVK run,B5 ; MVKH ; B B5 ; MVK 7,A4 ; MVK 0x1140,B3 ; MVKH ; NOP 2
                register B: lifted with its slots, not a call returning to regcall
  1200 regref   regcall's code, its B given a reference to run by the test
                a register B with a known target: still not a call returning to regref
"""

from pathlib import Path
import struct
import sys

WORDS = {
    0x1000: 0x02089028, 0x1004: 0x00002013, 0x1008: 0x02000068, 0x100C: 0x02100265,
    0x1010: 0x0188002A, 0x1014: 0x0180006A, 0x1018: 0x00004000, 0x1020: 0x020000A8,
    0x1024: 0x02102058, 0x1028: 0x00001C11, 0x102C: 0x0188122A, 0x1030: 0x0180006A,
    0x1034: 0x00006000, 0x1040: 0x020002A8, 0x1044: 0x00001812, 0x1048: 0x00008000,
    0x1060: 0x02089028, 0x1064: 0x00001413, 0x1068: 0x02000068, 0x106C: 0x0188202A,
    0x1070: 0x0180006A, 0x1074: 0x00004000, 0x1080: 0x02089028, 0x1084: 0x00000393,
    0x1088: 0x02000068, 0x108C: 0x02100265, 0x1090: 0x0188402A, 0x1094: 0x0180006A,
    0x1098: 0x00004000, 0x109C: 0x00001012, 0x10A0: 0x00008000, 0x10C0: 0x00000810,
    0x10C4: 0x0188682A, 0x10C8: 0x0180006A, 0x10CC: 0x00004000, 0x10D0: 0x020000A8,
    0x10D4: 0x00000812, 0x10D8: 0x00008000, 0x10E0: 0x008000A8, 0x10E4: 0x02102058,
    0x10E8: 0x80000411, 0x10EC: 0x0188722A, 0x10F0: 0x0180006A, 0x10F4: 0x00006000,
    0x10F8: 0x000C0362, 0x10FC: 0x00008000, 0x1100: 0x000C0362, 0x1104: 0x00008000,
    0x1140: 0x0288802A, 0x1144: 0x0280006A, 0x1148: 0x00140362, 0x114C: 0x020003A8,
    0x1150: 0x0188A02A, 0x1154: 0x0180006A, 0x1158: 0x00002000, 0x1200: 0x0288802A,
    0x1204: 0x0280006A, 0x1208: 0x00140362, 0x120C: 0x020003A8, 0x1210: 0x0189002A,
    0x1214: 0x0180006A, 0x1218: 0x00002000,
}


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x21C)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
