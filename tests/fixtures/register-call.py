#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build register-target B calls whose delay slots set B3 and arguments. Usage: IMAGE [be].

Load at 0x1000 with entry 0x1000 and auto-analysis; C6000RegisterCallTest.java
prepare declares the five functions, as ELF symbols would. Words are TI cl6x
8.3.15 output (-mv6740 --no_compress), listed by dis6x (SPRUFE8B 4.2.6, B, ADDKPC):

  1000 rcall   STW B3 ; B.S2X A4 ; MVK/MVKH 0x101c,B3 ; ADD 1,B4,A4 ; MVK 7,B4 ; NOP
               fp(a + 1, 7) + 3: call, returns to 0x101c
       101c    LDW *++B15[2],B3 ; ADD 3,A4,A4 ; NOP 4 ; B B3 ; NOP 5
  1040 rknown  STW B3 ; MVK/MVKH sink,B5 ; B.S2 B5 ; MVK 5,A4 ; ADDKPC 0x1058,B3,3
               sink(5): call, returns to 0x1058 ; LDW B3 ; NOP 4 ; B B3 ; NOP 5
  1080 rtail   MVK/MVKH sink,B5 ; B.S2 B5 ; MVK 9,A4 ; NOP 4    B3 untouched: not a returning call
  10a0 rpred   STW B3 ; MV A4,A1 ; MVK/MVKH sink,B5 ; [A1] B.S2 B5 ; MVK 5,A4 ;
               MVK/MVKH 0x10c4,B3 ; NOP 2     call if A1, both paths continue at 0x10c4
       10c4    LDW *++B15[2],B3 ; NOP 4 ; B B3 ; NOP 5
  10e0 sink    ADD 1,A4,A4 ; B B3 ; NOP 5
"""

from pathlib import Path
import struct
import sys

WORDS = {
    0x1000: 0x01BC54F6, 0x1004: 0x00101362, 0x1008: 0x01880E2A, 0x100C: 0x0180006A,
    0x1010: 0x02103058, 0x1014: 0x020003AA, 0x101C: 0x01BC52E6, 0x1020: 0x02106058,
    0x1024: 0x00006000, 0x1028: 0x000C0362, 0x102C: 0x00008000, 0x1040: 0x01BC54F6,
    0x1044: 0x0288702A, 0x1048: 0x0280006A, 0x104C: 0x00140362, 0x1050: 0x020002A8,
    0x1054: 0x01866162, 0x1058: 0x01BC52E6, 0x105C: 0x00006000, 0x1060: 0x000C0362,
    0x1064: 0x00008000, 0x1080: 0x0288702A, 0x1084: 0x0280006A, 0x1088: 0x00140362,
    0x108C: 0x020004A8, 0x1090: 0x00006000, 0x10A0: 0x01BC54F6, 0x10A4: 0x00900FD8,
    0x10A8: 0x0288702A, 0x10AC: 0x0280006A, 0x10B0: 0x80140362, 0x10B4: 0x020002A8,
    0x10B8: 0x0188622A, 0x10BC: 0x0180006A, 0x10C0: 0x00002000, 0x10C4: 0x01BC52E6,
    0x10C8: 0x00006000, 0x10CC: 0x000C0362, 0x10D0: 0x00008000, 0x10E0: 0x02102058,
    0x10E4: 0x000C0362, 0x10E8: 0x00008000,
}


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x100)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
