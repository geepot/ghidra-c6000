#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build branches whose delay slots are entered by a jump from outside the window. Usage: IMAGE [be].

Load at 0x1000 with entry 0x1000 and auto-analysis; C6000EnteredWindowTest.java
prepare declares the five functions, as ELF symbols would. Words are TI cl6x
8.3.15 output (-mv6740 --abi=eabi --no_compress), listed by dis6x. A jump into a
packet in another branch's delay slots runs the slots in sequence from there
(SPRUFE8B 3.5, 4.2.6). The decompiler re-reads an entered native window with an
"overlaps instruction" warning, and Ghidra 12.2 abandons a function after four such
overlaps (issue #52):

  1000 rentry  STW B3 ; MV A4,A1 ; [A1] B.S1 0x1028 ; NOP 5 ; MVK/MVKH sink,B5 ;
               B.S2 B5 ; MVK 5,A4 ; MVK/MVKH 0x1030,B3 ; 1028: ADD 1,A4,A4 ; NOP
               register call whose fourth slot (0x1028) is a jump target
       1030    LDW *++B15[2],B3 ; NOP 4 ; B B3 ; NOP 5
  1040 dentry  MV A4,A1 ; MV A6,A2 ; [A1] B.S1 0x1058 ; NOP 5 ; [A2] B.S1 0x106c ;
               ADD 1 ; 1058: ADD 2 ; ADD 3 ; ADD 4 ; ADD 5 ; ADD 6 ; 106c: B B3 ; NOP 5
               displacement branch whose second slot (0x1058) is a jump target
  1074 rplain  rentry's call without the incoming jump
  10ac sink    ADD 1,A4,A4 ; B B3 ; NOP 5
  10b8 dmany   MV A4,A1 ; MV A6,A2 ; five times: [A1] B.S1 m ; NOP 5 ; [A2] B.S1 s ;
               ADD 1 ; m: ADD 2 ; ADD 3 ; ADD 4 ; ADD 5 ; s: ...  B B3 ; NOP 5
               five displacement branches (10c8, 10e8, 1108, 1128, 1148), each entered
               at its second slot from the jump before it
"""

from pathlib import Path
import struct
import sys

WORDS = [
    0x01BC54F6, 0x00900FD8, 0x80000510, 0x00008000, 0x0288562A, 0x0280006A, 0x00140362, 0x020002A8,
    0x0188182A, 0x0180006A, 0x02102058, 0x00000000, 0x01BC52E6, 0x00006000, 0x000C0362, 0x00008000,
    0x00900FD8, 0x01180FD8, 0x80000310, 0x00008000, 0xA0000590, 0x02102058, 0x02104058, 0x02106058,
    0x02108058, 0x0210A058, 0x0210C058, 0x000C0362, 0x00008000, 0x01BC54F6, 0x00900FD8, 0x0288562A,
    0x0280006A, 0x00140362, 0x020003A8, 0x01884E2A, 0x0180006A, 0x02102058, 0x00000000, 0x01BC52E6,
    0x00006000, 0x000C0362, 0x00008000, 0x02102058, 0x000C0362, 0x00008000, 0x00900FD8, 0x01180FD8,
    0x80000210, 0x00008000, 0xA0000410, 0x02102058, 0x02104058, 0x02106058, 0x02108058, 0x0210A058,
    0x80000210, 0x00008000, 0xA0000410, 0x02102058, 0x02104058, 0x02106058, 0x02108058, 0x0210A058,
    0x80000210, 0x00008000, 0xA0000410, 0x02102058, 0x02104058, 0x02106058, 0x02108058, 0x0210A058,
    0x80000210, 0x00008000, 0xA0000410, 0x02102058, 0x02104058, 0x02106058, 0x02108058, 0x0210A058,
    0x80000210, 0x00008000, 0xA0000410, 0x02102058, 0x02104058, 0x02106058, 0x02108058, 0x0210A058,
    0x000C0362, 0x00008000,
]


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x200)
    for index, word in enumerate(WORDS):
        struct.pack_into(endian + "I", image, 4 * index, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
