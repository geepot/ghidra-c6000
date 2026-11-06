#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build nested delay windows for exact-schedule review. Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000NestedWindowScheduleTest.java prepare
declares the seven functions, as ELF symbols would. Words are TI cl6x 8.3.15
output (-mv6740 --no_compress), listed by dis6x (SPRUFE8B 4.2.6, B, MVK/MVKH):

  1000 retjump  MVK 1,A4 ; B tail1 ; ADD 15,A4,A4 ; NOP 3 ; B B3 ; ADD 8 ; ADD 8
       101c     tail1: ADD 2,A4,A4 ; ADD 4,A4,A4 ; NOP 3
                the return issues in the jump's last slot, so its slots run at
                tail1: returns 22. The native window of B tail1 is refused
                (nested transfer), so its slots 0x1008-0x1013 stay unowned.
  1040 ifcall   MV A4,A1 || MV B3,B13 ; [A1] B skip || [A1] ADD 1,A4,A4 ;
                [!A1] B callee || [!A1] MVKL ret,B3 ; [!A1] MVK 7,A4 || [!A1] MVKH ret,B3 ;
                NOP 4 ; ret: ADD 2,A4,A4 ; skip: MV B13,B3 ; B B3 ; NOP 5
                if/else call: the call arm sets its link under its own predicate
  1080 ifcall2  as ifcall, but the link is written under [B0], a copy of B4:
                no exact link on the call path
  10c0 callee   B B3 ; ADD A4,A4,A4 ; NOP 4
  10e0 ifcall3  MV A4,A1 || MV B3,B13 ; [!A1] B callee || [!A1] MVKL ret3,B3 ;
                [!A1] MVKH ret3,B3 || [!A1] MVK 7,A4 ; NOP 4 ; ret3: MV B13,B3 ; B B3 ; NOP 5
                conditional call whose link is written in its own issue packet
  1120 neighbour MVK 5,A4 ; B B3 ; NOP 5: returns 5
  112c absorber MVK 1,A4 ; B tail2 ; ADD 15,A4,A4 ; NOP 3 ; B B3 ; ADD 8 ; ADD 8
       1148     tail2: ADD 2,A4,A4 ; ADD 4,A4,A4 ; NOP 3: retjump's shape, returns 22;
                its unowned slots 0x1134-0x113f share neighbour's fetch packet 0x1120
"""

from pathlib import Path
import struct
import sys

WORDS = {
    0x1000: 0x020000A8, 0x1004: 0x00000390, 0x1008: 0x0211E058, 0x100C: 0x00004000,
    0x1010: 0x000C0362, 0x1014: 0x02110058, 0x1018: 0x02110058, 0x101C: 0x02104058,
    0x1020: 0x02108058, 0x1024: 0x00004000, 0x1040: 0x00900FD9, 0x1044: 0x068C0FDA,
    0x1048: 0x80000511, 0x104C: 0x82102058, 0x1050: 0x90001011, 0x1054: 0x9188322A,
    0x1058: 0x920003A9, 0x105C: 0x9180006A, 0x1060: 0x00006000, 0x1064: 0x02104058,
    0x1068: 0x01B406A2, 0x106C: 0x000C0362, 0x1070: 0x00008000, 0x1080: 0x00900FD9,
    0x1084: 0x068C0FDB, 0x1088: 0x001008F2, 0x108C: 0x80000591, 0x1090: 0x82102058,
    0x1094: 0x90000811, 0x1098: 0x2188542A, 0x109C: 0x920003A9, 0x10A0: 0x2180006A,
    0x10A4: 0x00006000, 0x10A8: 0x02104058, 0x10AC: 0x01B406A2, 0x10B0: 0x000C0362,
    0x10B4: 0x00008000, 0x10C0: 0x000C0362, 0x10C4: 0x02108078, 0x10C8: 0x00006000,
    0x10E0: 0x00900FD9, 0x10E4: 0x068C0FDA, 0x10E8: 0x9FFFFC11, 0x10EC: 0x91887E2A,
    0x10F0: 0x9180006B, 0x10F4: 0x920003A8, 0x10F8: 0x00006000, 0x10FC: 0x01B406A2,
    0x1100: 0x000C0362, 0x1104: 0x00008000, 0x1120: 0x020002A8,
    0x1124: 0x000C0362, 0x1128: 0x00008000, 0x112C: 0x020000A8, 0x1130: 0x00000510,
    0x1134: 0x0211E058, 0x1138: 0x00004000, 0x113C: 0x000C0362, 0x1140: 0x02110058,
    0x1144: 0x02110058, 0x1148: 0x02104058, 0x114C: 0x02108058, 0x1150: 0x00004000,
}


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x160)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
