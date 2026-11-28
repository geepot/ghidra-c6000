#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A function whose first instruction is a delayed call. Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000EntryCallTest.java prepare creates the three
functions before analysis, as ELF symbols would, while each B is still a jump. Words are
TI cl6x 8.3.15 output (-mv6740 --no_compress), listed by dis6x; the MVKL of ret1 carries
its linked address (SPRUFE8B 4.2.6, B; MVK/MVKH):

  1000 leaf       B B3 ; ADD A4,B4,A4 ; NOP 4
  1040 entrycall  B leaf ; MV B3,B13 ; MVKL ret1,B3 ; MVKH ret1,B3 ; MV A4,B4 ; NOP ;
                  ret1: ADD 1,A4,A4 ; B B13 ; NOP 5: B3 is set in the delay slots, a call
  1080 jumper     B leaf ; NOP 5: a thunk
"""

from pathlib import Path
import struct
import sys

WORDS = {
    0x1000: 0x000C0362, 0x1004: 0x02109078, 0x1008: 0x00006000, 0x1040: 0x0FFFF810,
    0x1044: 0x068C0FDA, 0x1048: 0x01882C2A, 0x104C: 0x0180006A, 0x1050: 0x02101FDA,
    0x1058: 0x02102058, 0x105C: 0x00340362, 0x1060: 0x00008000, 0x1080: 0x0FFFF010,
    0x1084: 0x00008000,
}


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0xc0)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
