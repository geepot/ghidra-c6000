#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build B B3 calls whose delay slots set B3 past the window. Usage: IMAGE [be].

Load at 0x1000 with entry 0x1000 and auto-analysis; C6000B3CallTest.java prepare
declares the four functions, as ELF symbols would. Words are TI cl6x 8.3.15 output
(-mv6740 --abi=eabi --no_compress), listed by dis6x (issue #39). A register branch only
loads the fetch counter (SPRUFE8B, B): when its delay slots set B3 to the address past
the window it is a call, whatever register holds the target (SPRU187U 7.4.2):

  1000 viaptr  STW B3 ; MV A4,B3 ; B.S2 B3 ; MVK/MVKH 0x1018,B3 ; NOP 3
               fp() + 1: a call through B3, returns to 0x1018
       1018    LDW *++B15[2],B3 ; ADD 1,A4,A4 ; NOP 4 ; B B3 ; NOP 5
  102c direct  STW B3 ; MVK/MVKH callee,B3 ; B.S2 B3 ; MVK/MVKH 0x1048,B3 ; NOP 3
               callee() + 1: a call to 0x105c, returns to 0x1048
       1048    LDW *++B15[2],B3 ; ADD 1,A4,A4 ; NOP 4 ; B B3 ; NOP 5
  105c callee  MVK 41,A4 ; B B3 ; NOP 5          a return
  1068 selfjmp MVK/MVKH 0x1078,B3 ; B.S2 B3 ; NOP 5 ; 1078: MVK 7,A4 ; NOP ; B B3 ; NOP 5
               B3 already holds the address past the window: not a call
"""

from pathlib import Path
import struct
import sys

WORDS = [
    0x01BC54F6, 0x01901FDA, 0x000C0362, 0x01880C2A, 0x0180006A, 0x00004000, 0x01BC52E6, 0x02102058,
    0x00006000, 0x000C0362, 0x00008000, 0x01BC54F6, 0x01882E2A, 0x0180006A, 0x000C0362, 0x0188242A,
    0x0180006A, 0x00004000, 0x01BC52E6, 0x02102058, 0x00006000, 0x000C0362, 0x00008000, 0x020014A8,
    0x000C0362, 0x00008000, 0x01883C2A, 0x0180006A, 0x000C0362, 0x00008000, 0x020003A8, 0x00000000,
    0x000C0362, 0x00008000,
]


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0xa0)
    for index, word in enumerate(WORDS):
        struct.pack_into(endian + "I", image, 4 * index, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
