#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build delay windows entered only at their trailing NOP slots. Usage: IMAGE [be].

Load at 0x1000 with entry 0x1000 and auto-analysis; C6000EnteredIdleTailTest.java
prepare declares the two functions. Words are TI cl6x 8.3.15 output (-mv6740
--abi=eabi --no_compress), listed by dis6x. A jump into another branch's delay
slots runs them in sequence from there (SPRUFE8B 3.5, 4.2.6); entering at a NOP
only idles until the branch lands. Five such windows exceed Ghidra 12.2's
overlap limit (issue #52):

  1000 idle  MV B4,A1 ; MV A6,A2 ; four times: [A1] B.S1 m ; NOP 5 ; [A2] B.S1 s ;
             ADD 1,A4,A4 (x3) ; m: NOP 2 ; s: ...
             then [A1] B.S1 m5 ; NOP 5 ; B.S2 B3 ; ADD 1,A4,A4 (x3) ; m5: NOP 2 ;
             B.S2 B3 ; NOP 5
             idle(a, b, c) is b ? a : a + 15, whatever c: each window's ADDs run
             on both of its paths, and its fifth cycle (m) is a jump target
  10c0 busy  MV B4,A1 ; MV A6,A2 ; five times: [A1] B.S1 n ; NOP 5 ; [A2] B.S1 t ;
             ADD 1,A4,A4 ; n: NOP ; ADD 1,A4,A4 (x3) ; t: ... then B.S2 B3 ; NOP 5
             each window is entered at a NOP that ADDs follow, so it is released
"""

from pathlib import Path
import struct
import sys

WORDS = [
    0x00901FD8, 0x01180FD8, 0x80000410, 0x00008000, 0xA0000490, 0x02102058, 0x02102058, 0x02102058,
    0x00002000, 0x80000390, 0x00008000, 0xA0000410, 0x02102058, 0x02102058, 0x02102058, 0x00002000,
    0x80000310, 0x00008000, 0xA0000390, 0x02102058, 0x02102058, 0x02102058, 0x00002000, 0x80000690,
    0x00008000, 0xA0000310, 0x02102058, 0x02102058, 0x02102058, 0x00002000, 0x80000610, 0x00008000,
    0x000C0362, 0x02102058, 0x02102058, 0x02102058, 0x00002000, 0x000C0362, 0x00008000, 0x00000000,
]
BUSY = [
    0x00901FD8, 0x01180FD8, 0x80000310, 0x00008000, 0xA0000510, 0x02102058, 0x00000000, 0x02102058,
    0x02102058, 0x02102058, 0x80000310, 0x00008000, 0xA0000510, 0x02102058, 0x00000000, 0x02102058,
    0x02102058, 0x02102058, 0x80000310, 0x00008000, 0xA0000510, 0x02102058, 0x00000000, 0x02102058,
    0x02102058, 0x02102058, 0x80000310, 0x00008000, 0xA0000510, 0x02102058, 0x00000000, 0x02102058,
    0x02102058, 0x02102058, 0x80000310, 0x00008000, 0xA0000510, 0x02102058, 0x00000000, 0x02102058,
    0x02102058, 0x02102058, 0x000C0362, 0x00008000,
]


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x200)
    for index, word in enumerate(WORDS):
        struct.pack_into(endian + "I", image, 4 * index, word)
    for index, word in enumerate(BUSY):
        struct.pack_into(endian + "I", image, 0xc0 + 4 * index, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
