#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a switch whose index and table are read through circular-capable bases. Usage: IMAGE [be].

Load at 0x1000 with no auto-analysis; C6000CircularMaskSwitchTest.java decompiles 0x1000.
Words are TI cl6x 8.5.0 output (-mv6740 --abi=eabi --no_compress), listed by dis6x; the
shape is a cl6x dispatch from compiled code, with the index loaded through A4 and the table
through A5, both registers AMR can make circular (SPRUFE8B 2.8.3, 3.9.2):

  1000 sw   LDBU *+A4[1],A3 ; MVK/MVKH 0x1100,A5 ; NOP 4
            CMPLTU 11,A3,A0 ; [A0] B dflt ; [!A0] LDW *+A5[A3],A3 ; NOP 4
            [!A0] B A3 ; NOP 5
       1028 dflt: B B3 ; NOP 5
       1030 + 16*i, i = 0..11: MVK i+1,A4 ; B B3 ; NOP 5 ; NOP
       1100 the table: 1030, 1040, ..., 10e0

The EABI keeps AMR zero at call boundaries (SPRAB89 3.2), so both loads address linearly
and the decompiler should recover a switch with twelve cases.
"""

from pathlib import Path
import struct
import sys

WORDS = [
    0x01902214, 0x02888028, 0x02800068, 0x00006000, 0x000D6BD8, 0xC0000510, 0xD1946A64, 0x00006000,
    0xD00C1362, 0x00008000, 0x000C0362, 0x00008000, 0x020000A8, 0x000C0362, 0x00008000, 0x00000000,
    0x02000128, 0x000C0362, 0x00008000, 0x00000000, 0x020001A8, 0x000C0362, 0x00008000, 0x00000000,
    0x02000228, 0x000C0362, 0x00008000, 0x00000000, 0x020002A8, 0x000C0362, 0x00008000, 0x00000000,
    0x02000328, 0x000C0362, 0x00008000, 0x00000000, 0x020003A8, 0x000C0362, 0x00008000, 0x00000000,
    0x02000428, 0x000C0362, 0x00008000, 0x00000000, 0x020004A8, 0x000C0362, 0x00008000, 0x00000000,
    0x02000528, 0x000C0362, 0x00008000, 0x00000000, 0x020005A8, 0x000C0362, 0x00008000, 0x00000000,
    0x02000628, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
]


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x140)
    for index, word in enumerate(WORDS):
        struct.pack_into(endian + "I", image, 4 * index, word)
    for case in range(12):
        struct.pack_into(endian + "I", image, 0x100 + 4 * case, 0x1030 + 16 * case)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
