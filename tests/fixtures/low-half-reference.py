#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""MVK low halves that an MVKH completes, or does not (SPRUFE8B pp. 380, 383; 4.2.6). Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000LowHalfReferenceTest.java prepare declares
f, h, g, k and m. Words are TI cl6x 8.3.15 output (-mv6740 --abi=eabi --no_compress),
listed by dis6x. Each MVK loads 0x1068, the address of g, which Ghidra's Scalar
Operand References analyzer takes for a data reference:

  1000 f  MVK 0x1068,B4 ; MVKH 0x10000,B4        B4 = 0x00011068: no reference
          MVK 0x1068,B5 ; MVKH 0x0,B5            B5 = 0x00001068: reference kept
          MVK 0x1068,B6 ; ADD B6,B6,B7 ; MVKH 0x10000,B6
                                                 B7 read the low half: kept
          B B3 ; NOP 5
  1024 h  B g ; MVK 0x1068,B3 ; MVKH 0x10000,B3 ; NOP 3
                                                 a return address in the call's slots: no reference
          MVK 2,A4 ; B g ; NOP 4 ; MVK 0x1068,B8 ; MVKH 0x10000,B8
                                                 the B lands before the MVKH issues: kept
  1068 g  MVK 1,A4 ; B B3 ; NOP 5
  1080 k  MVK 0x1068,B9 ; BNOP g,5 ; MVKH 0x10000,B9
                                                 BNOP lands before the MVKH issues: kept
  10a0 m  MVK 0x1068,B10 || B g ; NOP 5 ; MVKH 0x10000,B10
                                                 the MVKH would issue in cycle 6, where the B lands: kept
"""

from pathlib import Path
import struct
import sys

WORDS = [
    0x0208342A, 0x020000EA, 0x0288342A, 0x0280006A, 0x0308342A, 0x0398C07A, 0x030000EA, 0x000C0362,
    0x00008000, 0x00000910, 0x0188342A, 0x018000EA, 0x00004000, 0x02000128, 0x00000910, 0x00006000,
    0x0408342A, 0x040000EA, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x020000A8, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000,
    0x0488342A, 0x0FFAA120, 0x048000EA, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x0508342B, 0x0FFFF910, 0x00008000, 0x050000EA, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
]


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(4 * len(WORDS))
    for index, word in enumerate(WORDS):
        struct.pack_into(endian + "I", image, 4 * index, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
