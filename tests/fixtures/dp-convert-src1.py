#!/usr/bin/env python3
"""Build DPINT/DPTRUNC/DPSP src1-field decode cases.

Usage: dp-convert-src1.py IMAGE CASES.tsv [be]

Each word sits alone in a 32-byte packet. src2 = the pair's odd register and
src1 = its low register is how cl6x 8.3.15 and GNU as 2.47 encode every pair
(DPINT .L1 A7:A6,A3 assembles to 019cc118). Every other src1, an even src2
(the opcode diagram's form, which dis6x reads from src1) and x = 1 are not
decoded. The rows match unary-dp-src1.py.
"""

import struct
import sys
from pathlib import Path

LOW = {"DPINT": 0x118, "DPTRUNC": 0x038, "DPSP": 0x138}
# raw double placed in the pair, expected dst; low words matter to both results
VALUE = {"DPINT": (0x41dfffffffc00000, 0x7fffffff),
         "DPTRUNC": (0x41dfffffffc00000, 0x7fffffff),
         "DPSP": (0x4021333333333333, 0x4109999a)}
# name, src2, src1, x, decoded pair low register (-1 = undefined)
FORMS = [
    ("asm-pair6", 7, 6, 0, 6),
    ("asm-pair16", 17, 16, 0, 16),
    ("asm-pair0", 1, 0, 0, 0),
    ("diagram-odd-pair6", 7, 0, 0, -1),
    ("src1-even-other", 7, 2, 0, -1),
    ("src1-above-pair", 7, 8, 0, -1),
    ("src1-odd", 7, 5, 0, -1),
    ("src1-odd-high", 7, 7, 0, -1),
    ("cross-odd", 7, 6, 1, -1),
    ("even-pair6", 6, 0, 0, -1),
    ("even-pair16", 16, 0, 0, -1),
    ("even-pair0", 0, 0, 0, -1),
    ("even-src1-low", 6, 6, 0, -1),
    ("cross-even", 6, 0, 1, -1),
]


def word(mnemonic, side, src2, src1, x):
    return (3 << 23) | (src2 << 18) | (src1 << 13) | (x << 12) | LOW[mnemonic] | (side << 1)


def main():
    image, cases = Path(sys.argv[1]), Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    index = 0
    with image.open("wb") as out, cases.open("w") as manifest:
        for mnemonic in LOW:
            raw, result = VALUE[mnemonic]
            for side in (0, 1):
                for name, src2, src1, x, low in FORMS:
                    w = word(mnemonic, side, src2, src1, x)
                    out.write(struct.pack(endian + "I", w) + bytes(28))
                    manifest.write(f"{index}\t{mnemonic}-{name}-{side + 1}\t{mnemonic}\t"
                                   f"{side}\t{w:08x}\t{low}\t{raw:016x}\t{result:08x}\n")
                    index += 1


if __name__ == "__main__":
    main()
