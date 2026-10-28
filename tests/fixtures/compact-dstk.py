#!/usr/bin/env python3
"""Compact Dstk cases (SPRUFE8B Figure C-16). Usage: IMAGE CASES.tsv [be]"""

import struct
import sys
from pathlib import Path


def dstk(ld, side, reg, ucst5):
    """Figure C-16 Dstk: ucst1-0 in bits 14-13, ucst4-2 in bits 9-7."""
    return ((1 << 15) | ((ucst5 & 3) << 13) | (side << 12) | (3 << 10) |
            ((ucst5 >> 2) << 7) | (reg << 4) | (ld << 3) | (1 << 2) | 1)


# name, load (1) or store (0), register, ucst5
CASES = [
    ("STW", 0, "A4", 3),
    ("LDW", 1, "B6", 5),
    ("STW", 0, "B7", 31),
    ("LDW", 1, "A1", 17),
]


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    header = 0xe0000000 | (1 << 21)
    with image.open("wb") as output, manifest.open("w") as cases:
        for index, (name, ld, reg, ucst5) in enumerate(CASES):
            side = 1 if reg[0] == "B" else 0
            output.write(struct.pack(endian + "H", dstk(ld, side, int(reg[1:]), ucst5)))
            output.write(bytes(26))
            output.write(struct.pack(endian + "I", header))
            cases.write(f"{index}\t{name}-{reg}-{ucst5}\t{ld}\t{reg}\t{ucst5}\n")
        output.write(struct.pack(endian + "32I", *(0x10000000 + i for i in range(32))))


if __name__ == "__main__":
    main()
