#!/usr/bin/env python3
"""Compact LDNDW/STNDW offset cases (SPRUFE8B Figures C-9, C-11). Usage: IMAGE CASES.tsv [be]"""

import struct
import sys
from pathlib import Path


def dw(ucst4=0, src1=None, na=1, ld=1):
    """Doff4DW (src1 None) or DindDW: ptr A4, src/dst A1:A0, side A."""
    if src1 is None:
        hi = ((ucst4 & 7) << 13) | ((ucst4 >> 3) << 11)
    else:
        hi = (src1 << 13) | (1 << 10)
    return hi | (na << 4) | (ld << 3) | (1 << 2)


# name, opcode, load (1) or store (0), expected byte offset from A4
CASES = [
    ("LDNDW-offset", dw(ucst4=1), 1, 1),
    ("LDNDW-register", dw(src1=2), 1, 3),
    ("STNDW-offset", dw(ucst4=1, ld=0), 0, 1),
    ("STNDW-register", dw(src1=2, ld=0), 0, 3),
    ("LDDW-offset", dw(ucst4=1, na=0), 1, 8),
    ("STDW-offset", dw(ucst4=1, na=0, ld=0), 0, 8),
]


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    header = 0xe0000000 | (1 << 21) | (4 << 16)
    with image.open("wb") as output, manifest.open("w") as cases:
        for index, (name, opcode, load, offset) in enumerate(CASES):
            output.write(struct.pack(endian + "H", opcode))
            output.write(bytes(26))
            output.write(struct.pack(endian + "I", header))
            cases.write(f"{index}\t{name}\t{load}\t{offset}\n")
        output.write(bytes(range(0x10, 0x30)))


if __name__ == "__main__":
    main()
