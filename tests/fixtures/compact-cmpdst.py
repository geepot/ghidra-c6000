#!/usr/bin/env python3
"""Compact one-bit dst cases (SPRUFE8B Figures D-7, D-9, D-10). Usage: IMAGE CASES.tsv [be]"""

import struct
import sys
from pathlib import Path


def l2c(op, dst):
    """L2c: src1 = src2 = register 0, side A, no cross path."""
    return ((op >> 2) << 11) | (1 << 10) | ((op & 3) << 5) | (dst << 4) | (1 << 3)


def lx3c(ucst3, dst):
    """Lx3c CMPEQ ucst3, src2 = register 0, side A."""
    return (ucst3 << 13) | (dst << 11) | 0x26


def lx1c(op, ucst1, dst):
    """Lx1c: op, ucst1, src2 = register 0, side A."""
    return (op << 14) | (ucst1 << 13) | (1 << 12) | (dst << 11) | 0x26


# name, opcode, RS, destination, expected value (A0/A1 start at 0xdead, A16/A17 at 5)
CASES = [
    ("CMPEQ-L2c-A0", l2c(3, 0), 1, "A0", 1),
    ("CMPEQ-L2c-A1", l2c(3, 1), 1, "A1", 1),
    ("AND-L2c-A0", l2c(0, 0), 1, "A0", 5),
    ("CMPEQ-Lx3c-A0", lx3c(5, 0), 1, "A0", 1),
    ("CMPEQ-Lx3c-A1", lx3c(5, 1), 1, "A1", 1),
    ("CMPLT-Lx1c-A0", lx1c(0, 0, 0), 1, "A0", 1),
    ("CMPEQ-L2c-low", l2c(3, 0), 0, "A0", 1),
]


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as output, manifest.open("w") as cases:
        for index, (name, opcode, rs, dst, expected) in enumerate(CASES):
            header = 0xe0000000 | (1 << 21) | (rs << 19)
            output.write(struct.pack(endian + "H", opcode))
            output.write(bytes(26))
            output.write(struct.pack(endian + "I", header))
            cases.write(f"{index}\t{name}\t{dst}\t{expected:08x}\n")


if __name__ == "__main__":
    main()
