#!/usr/bin/env python3
"""Build 32-bit NORM/SUBU packets from SPRUFE8B execution examples.

Usage: long-arith.py IMAGE [be]
Each opcode is the first word of its own 32-byte fetch packet.
"""

import struct
import sys
from pathlib import Path


def word(op7, src1, src2, dst):
    return (dst << 23) | (src2 << 18) | (src1 << 13) | (op7 << 5) | 0x18


WORDS = [
    word(0b1100011, 0, 1, 2),  # NORM A1,A2
    word(0b1100011, 0, 1, 2),
    word(0b1100000, 0, 0, 3),  # NORM A1:A0,A3
    word(0b1100000, 0, 0, 3),
    word(0b1100000, 0, 0, 3),
    word(0b0101111, 1, 2, 4),  # SUBU A1,A2,A5:A4
    word(0b0111111, 1, 2, 4),
]


def main():
    path = Path(sys.argv[1])
    endian = ">" if len(sys.argv) > 2 and sys.argv[2] == "be" else "<"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as out:
        for opcode in WORDS:
            out.write(struct.pack(endian + "I", opcode))
            out.write(bytes(28))


if __name__ == "__main__":
    main()
