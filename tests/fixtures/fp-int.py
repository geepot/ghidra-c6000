#!/usr/bin/env python3
"""Build SPINT/SPTRUNC conversion packets and expected register/flag values.

Usage: fp-int.py IMAGE CASES.tsv [be]
Each case occupies one 32-byte fetch packet; source and destination are
A1/A2 for .L1 or B1/B2 for .L2.
"""

import struct
import sys
from pathlib import Path


def f32(value):
    return struct.unpack("<I", struct.pack("<f", value))[0]


# name, instruction, side, raw source, initial FADCR, result, new flag bits
CASES = [
    ("nearest", "SPINT", 0, f32(8.6), 0, 9, 0x80),
    ("zero", "SPINT", 0, f32(8.6), 1 << 9, 8, 0x80),
    ("up", "SPINT", 0, f32(8.6), 2 << 9, 9, 0x80),
    ("down", "SPINT", 0, f32(8.6), 3 << 9, 8, 0x80),
    ("tie-even", "SPINT", 0, f32(2.5), 0, 2, 0x80),
    ("tie-odd", "SPINT", 0, f32(3.5), 0, 4, 0x80),
    ("negative-tie-even", "SPINT", 0, f32(-2.5), 0, -2, 0x80),
    ("negative-zero", "SPINT", 0, f32(-8.6), 1 << 9, -8, 0x80),
    ("negative-up", "SPINT", 0, f32(-8.6), 2 << 9, -8, 0x80),
    ("negative-down", "SPINT", 0, f32(-8.6), 3 << 9, -9, 0x80),
    ("truncate", "SPTRUNC", 0, f32(8.6), 0, 8, 0x80),
    ("nan", "SPINT", 0, 0x7fc00000, 0, 0x7fffffff, 0x12),
    ("negative-nan", "SPINT", 0, 0xffc00000, 0, 0x80000000, 0x12),
    ("positive-infinity", "SPINT", 0, 0x7f800000, 0, 0x7fffffff, 0xc0),
    ("negative-infinity", "SPINT", 0, 0xff800000, 0, 0x80000000, 0xc0),
    ("denormal", "SPINT", 0, 0x00000001, 0, 0, 0x88),
    ("positive-overflow", "SPINT", 0, 0x4f000000, 0, 0x7fffffff, 0xc0),
    ("negative-limit", "SPINT", 0, 0xcf000000, 0, 0x80000000, 0),
    ("negative-overflow", "SPINT", 0, 0xcf000001, 0, 0x80000000, 0xc0),
    ("sticky-flags", "SPINT", 0, f32(4.0), 0x4, 4, 0),
    ("unit-two", "SPINT", 1, f32(8.6), 0, 9, 0x80),
    ("unit-two-down", "SPINT", 1, f32(-8.6), 3 << 25, -9, 0x80),
    ("unit-two-truncate", "SPTRUNC", 1, f32(8.6), 0, 8, 0x80),
]


def opcode(mnemonic, side):
    low = 0x158 if mnemonic == "SPINT" else 0x178
    return (2 << 23) | (1 << 18) | low | (side << 1)


def main():
    image = Path(sys.argv[1])
    cases = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, cases.open("w") as manifest:
        for index, (name, mnemonic, side, raw, fadcr, result, flags) in enumerate(CASES):
            out.write(struct.pack(endian + "I", opcode(mnemonic, side)))
            out.write(bytes(28))
            expected_flags = fadcr | (flags << (16 if side else 0))
            manifest.write(
                f"{index}\t{name}\t{mnemonic}\t{side}\t{raw:08x}\t"
                f"{fadcr:08x}\t{result & 0xffffffff:08x}\t"
                f"{expected_flags:08x}\n"
            )


if __name__ == "__main__":
    main()
