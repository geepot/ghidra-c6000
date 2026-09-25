#!/usr/bin/env python3
"""Build DPINT/DPTRUNC register-pair conversion packets and expected results.

Usage: dp-int.py IMAGE CASES.tsv [be]
"""

import struct
import sys
from pathlib import Path


def f64(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


# name, instruction, side, raw source, initial FADCR, result, new flag bits
CASES = [
    ("nearest", "DPINT", 0, f64(8.6), 0, 9, 0x80),
    ("zero", "DPINT", 0, f64(8.6), 1 << 9, 8, 0x80),
    ("up", "DPINT", 0, f64(8.6), 2 << 9, 9, 0x80),
    ("down", "DPINT", 0, f64(-8.6), 3 << 9, -9, 0x80),
    ("tie-even", "DPINT", 0, f64(2.5), 0, 2, 0x80),
    ("tie-odd", "DPINT", 0, f64(3.5), 0, 4, 0x80),
    ("negative-tie-even", "DPINT", 0, f64(-2.5), 0, -2, 0x80),
    ("truncate", "DPTRUNC", 0, f64(8.6), 0, 8, 0x80),
    ("nan", "DPINT", 0, 0x7ff8000000000000, 0, 0x7fffffff, 0x12),
    ("negative-nan", "DPINT", 0, 0xfff8000000000000, 0, 0x80000000, 0x12),
    ("infinity", "DPINT", 0, 0x7ff0000000000000, 0, 0x7fffffff, 0xc0),
    ("denormal", "DPINT", 0, 1, 0, 0, 0x88),
    ("positive-overflow", "DPINT", 0, f64(2147483648.0), 0, 0x7fffffff, 0xc0),
    ("negative-limit", "DPINT", 0, f64(-2147483648.0), 0, 0x80000000, 0),
    ("negative-overflow", "DPINT", 0, f64(-2147483648.5), 0, 0x80000000, 0xc0),
    ("unit-two", "DPINT", 1, f64(8.6), 0, 9, 0x80),
    ("unit-two-truncate", "DPTRUNC", 1, f64(8.6), 0, 8, 0x80),
]


def opcode(mnemonic, side):
    low = 0x118 if mnemonic == "DPINT" else 0x38
    return (2 << 23) | low | (side << 1)


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
                f"{index}\t{name}\t{mnemonic}\t{side}\t{raw:016x}\t"
                f"{fadcr:08x}\t{result & 0xffffffff:08x}\t"
                f"{expected_flags:08x}\n"
            )


if __name__ == "__main__":
    main()
