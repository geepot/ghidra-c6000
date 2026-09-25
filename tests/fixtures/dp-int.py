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

# The TI assembler and older GNU tic6x assembler use different src1 fields
# for nonzero source pairs (binutils gas/15094). Both select the same pair.
PAIR_VARIANTS = [
    (("ti-pair4", "DPINT", 0, f64(8.6), 0, 9, 0x80), 4, False),
    (("gnu-pair4", "DPINT", 0, f64(8.6), 0, 9, 0x80), 4, True),
    (("ti-pair4-trunc", "DPTRUNC", 1, f64(8.6), 0, 8, 0x80), 4, False),
    (("gnu-pair4-trunc", "DPTRUNC", 1, f64(8.6), 0, 8, 0x80), 4, True),
    (("ti-pair4-dpsp", "DPSP", 0, f64(8.6), 0, 0x4109999a, 0), 4, False),
    (("gnu-pair4-dpsp", "DPSP", 0, f64(8.6), 0, 0x4109999a, 0), 4, True),
]


def opcode(mnemonic, side, pair_low=0, legacy=False):
    low = {"DPINT": 0x118, "DPTRUNC": 0x38, "DPSP": 0x138}[mnemonic]
    # src2 names the odd/high register; TI zeroes src1, while older GNU
    # tic6x put the even/low register there.
    return ((2 << 23) | ((pair_low + 1) << 18) |
            ((pair_low if legacy else 0) << 13) | low | (side << 1))


def main():
    image = Path(sys.argv[1])
    cases = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, cases.open("w") as manifest:
        variants = [(case, 0, False) for case in CASES] + PAIR_VARIANTS
        for index, (case, pair_low, legacy) in enumerate(variants):
            name, mnemonic, side, raw, fadcr, result, flags = case
            out.write(struct.pack(endian + "I", opcode(mnemonic, side, pair_low, legacy)))
            out.write(bytes(28))
            expected_flags = fadcr | (flags << (16 if side else 0))
            manifest.write(
                f"{index}\t{name}\t{mnemonic}\t{side}\t{raw:016x}\t"
                f"{fadcr:08x}\t{result & 0xffffffff:08x}\t"
                f"{expected_flags:08x}\t{pair_low}\n"
            )


if __name__ == "__main__":
    main()
