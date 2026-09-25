#!/usr/bin/env python3
"""Build scalar and 40-bit unary operand-form cases. IMAGE CASES.tsv [be]."""

from pathlib import Path
import re
import struct
import sys


# mnemonic, side, pair operands, source bits, expected bits, saturation
CASES = [
    ("ABS", 1, False, 0x80000000, 0x7fffffff, True),
    ("ABS", 2, True, 0x1234568000000000, 0x7fffffffff, True),
    ("ABS", 1, True, 0xffffffefffffffff, 0x1000000001, False),
    ("NEG", 1, True, 0xffffff0000000001, 0xffffffffff, False),
    ("NEG", 2, True, 0x0000008000000000, 0x8000000000, False),
    ("MV", 1, True, 0xdeadbe0123456789, 0x0123456789, False),
    ("MV", 2, True, 0x123456ffffffffff, 0xffffffffff, False),
]


def word(mnemonic, side, pair, src=2, dst=4, x=0):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    spelling = f'"{mnemonic}.L{side}"'
    line = next(line for line in decode.read_text().splitlines()
                if spelling in line and ("DstPair" in line) == pair)
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    return (sum(value << bit for bit, value in fixed.items()) |
            (src << 18) | (dst << 23) | (x << 12))


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (mnemonic, side, pair, source, expected, sat) in enumerate(CASES):
            out.write(struct.pack(endian + "I", word(mnemonic, side, pair)) + bytes(28))
            bank = "A" if side == 1 else "B"
            src = f"{bank}3_{bank}2" if pair else f"{bank}2"
            dst = f"{bank}5_{bank}4" if pair else f"{bank}4"
            rows.write(f"{index}\t{mnemonic}.L{side}\t{src}\t{dst}\t"
                       f"{source:016x}\t{expected:016x}\t{int(sat)}\t"
                       f"{1 if side == 1 else 2}\n")
        invalid = [
            word("ABS", 1, True, src=3),
            word("ABS", 2, True, dst=5),
            word("NEG", 1, True, x=1),
            word("NEG", 2, True, src=3),
            word("MV", 1, True, src=3),
            word("MV", 2, True, dst=5),
            word("SAT", 2, False, x=1),
        ]
        for opcode in invalid:
            index += 1
            out.write(struct.pack(endian + "I", opcode) + bytes(28))
            rows.write(f"{index}\t-\t-\t-\t0\t0\t0\t0\n")


if __name__ == "__main__":
    main()
