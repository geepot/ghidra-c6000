#!/usr/bin/env python3
"""Build independent-value tests for packed arithmetic and comparisons.

Usage: packed-arith.py IMAGE CASES.tsv [be]
"""
import re
import struct
import sys
from pathlib import Path


CASES = [
    ("ADD2", "L", 0x7FFFFFFF, 0x00010001, 0x80000000),
    ("ADD4", "L", 0xFF00FF00, 0x01020103, 0x00020003),
    ("SUB2", "L", 0x80000000, 0x00010001, 0x7FFFFFFF),
    ("SUB4", "L", 0x00000000, 0x01020304, 0xFFFEFDFC),
    ("CMPEQ2", "S", 0x11112222, 0x11113333, 0x00000002),
    ("CMPEQ4", "S", 0x10203040, 0x10223340, 0x00000009),
    ("CMPGT2", "S", 0x80017FFF, 0x7FFF8000, 0x00000001),
    ("CMPGTU4", "S", 0x807F00FF, 0x7F800001, 0x00000009),
    ("MIN2", "L", 0x80017FFF, 0x7FFF8000, 0x80018000),
    ("MAX2", "L", 0x80017FFF, 0x7FFF8000, 0x7FFF7FFF),
    ("MINU4", "L", 0x807F00FF, 0x7F800001, 0x7F7F0001),
    ("MAXU4", "L", 0x807F00FF, 0x7F800001, 0x808000FF),
    ("AVG2", "M", 0x7FFF8000, 0x7FFF8001, 0x7FFF8001),
    ("AVGU4", "M", 0xFF00FF00, 0xFF010201, 0xFF018101),
    ("SMPYH", "M", 0x40000000, 0x40000000, 0x20000000),
    ("SMPYH", "M", 0x80000000, 0x80000000, 0x7FFFFFFF),
    ("SHLMB", "L", 0x3789F23A, 0x04B84975, 0xB8497537),
    ("SHLMB", "S", 0x01242451, 0x01A6A051, 0xA6A05101),
    ("SHRMB", "L", 0x3789F23A, 0x04B84975, 0x3A04B849),
    ("SHRMB", "S", 0x01242451, 0x01A6A051, 0x5101A6A0),
]


def opcode(mnemonic, unit, side, cross):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    prefix = f":{mnemonic}.{unit}{side} "
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(prefix))
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    word |= 1 << 13  # src1 = A1 or B1
    word |= 2 << 18  # src2 = A2/B2, according to x
    word |= 3 << 23  # dst = A3 or B3
    word |= cross << 12
    return word


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        index = 0
        for mnemonic, unit, a, b, expected in CASES:
            for side, cross in ((1, 0), (2, 1)):
                out.write(struct.pack(endian + "I", opcode(mnemonic, unit, side, cross)))
                out.write(bytes(28))
                rows.write(f"{index}\t{mnemonic}\t{unit}{side}\t{a:08x}\t"
                           f"{b:08x}\t{expected:08x}\t"
                           f"{int(mnemonic == 'SMPYH' and a == 0x80000000)}\n")
                index += 1


if __name__ == "__main__":
    main()
