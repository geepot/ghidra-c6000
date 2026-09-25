#!/usr/bin/env python3
"""Build DOTP2 full-width signed dot product fixtures. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# side, cross path, source 1, source 2, expected full-width result
CASES = [
    (1, 0, 0x6A321193, 0xB1746CA4, 0xFFFFFFFFE6DFF6D4),
    (2, 1, 0x12343497, 0x21FF50A7, 0x0000000012FC544D),
    (1, 1, 0x80008000, 0x80008000, 0x0000000080000000),
    (2, 0, 0x80007FFF, 0x7FFF8000, 0xFFFFFFFF80010000),
]


def opcode(side, cross):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    prefix = f":DOTP2.M{side} "
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(prefix) and "DstPair" in line)
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    word |= 1 << 13
    word |= 2 << 18
    word |= 4 << 23
    word |= cross << 12
    return word


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (side, cross, a, b, expected) in enumerate(CASES):
            out.write(struct.pack(endian + "I", opcode(side, cross)))
            out.write(bytes(28))
            own, other = ("A", "B") if side == 1 else ("B", "A")
            rows.write(f"{index}\tDOTP2.M{side}\t{own}1\t"
                       f"{other if cross else own}2\t{own}5_{own}4\t"
                       f"{a:08x}\t{b:08x}\t{expected:016x}\n")


if __name__ == "__main__":
    main()
