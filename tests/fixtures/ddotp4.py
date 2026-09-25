#!/usr/bin/env python3
"""Build DDOTP4 signed halfword-by-byte fixtures. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# side, cross path, signed halfword pair, signed byte quartet, result pair
# The first two cases are SPRUFE8B's worked examples.
CASES = [
    (1, 0, 0x00050003, 0x01020304, 0x0000000B0000001B),
    (1, 1, 0x80008000, 0x80807F7F, 0x00800000FF810000),
    (2, 0, 0x0001FFFF, 0xFF01FE02, 0xFFFFFFFEFFFFFFFC),
    (2, 1, 0x7FFF8000, 0x80FF017F, 0xFFC08080FFC0FFFF),
]


def opcode(side, cross):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    prefix = f":DDOTP4.M{side} "
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(prefix))
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    word |= 1 << 13  # src1
    word |= 2 << 18  # src2
    word |= 2 << 24  # destination A5:A4 / B5:B4
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
            rows.write(f"{index}\tDDOTP4.M{side}\t{own}1\t"
                       f"{other if cross else own}2\t{own}5_{own}4\t"
                       f"{a:08x}\t{b:08x}\t{expected:016x}\n")


if __name__ == "__main__":
    main()
