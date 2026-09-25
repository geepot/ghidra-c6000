#!/usr/bin/env python3
"""Build CMPYR/CMPYR1 signed rounding fixtures. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# mnemonic, side, cross, src1, src2, packed result, CSR.SAT, SSR.M1/M2
# All eight are worked examples in SPRUFE8B.
CASES = [
    ("CMPYR", 1, 0, 0x08000400, 0x09000200, 0x00400034, 0, 0),
    ("CMPYR", 2, 1, 0x7FFF7FFF, 0x7FFF8000, 0x7FFF0000, 0, 0),
    ("CMPYR", 1, 0, 0x80008000, 0x80008000, 0x00007FFF, 1, 0x10),
    ("CMPYR", 2, 0, 0x80008000, 0x80008001, 0x00017FFF, 1, 0x20),
    ("CMPYR1", 1, 0, 0x08000400, 0x09000200, 0x00800068, 0, 0),
    ("CMPYR1", 2, 1, 0x7FFF7FFF, 0x7FFF8000, 0x7FFFFFFF, 1, 0x20),
    ("CMPYR1", 1, 0, 0x80008000, 0x80008000, 0x00007FFF, 1, 0x10),
    ("CMPYR1", 2, 0, 0xC000C000, 0x80008001, 0x00017FFF, 1, 0x20),
]


def opcode(mnemonic, side, cross):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    prefix = f":{mnemonic}.M{side} "
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(prefix))
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    word |= 1 << 13  # src1
    word |= 2 << 18  # src2
    word |= 3 << 23  # dst
    word |= cross << 12
    return word


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (mnemonic, side, cross, a, b, result, sat, ssr) in enumerate(CASES):
            out.write(struct.pack(endian + "I", opcode(mnemonic, side, cross)))
            out.write(bytes(28))
            own, other = ("A", "B") if side == 1 else ("B", "A")
            rows.write(f"{index}\t{mnemonic}.M{side}\t{own}1\t"
                       f"{other if cross else own}2\t{own}3\t"
                       f"{a:08x}\t{b:08x}\t{result:08x}\t{sat}\t{ssr}\n")


if __name__ == "__main__":
    main()
