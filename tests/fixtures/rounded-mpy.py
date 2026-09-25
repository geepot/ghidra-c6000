#!/usr/bin/env python3
"""Build MPYHIR/MPYILR rounding fixtures. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# mnemonic, side, cross path, encoded src1, encoded src2, expected 32-bit result
# The first case of each mnemonic is SPRUFE8B's worked example. The remaining
# cases exercise signed boundaries and the +0x4000 rounding tie.
CASES = [
    ("MPYHIR", 2, 0, 0x12343497, 0x21FF50A7, 0x04D5B710),
    ("MPYHIR", 1, 1, 0x80000000, 0x7FFFFFFF, 0x80000001),
    ("MPYHIR", 2, 1, 0x7FFF0000, 0x7FFFFFFF, 0x7FFEFFFF),
    ("MPYHIR", 1, 0, 0xFFFF0000, 0x00004000, 0x00000000),
    ("MPYILR", 2, 0, 0x12343497, 0x21FF50A7, 0x0DF7D3F5),
    ("MPYILR", 1, 1, 0x00008000, 0x7FFFFFFF, 0x80000001),
    ("MPYILR", 2, 1, 0x00007FFF, 0x80000000, 0x80010000),
    ("MPYILR", 1, 0, 0x0000FFFF, 0x00004000, 0x00000000),
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
        for index, (mnemonic, side, cross, src1, src2, expected) in enumerate(CASES):
            out.write(struct.pack(endian + "I", opcode(mnemonic, side, cross)))
            out.write(bytes(28))
            own, other = ("A", "B") if side == 1 else ("B", "A")
            if mnemonic == "MPYILR":
                first, second = f"{other if cross else own}2", f"{own}1"
                first_value, second_value = src2, src1
            else:
                first, second = f"{own}1", f"{other if cross else own}2"
                first_value, second_value = src1, src2
            rows.write(f"{index}\t{mnemonic}.M{side}\t{first}\t{second}\t{own}3\t"
                       f"{first_value:08x}\t{second_value:08x}\t{expected:08x}\n")


if __name__ == "__main__":
    main()
