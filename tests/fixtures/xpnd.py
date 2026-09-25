#!/usr/bin/env python3
"""Build XPND2/XPND4 bit-mask expansion fixtures. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# mnemonic, side, cross path, input, expected mask
CASES = [
    ("XPND2", 1, 0, 0xB1746CA1, 0x0000FFFF),
    ("XPND2", 2, 1, 0x00000003, 0xFFFFFFFF),
    ("XPND2", 1, 1, 0xFFFFFFFC, 0x00000000),
    ("XPND4", 1, 0, 0xB1746CA4, 0x00FF0000),
    ("XPND4", 2, 1, 0x00000009, 0xFF0000FF),
    ("XPND4", 1, 1, 0x0000000F, 0xFFFFFFFF),
    ("XPND4", 2, 0, 0x00000010, 0x00000000),
]


def opcode(mnemonic, side, cross):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    prefix = f":{mnemonic}.M{side} "
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(prefix))
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    word |= 2 << 18
    word |= 3 << 23
    word |= cross << 12
    return word


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (mnemonic, side, cross, value, expected) in enumerate(CASES):
            out.write(struct.pack(endian + "I", opcode(mnemonic, side, cross)))
            out.write(bytes(28))
            own, other = ("A", "B") if side == 1 else ("B", "A")
            rows.write(f"{index}\t{mnemonic}.M{side}\t"
                       f"{other if cross else own}2\t-\t{own}3\t"
                       f"{value:08x}\t00000000\t{expected:08x}\n")


if __name__ == "__main__":
    main()
