#!/usr/bin/env python3
"""Build MPYSU4/MPYU4 packed byte-product fixtures. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# mnemonic, side, cross path, source 1, source 2, expected 64-bit result
CASES = [
    ("MPYSU4", 1, 0, 0x6A321193, 0xB1746CA4, 0x494A16A8072CBA2C),
    ("MPYSU4", 2, 1, 0x80808080, 0xFFFFFFFF, 0x8080808080808080),
    ("MPYU4", 1, 1, 0x6832C193, 0xB1742CAB, 0x47E816A8212C6231),
    ("MPYU4", 2, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFE01FE01FE01FE01),
]


def opcode(mnemonic, side, cross):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    prefix = f":{mnemonic}.M{side} "
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
        for index, (mnemonic, side, cross, a, b, expected) in enumerate(CASES):
            out.write(struct.pack(endian + "I", opcode(mnemonic, side, cross)))
            out.write(bytes(28))
            own, other = ("A", "B") if side == 1 else ("B", "A")
            rows.write(f"{index}\t{mnemonic}.M{side}\t{own}1\t"
                       f"{other if cross else own}2\t{own}5_{own}4\t"
                       f"{a:08x}\t{b:08x}\t{expected:016x}\n")


if __name__ == "__main__":
    main()
