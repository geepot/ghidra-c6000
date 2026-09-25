#!/usr/bin/env python3
"""Build DPACK2/DPACKX2 paired-result fixtures. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# mnemonic, side, cross, src1, src2, expected register pair.
CASES = [
    ("DPACK2", 1, 0, 0x87654321, 0x12345678, 0x8765123443215678),
    ("DPACK2", 2, 0, 0x87654321, 0x12345678, 0x8765123443215678),
    ("DPACK2", 1, 1, 0x0001ffff, 0xffff0002, 0x0001ffffffff0002),
    ("DPACKX2", 1, 0, 0x87654321, 0x12345678, 0x5678876543211234),
    ("DPACKX2", 1, 1, 0x3fff8000, 0x40007777, 0x77773fff80004000),
    ("DPACKX2", 2, 1, 0x3fff8000, 0x40007777, 0x77773fff80004000),
]


def opcode(mnemonic, side, cross):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    prefix = f":{mnemonic}.L{side} "
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(prefix))
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    word |= 1 << 18  # src2 A1/B1
    word |= 1 << 24  # dst A3:A2/B3:B2
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
            src2_bank = other if cross else own
            rows.write(f"{index}\t{mnemonic}.L{side}\t{own}0\t{src2_bank}1\t"
                       f"{own}3_{own}2\t{a:x}\t{b:x}\t{expected:x}\t0\t0\n")


if __name__ == "__main__":
    main()
