#!/usr/bin/env python3
"""Build MPY2IR/RPACK2/SMPY32 fixtures. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# mnemonic, side, cross, src1, src2, result, SAT, SSR
CASES = [
    ("MPY2IR", 2, 0, 0x80008001, 0x80000000, 0x7fffffff7fff0000, 1, 0x20),
    ("MPY2IR", 1, 1, 0x87654321, 0x12345678, 0xeed8e38f098c16c1, 0, 0),
    ("MPY2IR", 1, 0, 0, 0x7fffffff, 0, 0, 0),
    # SPRUFE8B's worked example prints FDBA for the upper halfword. Its
    # Execution rule and TI's compiler guide both specify a saturating left
    # shift, which yields FDB9 here. Keep this discrepancy visible.
    ("RPACK2", 1, 0, 0xfedcba98, 0x12345678, 0xfdb92468, 0, 0),
    ("RPACK2", 2, 1, 0x87654321, 0x12345678, 0x80002468, 1, 8),
    ("RPACK2", 1, 0, 0x40000000, 0xc0000000, 0x7fff8000, 1, 4),
    ("SMPY32", 1, 0, 0x87654321, 0x12345678, 0xeed8ed1a, 0, 0),
    ("SMPY32", 2, 0, 0x80000000, 0x80000000, 0x7fffffff, 1, 0x20),
    ("SMPY32", 1, 1, 0xffffffff, 0x7fffffff, 0xffffffff, 0, 0),
]


def opcode(mnemonic, side, cross):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    unit = "S" if mnemonic == "RPACK2" else "M"
    prefix = f":{mnemonic}.{unit}{side} "
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(prefix))
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    word |= 1 << 13  # src1
    word |= 2 << 18  # src2
    word |= (2 << 24) if mnemonic == "MPY2IR" else (3 << 23)
    word |= cross << 12
    return word, unit


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (mnemonic, side, cross, a, b, result, sat, ssr) in enumerate(CASES):
            word, unit = opcode(mnemonic, side, cross)
            out.write(struct.pack(endian + "I", word))
            out.write(bytes(28))
            own, other = ("A", "B") if side == 1 else ("B", "A")
            src2 = f"{other if cross else own}2"
            dst = f"{own}5_{own}4" if mnemonic == "MPY2IR" else f"{own}3"
            rows.write(f"{index}\t{mnemonic}.{unit}{side}\t{own}1\t{src2}\t{dst}\t"
                       f"{a:x}\t{b:x}\t{result:x}\t{sat}\t{ssr}\n")


if __name__ == "__main__":
    main()
