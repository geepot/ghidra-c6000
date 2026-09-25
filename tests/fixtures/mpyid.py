#!/usr/bin/env python3
"""Build MPYID register and signed-constant fixtures. Usage: IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


CASES = [
    ("negative", 1, False, -0x80000000, 2),
    ("cross", 2, False, 0x7fffffff, 0x7fffffff),
    ("constant", 1, True, -3, 123456789),
    ("constant-cross", 2, True, -3, -123456789),
]


def opcode(side, immediate):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    prefix = f":MPYID.M{side} " + ("SCst5," if immediate else "Src1,")
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(prefix))
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    word |= ((-3 & 31) if immediate else 1) << 13
    word |= 2 << 18
    word |= 4 << 23
    word |= (side == 2) << 12
    return word


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (name, side, immediate, a, b) in enumerate(CASES):
            out.write(struct.pack(endian + "I", opcode(side, immediate)))
            out.write(bytes(28))
            expected = (a * b) & 0xffffffffffffffff
            rows.write(f"{index}\t{name}\t{side}\t{int(immediate)}\t"
                       f"{a & 0xffffffff:08x}\t{b & 0xffffffff:08x}\t"
                       f"{expected:016x}\n")


if __name__ == "__main__":
    main()
