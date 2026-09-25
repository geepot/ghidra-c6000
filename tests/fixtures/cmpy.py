#!/usr/bin/env python3
"""Build CMPY signed complex multiplication fixtures. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# side, cross, src1, src2, pair result, CSR.SAT, SSR.M1/M2
# The first three outputs are from SPRUFE8B. The saturation flag in its third
# example conflicts with the instruction description; the flag expectation
# here follows the stated rule that saturating instructions set CSR/SSR.
CASES = [
    (1, 0, 0x00080004, 0x00090002, 0x0000004000000034, 0, 0),
    (2, 1, 0x7FFF7FFF, 0x7FFF8000, 0x7FFE8001FFFF8001, 0, 0),
    (1, 0, 0x80008000, 0x80008000, 0x000000007FFFFFFF, 1, 0x10),
    (2, 1, 0x80008000, 0x80008000, 0x000000007FFFFFFF, 1, 0x20),
    (2, 0, 0xFFFF8000, 0x00010002, 0x0000FFFFFFFF7FFE, 0, 0),
]


def opcode(side, cross):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    prefix = f":CMPY.M{side} "
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(prefix))
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    word |= 1 << 13  # src1
    word |= 2 << 18  # src2
    word |= 2 << 24  # pair destination A5:A4/B5:B4
    word |= cross << 12
    return word


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (side, cross, a, b, result, sat, ssr) in enumerate(CASES):
            out.write(struct.pack(endian + "I", opcode(side, cross)))
            out.write(bytes(28))
            own, other = ("A", "B") if side == 1 else ("B", "A")
            rows.write(f"{index}\tCMPY.M{side}\t{own}1\t"
                       f"{other if cross else own}2\t{own}5_{own}4\t"
                       f"{a:08x}\t{b:08x}\t{result:016x}\t{sat}\t{ssr}\n")


if __name__ == "__main__":
    main()
