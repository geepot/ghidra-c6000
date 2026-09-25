#!/usr/bin/env python3
"""Build GMPY/XORMPY word-multiply cases. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# mnemonic, side, cross-path, src1, src2, GPLYA, GPLYB, expected.
# The first and fourth results are published SPRUFE8B examples; the remaining
# cases check side selection, ignored high multiplier bits, and identities.
CASES = [
    ("GMPY", 1, 0, 0x12345678, 0x126, 0x87654321, 0, 0xc721a0ef),
    ("GMPY", 2, 0, 0x12345678, 0x126, 0, 0x87654321, 0xc721a0ef),
    ("GMPY", 2, 1, 0x12345678, 0x126, 0x87654321, 0, 0x1e654210),
    ("XORMPY", 1, 0, 0x12345678, 0x126, 0xffffffff, 0, 0x1e654210),
    ("XORMPY", 2, 1, 0x12345678, 0x126, 0, 0xffffffff, 0x1e654210),
    ("GMPY", 1, 0, 0x12345678, 0xffff0126, 0x87654321, 0, 0xc721a0ef),
    ("GMPY", 2, 0, 0xdeadbeef, 1, 0, 0xabcdef01, 0xdeadbeef),
    ("XORMPY", 1, 0, 0xdeadbeef, 0, 0xffffffff, 0, 0),
    ("GMPY", 1, 1, 0, 0x1ff, 0xffffffff, 0, 0),
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
        for index, (mnemonic, side, cross, a, b, poly_a, poly_b, expected) in enumerate(CASES):
            out.write(struct.pack(endian + "I", opcode(mnemonic, side, cross)))
            out.write(bytes(28))
            own, other = ("A", "B") if side == 1 else ("B", "A")
            rows.write(f"{index}\t{mnemonic}.M{side}\t{own}1\t"
                       f"{other if cross else own}2\t{own}3\t"
                       f"{a:x}\t{b:x}\t{expected:x}\t0\t0\t0\t"
                       f"{poly_a:x}\t{poly_b:x}\n")


if __name__ == "__main__":
    main()
