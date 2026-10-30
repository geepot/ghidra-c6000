#!/usr/bin/env python3
"""Unconditional-only SMPY32/RPACK2 next to their predicated twins MPY32US/DMV.
IMAGE CASES.tsv [be].

SPRUFE8B 3.6 Table 3-9 reserves creg=0 with z=1; SMPY32 and RPACK2 use it as fixed
bits 31:28 and share their other opcode bits with MPY32US and DMV.
"""
import re
import struct
import sys
from pathlib import Path

PREDICATES = {"": (0, 0), "[B0]": (1, 0), "[!B0]": (1, 1), "[!A0]": (6, 1), "[A1]": (4, 0)}
UNIT = {"SMPY32": "M", "MPY32US": "M", "RPACK2": "S", "DMV": "S"}
PAIR = {"MPY32US", "DMV"}

# mnemonic, predicate, side, cross, dst, src1, src2, result, CSR.SAT, SSR
# Values follow tests/fixtures/remaining-arith.py. The shadowing only shows with
# an even dst, which the twin's register-pair destination can also encode.
CASES = [
    ("SMPY32", "", 1, 0, 4, 0x87654321, 0x12345678, 0xeed8ed1a, 0, 0),
    ("SMPY32", "", 2, 0, 4, 0x80000000, 0x80000000, 0x7fffffff, 1, 0x20),
    ("SMPY32", "", 1, 1, 8, 0xffffffff, 0x7fffffff, 0xffffffff, 0, 0),
    ("SMPY32", "", 2, 1, 3, 0x87654321, 0x12345678, 0xeed8ed1a, 0, 0),
    ("RPACK2", "", 1, 0, 4, 0xfedcba98, 0x12345678, 0xfdb92468, 0, 0),
    ("RPACK2", "", 2, 1, 8, 0x87654321, 0x12345678, 0x80002468, 1, 8),
    ("RPACK2", "", 1, 0, 3, 0x40000000, 0xc0000000, 0x7fff8000, 1, 4),
    ("MPY32US", "", 1, 0, 4, None, None, None, None, None),
    ("MPY32US", "", 2, 1, 4, None, None, None, None, None),
    ("MPY32US", "[B0]", 1, 0, 4, None, None, None, None, None),
    ("MPY32US", "[!B0]", 2, 0, 4, None, None, None, None, None),
    ("MPY32US", "[!A0]", 1, 1, 4, None, None, None, None, None),
    ("DMV", "", 1, 0, 4, None, None, None, None, None),
    ("DMV", "[A1]", 2, 1, 8, None, None, None, None, None),
    ("DMV", "[!B0]", 1, 0, 4, None, None, None, None, None),
]


def opcode(mnemonic, predicate, side, cross, dst):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    name = f"{mnemonic}.{UNIT[mnemonic]}{side}"
    prefix = f':^Cond^"{name}" ' if mnemonic in PAIR else f":{name} "
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(prefix))
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    if mnemonic in PAIR:
        creg, z = PREDICATES[predicate]
        word |= (creg << 29) | (z << 28)
    word |= 1 << 13  # src1
    word |= 2 << 18  # src2
    word |= dst << 23
    word |= cross << 12
    return word


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (mnemonic, predicate, side, cross, dst_reg, a, b, result, sat, ssr) in enumerate(CASES):
            out.write(struct.pack(endian + "I", opcode(mnemonic, predicate, side, cross, dst_reg)))
            out.write(bytes(28))
            own, other = ("A", "B") if side == 1 else ("B", "A")
            src2 = f"{other if cross else own}2"
            dst = (f"{own}{dst_reg + 1}:{own}{dst_reg}" if mnemonic in PAIR
                   else f"{own}{dst_reg}")
            text = f"{predicate}{mnemonic}.{UNIT[mnemonic]}{side} {own}1,{src2},{dst}"
            values = "-\t-\t-\t-\t-" if a is None else f"{a:x}\t{b:x}\t{result:x}\t{sat}\t{ssr}"
            rows.write(f"{index}\t{text}\t{own}1\t{src2}\t{dst}\t{values}\n")


if __name__ == "__main__":
    main()
