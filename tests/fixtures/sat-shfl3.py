#!/usr/bin/env python3
"""Build SAT and SHFL3 fixture cases. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# mnemonic, side, src1, src2, result, CSR.SAT, SSR
# SAT sources contain the architectural 40-bit value in a register pair.
CASES = [
    ("SAT", 2, 0, 0x0000001f3413539a, 0x7fffffff, 1, 2),
    ("SAT", 2, 0, 0x00000000a1907321, 0x7fffffff, 1, 2),
    ("SAT", 1, 0, 0x000000ff7fffffff, 0x80000000, 1, 1),
    ("SAT", 1, 0, 0x000000ff80000000, 0x80000000, 0, 0),
    ("SAT", 2, 0, 0x000000ffffffffff, 0xffffffff, 0, 0),
    ("SAT", 1, 0, 0x000000007fffffff, 0x7fffffff, 0, 0),
    ("SHFL3", 1, 0x87654321, 0x12345678, 0x00008c117e179306, 0, 0),
    ("SHFL3", 2, 0x00000000, 0x00000001, 0x0000000000000001, 0, 0),
    ("SHFL3", 1, 0x00000001, 0x00000000, 0x0000000000000002, 0, 0),
    ("SHFL3", 2, 0x00010000, 0x00000000, 0x0000000000000004, 0, 0),
    ("SHFL3", 1, 0xffffffff, 0x0000ffff, 0x0000ffffffffffff, 0, 0),
]


def opcode(mnemonic, side):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    prefix = f":{mnemonic}.L{side} "
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(prefix))
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    word |= 2 << 18  # src2 A3:A2 or B3:B2 for SAT; A2/B2 for SHFL3
    if mnemonic == "SAT":
        word |= 5 << 23  # destination A5/B5
    else:
        word |= 1 << 13  # src1 A1/B1
        word |= 2 << 24  # destination A5:A4/B5:B4
    return word


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (mnemonic, side, a, b, expected, sat, ssr) in enumerate(CASES):
            out.write(struct.pack(endian + "I", opcode(mnemonic, side)))
            out.write(bytes(28))
            bank = "A" if side == 1 else "B"
            src1 = "-" if mnemonic == "SAT" else f"{bank}1"
            src2 = f"{bank}3_{bank}2" if mnemonic == "SAT" else f"{bank}2"
            dst = f"{bank}5" if mnemonic == "SAT" else f"{bank}5_{bank}4"
            rows.write(f"{index}\t{mnemonic}.L{side}\t{src1}\t{src2}\t{dst}\t"
                       f"{a:x}\t{b:x}\t{expected:x}\t{sat}\t{ssr}\n")


if __name__ == "__main__":
    main()
