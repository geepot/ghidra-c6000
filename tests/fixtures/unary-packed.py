#!/usr/bin/env python3
"""Build packed unary and bit permutation cases. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# mnemonic, side, input bits, output bits, FAUCR warning bits, preset CSR.SAT
CASES = [
    ("ABS2", 1, 0xff684e3d, 0x00984e3d, 0, 1),
    ("ABS2", 2, 0x3ff6f105, 0x3ff60efb, 0, 0),
    ("ABS2", 1, 0x80008000, 0x7fff7fff, 0, 1),
    ("ABS2", 2, 0xffff0001, 0x00010001, 0, 1),
    ("BITC4", 1, 0x9e526e30, 0x05030502, 0, 0),
    ("BITC4", 2, 0xffffffff, 0x08080808, 0, 0),
    ("BITC4", 1, 0x00000000, 0x00000000, 0, 0),
    ("BITR", 2, 0xa6e2c179, 0x9e834765, 0, 0),
    ("BITR", 1, 0x80000001, 0x80000001, 0, 0),
    ("BITR", 2, 0x0000000f, 0xf0000000, 0, 0),
    ("DEAL", 1, 0x9e526e30, 0xb1746ca4, 0, 0),
    ("DEAL", 2, 0x55555555, 0x0000ffff, 0, 0),
    ("SHFL", 1, 0xb1746ca4, 0x9e526e30, 0, 0),
    ("SHFL", 2, 0x0000ffff, 0x55555555, 0, 0),
    ("SWAP4", 1, 0x9e526e30, 0x529e306e, 0, 0),
    ("SWAP4", 2, 0x11223344, 0x22114433, 0, 0),
    ("UNPKHU4", 1, 0x9e526e30, 0x009e0052, 0, 0),
    ("UNPKHU4", 2, 0x11056934, 0x00110005, 0, 0),
    ("ABSDP", 1, 0xc004000000000000, 0x4004000000000000, 0, 0),
    ("ABSDP", 2, 0x8000000000000000, 0x0000000000000000, 0, 0),
    ("ABSDP", 1, 0xfff0000000000000, 0x7ff0000000000000, 0x20, 0),
    ("ABSDP", 2, 0x8000000000000001, 0x0000000000000000, 0x88, 0),
    ("ABSDP", 1, 0x7ff8000000000001, 0x7fffffffffffffff, 0x2, 0),
    ("ABSDP", 2, 0xfff0000000000001, 0x7fffffffffffffff, 0x12, 0),
    ("ABSSP", 1, 0xc0200000, 0x40200000, 0, 0),
    ("ABSSP", 2, 0x80000000, 0x00000000, 0, 0),
    ("ABSSP", 1, 0xff800000, 0x7f800000, 0x20, 0),
    ("ABSSP", 2, 0x80000001, 0x00000000, 0x88, 0),
    ("ABSSP", 1, 0x7fc00001, 0x7fffffff, 0x2, 0),
    ("ABSSP", 2, 0xff800001, 0x7fffffff, 0x12, 0),
    ("SPDP", 1, 0x4109999a, 0x4021333340000000, 0, 0),
    ("SPDP", 2, 0x80000000, 0x8000000000000000, 0, 0),
    ("SPDP", 1, 0xff800000, 0xfff0000000000000, 0x20, 0),
    ("SPDP", 2, 0x80000001, 0x8000000000000000, 0x88, 0),
    ("SPDP", 1, 0x7fc00001, 0x7fffffffffffffff, 0x2, 0),
    ("SPDP", 2, 0xff800001, 0x7fffffffffffffff, 0x12, 0),
    ("SPDP", 1, 0x4109999a, 0x4021333340000000, 0, 0, 1),
]


def opcode(mnemonic, side, cross=False):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    unit = "L" if mnemonic in {"ABS2", "SWAP4", "UNPKHU4"} else "S" if mnemonic in {"ABSDP", "ABSSP", "SPDP"} else "M"
    prefix = f":{mnemonic}.{unit}{side} "
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(prefix))
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    if cross:
        word |= 1 << 12
    word |= 2 << 18  # src2 A2/B2 or A3:A2/B3:B2
    word |= (2 << 24) if mnemonic in {"ABSDP", "SPDP"} else (4 << 23)
    return word, unit


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, case in enumerate(CASES):
            mnemonic, side, value, expected, flags, sat = case[:6]
            cross = len(case) > 6 and bool(case[6])
            word, unit = opcode(mnemonic, side, cross)
            out.write(struct.pack(endian + "I", word))
            out.write(bytes(28))
            bank = "A" if side == 1 else "B"
            srcbank = ("B" if bank == "A" else "A") if cross else bank
            src = f"{bank}3_{bank}2" if mnemonic == "ABSDP" else f"{srcbank}2"
            dst = f"{bank}5_{bank}4" if mnemonic in {"ABSDP", "SPDP"} else f"{bank}4"
            rows.write(f"{index}\t{mnemonic}.{unit}{side}\t{src}\t{dst}\t"
                       f"{value:x}\t{expected:x}\t"
                       f"{flags << (16 if side == 2 else 0):x}\t{sat}\n")


if __name__ == "__main__":
    main()
