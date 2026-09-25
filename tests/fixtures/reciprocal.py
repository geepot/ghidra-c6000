#!/usr/bin/env python3
"""Build RCPSP/RSQRSP/RCPDP/RSQRDP examples. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# mnemonic, side, source bits, expected result bits, FAUCR warning bits.
# The ordinary outputs include SPRUFE8B's 4.0 and 8.6 examples. The special
# outputs/status values follow each instruction's numbered NOTE clauses.
CASES = [
    ("RCPSP", 1, 0x40800000, 0x3e800000, 0),
    ("RCPSP", 2, 0xc0800000, 0xbe800000, 0),
    ("RSQRSP", 1, 0x40800000, 0x3f000000, 0),
    ("RSQRSP", 2, 0x4109999a, 0x3eae8000, 0),
    ("RCPDP", 1, 0x4010000000000000, 0x3fd0000000000000, 0),
    ("RSQRDP", 2, 0x4010000000000000, 0x3fe0000000000000, 0),
    ("RCPSP", 1, 0x00000000, 0x7f800000, 0x420),
    ("RCPSP", 2, 0x80000000, 0xff800000, 0x420),
    ("RSQRSP", 1, 0x80000000, 0xff800000, 0x420),
    ("RSQRSP", 2, 0x00000001, 0x7f800000, 0x488),
    ("RCPSP", 1, 0x80000001, 0xff800000, 0x4e8),
    ("RCPSP", 2, 0x7f800000, 0x00000000, 0),
    ("RSQRSP", 1, 0x7f800000, 0x00000000, 0),
    ("RSQRSP", 2, 0xff800000, 0x7fffffff, 0x10),
    ("RSQRSP", 1, 0xbf800000, 0x7fffffff, 0x10),
    ("RCPSP", 2, 0x7fc00001, 0x7fffffff, 0x2),
    ("RSQRSP", 1, 0x7f800001, 0x7fffffff, 0x12),
    ("RCPSP", 1, 0x7e800001, 0x00000000, 0x180),
    ("RCPDP", 2, 0x0000000000000000, 0x7ff0000000000000, 0x420),
    ("RCPDP", 1, 0x8000000000000001, 0xfff0000000000000, 0x4e8),
    ("RSQRDP", 1, 0xbff0000000000000, 0x7fffffffffffffff, 0x10),
    ("RSQRDP", 2, 0x7ff8000000000001, 0x7fffffffffffffff, 0x2),
    ("RCPDP", 2, 0x7ff0000000000001, 0x7fffffffffffffff, 0x12),
    ("RCPDP", 1, 0x7fd0000000000001, 0x0000000000000000, 0x180),
]


def opcode(mnemonic, side):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    prefix = f":{mnemonic}.S{side} "
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(prefix))
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    word |= 2 << 18  # SP src2 A2/B2, DP src2 A3:A2/B3:B2
    word |= (2 << 24) if mnemonic.endswith("DP") else (4 << 23)
    return word


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (mnemonic, side, value, expected, flags) in enumerate(CASES):
            out.write(struct.pack(endian + "I", opcode(mnemonic, side)))
            out.write(bytes(28))
            bank = "A" if side == 1 else "B"
            pair = mnemonic.endswith("DP")
            src = f"{bank}3_{bank}2" if pair else f"{bank}2"
            dst = f"{bank}5_{bank}4" if pair else f"{bank}4"
            rows.write(f"{index}\t{mnemonic}.S{side}\t{src}\t{dst}\t"
                       f"{value:x}\t{expected:x}\t{flags << (16 if side == 2 else 0):x}\n")


if __name__ == "__main__":
    main()
