#!/usr/bin/env python3
"""Generate MPYSP rounding and FMCR cases. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# SP operands, expected SP bits for RMODE=nearest/zero/+inf/-inf, warning bits.
CASES = [
    (0x3f800000, 0x3f800000, (0x3f800000,) * 4, 0),
    (0xc0200000, 0x4109999a, (0xc1ac0000, 0xc1ac0000, 0xc1ac0000, 0xc1ac0001), 0x80),
    (0x3f800001, 0x3f800001, (0x3f800002, 0x3f800002, 0x3f800003, 0x3f800002), 0x80),
    (0x7f7fffff, 0x40000000, (0x7f800000, 0x7f7fffff, 0x7f800000, 0x7f7fffff), 0xc0),
    (0xff7fffff, 0x40000000, (0xff800000, 0xff7fffff, 0xff7fffff, 0xff800000), 0xc0),
    (0x00800000, 0x3f000000, (0, 0, 0x00800000, 0), 0x180),
    (0x80800000, 0x3f000000, (0x80000000, 0x80000000, 0x80000000, 0x80800000), 0x180),
    (0x7f800000, 0xc0000000, (0xff800000,) * 4, 0x20),
    (0x7f800000, 0, (0x7fffffff,) * 4, 0x10),
    (0x7fc00001, 0x3f800000, (0x7fffffff,) * 4, 0x1),
    (0xbf800000, 0x7f800001, (0xffffffff,) * 4, 0x12),
    (0x00000001, 0x3f800000, (0,) * 4, 0x84),
    (0x3f800000, 0x80000001, (0x80000000,) * 4, 0x88),
    (0x00000001, 0x80000001, (0x80000000,) * 4, 0x8c),
    (0x80000000, 0xbf800000, (0,) * 4, 0),
]


def opcode(side, cross):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(f":MPYSP.M{side} "))
    fixed = {int(bit): int(value) for bit, value in re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    return word | (1 << 13) | (2 << 18) | (4 << 23) | (int(cross) << 12)


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        index = 0
        for side in (1, 2):
            bank = "A" if side == 1 else "B"
            other = "B" if side == 1 else "A"
            for mode in range(4):
                for case_index, (left, right, outputs, flags) in enumerate(CASES):
                    cross = case_index == 1
                    out.write(struct.pack(endian + "I", opcode(side, cross)))
                    out.write(bytes(28))
                    preset = (mode << 9) | 4
                    expectedFlags = preset | flags
                    if side == 1:
                        preset |= 0x10000
                        expectedFlags |= 0x10000
                    else:
                        preset = (preset << 16) | 1
                        expectedFlags = (expectedFlags << 16) | 1
                    rows.write(f"{index}\tMPYSP.M{side}\t{bank}1\t"
                               f"{other if cross else bank}2\t{bank}4\t"
                               f"{left:x}\t{right:x}\t{outputs[mode]:x}\t"
                               f"{preset:x}\t{expectedFlags:x}\n")
                    index += 1


if __name__ == "__main__":
    main()
