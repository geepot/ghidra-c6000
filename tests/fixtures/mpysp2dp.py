#!/usr/bin/env python3
"""Generate MPYSP2DP results and FMCR cases. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


def product(left, right):
    a = struct.unpack(">f", left.to_bytes(4, "big"))[0]
    b = struct.unpack(">f", right.to_bytes(4, "big"))[0]
    return int.from_bytes(struct.pack(">d", a * b), "big")


# Inputs, expected double bits, FMCR warning bits.
CASES = [
    (0x3f800000, 0x3f800000, product(0x3f800000, 0x3f800000), 0),
    (0xc0200000, 0x4109999a, product(0xc0200000, 0x4109999a), 0),
    (0, 0xbf800000, 0x8000000000000000, 0),
    (0x80000000, 0xbf800000, 0, 0),
    (0x7f800000, 0xc0000000, 0xfff0000000000000, 0x20),
    (0xff800000, 0xff800000, 0x7ff0000000000000, 0x20),
    (0x7f800000, 0, 0x7fffffffffffffff, 0x10),
    (0xff800000, 0x80000000, 0x7fffffffffffffff, 0x10),
    (0x7f800000, 0x80000001, 0xffffffffffffffff, 0x18),
    (0x3f800000, 0x80000001, 0x8000000000000000, 0x88),
    (0x80000001, 0x3f800000, 0x8000000000000000, 0x84),
    (0x80000001, 0, 0x8000000000000000, 0x4),
    (0x00000001, 0x80000001, 0x8000000000000000, 0x8c),
    (0x7fc00001, 0x3f800000, 0x7fffffffffffffff, 0x1),
    (0x3f800000, 0xffc00001, 0xffffffffffffffff, 0x2),
    (0x7f800001, 0x3f800000, 0x7fffffffffffffff, 0x11),
    (0x7fc00001, 0x7f800001, 0x7fffffffffffffff, 0x13),
    (0x7fc00001, 0x00000001, 0x7fffffffffffffff, 0x9),
]


def opcode(side, cross):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(f":MPYSP2DP.M{side} "))
    fixed = {int(bit): int(value) for bit, value in re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    return word | (1 << 13) | (2 << 18) | (2 << 24) | (int(cross) << 12)


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        index = 0
        for side in (1, 2):
            bank = "A" if side == 1 else "B"
            other = "B" if side == 1 else "A"
            for case_index, (left, right, expected, flags) in enumerate(CASES):
                cross = case_index == 1
                out.write(struct.pack(endian + "I", opcode(side, cross)))
                out.write(bytes(28))
                preset = 0x200
                expectedFlags = preset | flags
                if side == 2:
                    preset <<= 16
                    expectedFlags <<= 16
                rows.write(f"{index}\tMPYSP2DP.M{side}\t{bank}1\t"
                           f"{other if cross else bank}2\t{bank}5_{bank}4\t"
                           f"{left:x}\t{right:x}\t{expected:x}\t"
                           f"{preset:x}\t{expectedFlags:x}\n")
                index += 1


if __name__ == "__main__":
    main()
