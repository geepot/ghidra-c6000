#!/usr/bin/env python3
"""Generate DPSP rounding and FADCR cases. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# Source bits, expected SP bits for RMODE=nearest/zero/+inf/-inf, warning bits.
CASES = [
    (0x3ff0000000000000, (0x3f800000,) * 4, 0),
    (0x4021333333333333, (0x4109999a, 0x41099999, 0x4109999a, 0x41099999), 0x80),
    (0xc021333333333333, (0xc109999a, 0xc1099999, 0xc1099999, 0xc109999a), 0x80),
    (0x3ff0000010000000, (0x3f800000, 0x3f800000, 0x3f800001, 0x3f800000), 0x80),
    (0xbff0000010000000, (0xbf800000, 0xbf800000, 0xbf800000, 0xbf800001), 0x80),
    (0x47efffffe0000000, (0x7f7fffff,) * 4, 0),
    (0x47efffffdfffffff, (0x7f7fffff, 0x7f7ffffe, 0x7f7fffff, 0x7f7ffffe), 0x80),
    (0x3810000000000000, (0x00800000,) * 4, 0),
    (0x3810000000000001, (0x00800000, 0x00800000, 0x00800001, 0x00800000), 0x80),
    (0x47f0000000000000, (0x7f800000, 0x7f7fffff, 0x7f800000, 0x7f7fffff), 0xc0),
    (0xc7f0000000000000, (0xff800000, 0xff7fffff, 0xff7fffff, 0xff800000), 0xc0),
    (0x3800000000000000, (0, 0, 0x00800000, 0), 0x180),
    (0xb800000000000000, (0x80000000, 0x80000000, 0x80000000, 0x80800000), 0x180),
    (0x0000000000000001, (0,) * 4, 0x88),
    (0x8000000000000001, (0x80000000,) * 4, 0x88),
    (0x7ff0000000000000, (0x7f800000,) * 4, 0x20),
    (0xfff0000000000000, (0xff800000,) * 4, 0x20),
    (0x7ff8000000000001, (0x7fffffff,) * 4, 0x2),
    (0x7ff0000000000001, (0x7fffffff,) * 4, 0x12),
    (0x8000000000000000, (0x80000000,) * 4, 0),
]


def opcode(side):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(f":DPSP.L{side} "))
    fixed = {int(bit): int(value) for bit, value in re.findall(r"\bi(\d+)=(\d)\b", line)}
    return sum(value << bit for bit, value in fixed.items()) | (3 << 18) | (4 << 23)


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        index = 0
        for side in (1, 2):
            bank = "A" if side == 1 else "B"
            for mode in range(4):
                for value, outputs, flags in CASES:
                    preset = (mode << 9) | 4 # preserve unrelated sticky DEN1
                    expectedFlags = preset | flags
                    if side == 2:
                        preset <<= 16
                        expectedFlags <<= 16
                    out.write(struct.pack(endian + "I", opcode(side)))
                    out.write(bytes(28))
                    rows.write(f"{index}\tDPSP.L{side}\t{bank}3_{bank}2\t{bank}4\t"
                               f"{value:x}\t{outputs[mode]:x}\t{preset:x}\t{expectedFlags:x}\n")
                    index += 1


if __name__ == "__main__":
    main()
