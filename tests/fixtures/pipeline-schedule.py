#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic SPRUFE8B 3.5 / 4.2 packets. Usage: IMAGE [be]. No firmware bytes."""
from pathlib import Path
import struct
import re
import sys


def main():
    image = bytearray(0x3000)
    endian = ">" if len(sys.argv) > 2 and sys.argv[2] == "be" else "<"

    def put(at, *words):
        for k, word in enumerate(words):
            struct.pack_into(endian + "I", image, at - 0x1000 + 4 * k, word)

    def mv(src, dst):
        return (dst << 23) | (src << 18) | 0x58

    def mvk(value, dst, side_b=False):
        return (dst << 23) | ((value & 0xffff) << 7) | (0x2a if side_b else 0x28)

    b3 = 0xc0362
    stw = 0x274 | (4 << 18) | (3 << 23)
    ldw = 0x264 | (4 << 18) | (5 << 23)
    mpy = 0xe00 | (3 << 13) | (4 << 18) | (5 << 23)
    put(0x1000, mvk(1, 3) | 1, mv(3, 4), b3, 0x8000)
    put(0x1100, mpy, mv(5, 6), 0x2000, mv(5, 7), b3, 0x8000)
    # Read-before-store observes one address through independent T paths:
    # STW.D2T2 B6,*B4 || LDW.D1T1 *A4,A5 (SPRUFE8B 3.8.5).
    # Two transfers through T1 are physically invalid even on different .D units.
    put(0x1200, (stw & ~(31 << 23)) | (6 << 23) | 0x82 | 1, ldw, 0x8000, b3, 0x8000)
    put(0x1300, mvk(1, 3) | 1, stw, 0x8000, b3, 0x8000)
    put(0x1400, 0x10 | (16 << 7), 0, 0x10 | (32 << 7), mvk(1, 3), 0x2000, stw | (7 << 13))
    put(0x1440, mvk(2, 4), mvk(3, 5), stw | (6 << 13))
    put(0x1480, mvk(4, 6), b3, 0x8000)
    put(0x1500, 0x20000000 | 0x10 | (16 << 7), mvk(0, 0, True), 0x6000, mvk(0x11, 4), 0x008c0362 | (5 << 13))
    put(0x1540, mvk(0x22, 4), 0x008c0362 | (5 << 13))
    for k in range(6):
        dest = 0x40 + 16 * k
        put(0x1700 + 4 * k, 0x10 | ((dest // 4) << 7))
        put(0x1700 + dest, mvk(0x11 + k, 5 + k), b3 if k == 5 else stw | (7 << 13))
    put(0x1798, 0x8000)
    put(0x1718, stw | (6 << 13))
    put(0x1800, mpy | 0x20000000, mvk(7, 5), 0x6000, b3, 0x8000)
    put(0x1900, mpy, mvk(9, 5), mv(5, 6), 0, mv(5, 7), b3, 0x8000)
    put(0x1a00, b3, mvk(0x1234, 3, True), 0x6000)
    put(0x1b00, (ldw & ~(15 << 9)) | (9 << 9) | (1 << 13), mv(4, 6), 0x6000, mv(5, 7), b3, 0x8000)
    put(0x1c00, (0x02185764 & ~(31 << 18)) | (8 << 18), mv(8, 6) | 1, (7 << 23) | (4 << 18) | 0x8f0, 0x6000, b3, 0x8000)
    put(0x1d00, ldw, mvk(5, 4, True), (6 << 23) | (4 << 18) | 0x1058, 0x6000, b3, 0x8000)
    put(0x1600, mpy, (20 << 23) | (4 << 18) | 0x3a2, 0x6000, b3, 0x8000)
    # Updating-load aliases retain independent E1 base and E5 data writes.
    # The adjacent same-cycle base writer remains an undefined-write refusal.
    put(0x1e00, 0x1e000, b3, 0x8000)
    alias = (ldw & ~((31 << 23) | (15 << 9))) | (4 << 23) | (9 << 9) | (1 << 13)
    put(0x1e40, alias, mv(4, 6), 0x4000, mv(4, 7), b3, 0x8000)
    put(0x2000, alias | 1, mvk(7, 4), b3, 0x8000)
    # Prefix provides a known incoming E1 hazard; scheduled entry is 0x1f04.
    put(0x1f00, mvk(5, 4), (6 << 23) | (4 << 18) | 0x105a, b3, 0x8000)
    put(0x2100, 0x10 | (0x100 // 4 << 7), 0x8000)
    put(0x2200, b3, 0x8000)
    put(0x2300, b3, 0x8000)
    put(0x2400, b3, 0x6000, mpy)  # E4 write would escape the return boundary.
    def abs_word(side, source, destination):
        decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
        line = next(line for line in decode.read_text().splitlines() if f'"ABS.L{side}" Src2, Dst is' in line)
        fixed = {int(bit): int(value) for bit, value in re.findall(r"\bi(\d+)=(\d)\b", line)}
        return sum(value << bit for bit, value in fixed.items()) | (source << 18) | (destination << 23)
    put(0x2700, abs_word(1, 3, 4) | 1, abs_word(2, 5, 4), b3, 0x8000)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
