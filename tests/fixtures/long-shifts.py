#!/usr/bin/env python3
"""Generate 40-bit SHL/SHR/SHRU opcode and execution cases. IMAGE CASES.tsv [be]."""

from pathlib import Path
import struct
import sys


MASK40 = (1 << 40) - 1
# name, opfield, side, cross path, source low, source high, count
CASES = [
    ("SHL", 0x31, 1, 0, 0xffffffff, 0xffffffff, 1),
    ("SHL", 0x30, 2, 0, 0x23456789, 0xabcdef01, 31),
    ("SHR", 0x35, 1, 0, 0x00000003, 0xffffff80, 4),
    ("SHR", 0x34, 2, 0, 0xffffffff, 0xffffffff, 31),
    ("SHRU", 0x25, 1, 0, 0x00000003, 0xffffff80, 4),
    ("SHRU", 0x24, 2, 0, 0xffffffff, 0xffffffff, 31),
    ("SHL", 0x13, 1, 1, 0x80000000, 0, 4),
    ("SHL", 0x12, 2, 0, 0x80000000, 0, 1),
    ("SHL", 0x31, 1, 0, 0xffffffff, 0xffffffff, 63),
    ("SHR", 0x35, 2, 0, 0xffffffff, 0xffffffff, 63),
    ("SHRU", 0x25, 1, 0, 0xffffffff, 0xffffffff, 63),
    ("SHL", 0x31, 2, 0, 0x23456789, 0xabcdef01, 64),
]
# Pair forms require a local, even src2 and an even destination.
INVALID = [("SHL", 0x31, 1, 1, 2, 6),
           ("SHR", 0x35, 2, 0, 3, 6),
           ("SHRU", 0x24, 1, 0, 2, 7)]


def expected(name, op, low, high, count):
    source = (high << 32) | low
    if op in (0x13, 0x12):
        source = low
    else:
        source &= MASK40
    amount = min(count & 63, 40)
    if name == "SHL":
        return (source << amount) & MASK40
    if name == "SHR" and source & (1 << 39):
        source -= 1 << 40
    return (source >> amount) & MASK40


def word(op, side, cross, src1, src2=2, dst=6):
    return ((dst << 23) | (src2 << 18) | (src1 << 13) |
            (cross << 12) | (op << 6) | 0x20 | ((side - 1) << 1))


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (name, op, side, cross, low, high, count) in enumerate(CASES):
            immediate = op in (0x30, 0x34, 0x24, 0x12)
            out.write(struct.pack(endian + "I", word(op, side, cross,
                                                       count if immediate else 4)) + bytes(28))
            result = expected(name, op, low, high, count)
            rows.write(f"{index}\t{name}.S{side}\t{side}\t{cross}\t"
                       f"{low:08x}\t{high:08x}\t{count}\t{result:016x}\n")
        for name, op, side, cross, src2, dst in INVALID:
            index += 1
            out.write(struct.pack(endian + "I", word(op, side, cross, 4, src2, dst)) + bytes(28))
            rows.write(f"{index}\t-\t{side}\t{cross}\t00000000\t00000000\t1\t-\n")


if __name__ == "__main__":
    main()
