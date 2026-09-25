#!/usr/bin/env python3
"""Build cross-path SUBDP.L cases. Usage: IMAGE CASES [be]."""

from pathlib import Path
import struct
import sys


def bits(value):
    return struct.unpack(">Q", struct.pack(">d", value))[0]


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "be"):
        raise SystemExit(__doc__)
    image, manifest = Path(sys.argv[1]), Path(sys.argv[2])
    endian = ">" if len(sys.argv) == 4 else "<"
    with image.open("wb") as binary, manifest.open("w") as rows:
        for index, (side, a, b) in enumerate([
            (1, 5.0, 2.0), (1, 2.0, 5.0), (1, -5.0, 2.0),
            (1, 0.5, 0.25), (2, 5.0, 2.0), (2, 2.0, 5.0),
            (2, -5.0, 2.0), (2, 0.5, 0.25),
        ]):
            own, other = ("A", "B") if side == 1 else ("B", "A")
            word = ((4 << 23) | (2 << 18) | (6 << 13) | (1 << 12) |
                    (0b0011101 << 5) | 0x18 | (side - 1) << 1)
            binary.write(struct.pack(endian + "I", word) + bytes(28))
            rows.write(f"{index}\tSUBDP.L{side}\t{other}7:{other}6\t"
                       f"{own}3:{own}2\t{own}5:{own}4\t"
                       f"{other}7_{other}6\t{own}3_{own}2\t"
                       f"{bits(a):x}\t{bits(b):x}\t{bits(a-b):x}\t0\t0\n")


if __name__ == "__main__":
    main()
