#!/usr/bin/env python3
"""Build SSHL register/immediate saturation cases. Usage: IMAGE CASES [be]."""

from pathlib import Path
import struct
import sys


# side, immediate, cross, count, signed source
CASES = [
    (1, True, False, 0, 0x47191925),
    (1, True, False, 2, 0x02e3031c),
    (2, True, False, 8, 0x00100000),
    (2, True, False, 31, -1),
    (1, True, True, 4, 0x10000000),
    (1, False, False, 6, 0x47191925),
    (2, False, True, 63, -1),
    (1, False, False, 32, 0),
    (1, False, False, 32, 1),
    (2, False, False, 0x42, -3),
]


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "be"):
        raise SystemExit(__doc__)
    image, manifest = Path(sys.argv[1]), Path(sys.argv[2])
    endian = ">" if len(sys.argv) == 4 else "<"
    with image.open("wb") as binary, manifest.open("w") as rows:
        for index, (side, immediate, cross, count, source) in enumerate(CASES):
            own, other = ("A", "B") if side == 1 else ("B", "A")
            opfield = 0b100010 if immediate else 0b100011
            word = ((3 << 23) | (2 << 18) | ((count & 31 if immediate else 1) << 13)
                    | (int(cross) << 12) | (opfield << 6) | 0x20 | ((side - 1) << 1))
            binary.write(struct.pack(endian + "I", word) + bytes(28))
            signed = source if source < 0x80000000 else source - 0x100000000
            exact = signed << (count & 31 if immediate else count & 63)
            result = min(max(exact, -0x80000000), 0x7fffffff)
            saturated = result != exact
            rows.write(f"{index}\tsshl-{index}\tSSHL.S{side}\t"
                       f"{'-' if immediate else own + '1'}\t"
                       f"{other if cross else own}2\t{own}3\t{count:x}\t"
                       f"{source & 0xffffffff:x}\t{result & 0xffffffff:x}\t"
                       f"{int(saturated)}\n")


if __name__ == "__main__":
    main()
