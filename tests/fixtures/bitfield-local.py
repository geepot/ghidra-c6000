#!/usr/bin/env python3
"""Generate constant CLR/EXT/EXTU/SET forms with both values of bit 12.

Usage: bitfield-local.py IMAGE CASES [be]

Bit 12 belongs to cstb in these forms; it does not select a cross-path source.
The manifest can be executed by C6000LogicalImmediateTest.java.
"""

from pathlib import Path
import struct
import sys


OPS = {"CLR": 0xC8, "EXT": 0x48, "EXTU": 0x08, "SET": 0x88}
SOURCE_VALUE = 0xA5F0F0A5
MASK32 = 0xFFFFFFFF


def expected(name, a, b):
    if name in {"CLR", "SET"}:
        mask = ((1 << (b - a + 1)) - 1) << a
        return SOURCE_VALUE & ~mask if name == "CLR" else SOURCE_VALUE | mask
    shifted = (SOURCE_VALUE << a) & MASK32
    if name == "EXT" and shifted & 0x80000000:
        shifted -= 1 << 32
    return (shifted >> b) & MASK32


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "be"):
        raise SystemExit(__doc__)
    image, cases = Path(sys.argv[1]), Path(sys.argv[2])
    endian = ">" if len(sys.argv) == 4 else "<"
    rows = []
    with image.open("wb") as binary:
        for name, fixed in OPS.items():
            for side in (0, 1):
                for b in (9, 21):
                    index = len(rows)
                    a = 5
                    word = ((6 << 23) | (4 << 18) | (a << 13)
                            | (b << 8) | fixed | (side << 1))
                    binary.write(struct.pack(endian + "8I", word,
                                             *([0xFFFFFFFF] * 7)))
                    bank = "A" if side == 0 else "B"
                    opposite = "B" if side == 0 else "A"
                    rows.append(f"{index}\t{name}.S{side + 1}\t{bank}4\t"
                                f"{bank}6\t{opposite}4\t"
                                f"{SOURCE_VALUE:08x}\t{expected(name, a, b) & MASK32:08x}")
    cases.write_text("\n".join(rows) + "\n")


if __name__ == "__main__":
    main()
