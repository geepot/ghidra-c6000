#!/usr/bin/env python3
"""Build GFPGFR-controlled GMPY4 fixtures. IMAGE CASES.tsv [be]."""
import struct
import sys
from pathlib import Path


# side, cross, GFPGFR, src1, src2, expected packed result
# The first two are SPRUFE8B examples; the others vary side, polynomial and
# field size independently of the p-code implementation.
CASES = [
    (1, 0, 0x0700001D, 0x45230001, 0x57340001, 0x72920001),
    (1, 1, 0x0700001D, 0xFFFE021F, 0xFFFE0201, 0xE2E3041F),
    (2, 0, 0x0700001B, 0x57830102, 0x83125783, 0xC1F5571D),
    (2, 1, 0x03000003, 0x0F070201, 0x0E03010F, 0x0509020F),
    (2, 1, 0x0700001D, 0x45230001, 0x57340001, 0x72920001),
]


def opcode(side, cross):
    # TI cl6x: GMPY4 .M1 A1,A2,A3 = 0x01882470. SPRUFE8B Figure E-1
    # gives bit 28 as predicate z; this fixture must remain unconditional
    # even when testing a decoder that incorrectly fixes that bit to one.
    return 0x01882470 | ((side - 1) << 1) | (cross << 12)


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (side, cross, gfpgfr, a, b, expected) in enumerate(CASES):
            out.write(struct.pack(endian + "I", opcode(side, cross)))
            out.write(bytes(28))
            own, other = ("A", "B") if side == 1 else ("B", "A")
            rows.write(f"{index}\tGMPY4.M{side}\t{own}1\t"
                       f"{other if cross else own}2\t{own}3\t"
                       f"{a:08x}\t{b:08x}\t{expected:08x}\t0\t0\t{gfpgfr:08x}\n")


if __name__ == "__main__":
    main()
