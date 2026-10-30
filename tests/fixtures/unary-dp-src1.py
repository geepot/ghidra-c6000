#!/usr/bin/env python3
"""Build ABSDP/RCPDP/RSQRDP src1-field decode cases.

Usage: unary-dp-src1.py IMAGE CASES.tsv [be]

Each word sits alone in a 32-byte packet. src2 = the pair's odd register and
src1 = its low register is how cl6x 8.3.15 and GNU as 2.47 encode every pair
(ABSDP .S1 A7:A6,A9:A8 assembles to 041ccb20). "even" rows are the src2 = low,
src1 = 0 form main already decodes; they serve as each pair's reference result
and FAUCR. Every other src1 and x = 1 are not decoded; the decode rows match
dp-convert-src1.py. GUARDED rows add [A1], [!A1], reserved creg 7 and a
flag-setting SNaN to both forms.
"""

import struct
import sys
from pathlib import Path

OP = {"ABSDP": 0x2C, "RCPDP": 0x2D, "RSQRDP": 0x2E}
# raw double placed in the pair; ABSDP gets a negative value, both words nonzero
RAW = {"ABSDP": 0xC005BF0A8B145769, "RCPDP": 0x4005BF0A8B145769, "RSQRDP": 0x4005BF0A8B145769}
DST = 10
# name, src2, src1, x, decoded pair low register (-1 = undefined)
FORMS = [
    ("asm-pair6", 7, 6, 0, 6),
    ("asm-pair16", 17, 16, 0, 16),
    ("asm-pair0", 1, 0, 0, 0),
    ("diagram-odd-pair6", 7, 0, 0, -1),
    ("src1-even-other", 7, 2, 0, -1),
    ("src1-above-pair", 7, 8, 0, -1),
    ("src1-odd", 7, 5, 0, -1),
    ("src1-odd-high", 7, 7, 0, -1),
    ("cross-odd", 7, 6, 1, -1),
    ("even-pair6", 6, 0, 0, 6),
    ("even-pair16", 16, 0, 0, 16),
    ("even-pair0", 0, 0, 0, 0),
    ("even-src1-low", 6, 6, 0, -1),
    ("cross-even", 6, 0, 1, -1),
]
SNAN = 0xFFF0000000000001
# name, src2, src1, x, low register, creg/z (bits 31..28), raw
GUARDED = [(f"{form}-{name}", src2, src1, 0, low if creg != 0xF else -1, creg, raw)
           for form, src2, src1, low in (("asm-pair6", 7, 6, 6), ("even-pair6", 6, 0, 6))
           for name, creg, raw in (("a1", 0x8, None), ("not-a1", 0x9, None), ("creg7", 0xF, None), ("snan", 0, SNAN))]
PREDICATE = {0: "-", 0x8: "A1", 0x9: "!A1", 0xF: "creg7"}


def word(mnemonic, side, src2, src1, x):
    return (DST << 23) | (src2 << 18) | (src1 << 13) | (x << 12) | (OP[mnemonic] << 6) | (0x8 << 2) | (side << 1)


def main():
    image, cases = Path(sys.argv[1]), Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    index = 0
    with image.open("wb") as out, cases.open("w") as manifest:
        for mnemonic in OP:
            for side in (0, 1):
                for name, src2, src1, x, low, creg, raw in [f + (0, None) for f in FORMS] + GUARDED:
                    w = word(mnemonic, side, src2, src1, x) | (creg << 28)
                    raw = RAW[mnemonic] if raw is None else raw
                    out.write(struct.pack(endian + "I", w) + bytes(28))
                    manifest.write(f"{index}\t{mnemonic}-{name}-{side + 1}\t{mnemonic}\t"
                                   f"{side}\t{w:08x}\t{low}\t{raw:016x}\t{name}\t{PREDICATE[creg]}\n")
                    index += 1


if __name__ == "__main__":
    main()
