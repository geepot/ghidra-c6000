#!/usr/bin/env python3
"""NOP count cases (SPRUFE8B NOP, Figure H-9). Usage: IMAGE CASES.tsv [be]"""

import struct
import sys
from pathlib import Path

# [A1] SPLOOP 1; LDW; NOP 4; MV; SPKERNELR || STW; NOP; NOP: dynamic length 7
LOOP = [0x80038000, 0x00103664, 0x00006000, 0x00001fda,
        0x00036001, 0x001036f6, 0x00000000, 0x00000000]


def unop(n3):
    """Figure H-9 Unop, N3 in bits 15-13."""
    return (n3 << 13) | 0x0c6e


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    header = 0xe0000000 | (1 << 21)
    with image.open("wb") as output, manifest.open("w") as cases:
        output.write(struct.pack(endian + "8I", *LOOP))
        for n3 in range(8):
            output.write(struct.pack(endian + "H", unop(n3)))
            output.write(bytes(26))
            output.write(struct.pack(endian + "I", header))
            cases.write(f"{n3 + 1}\tNOP-N3-{n3}\t{n3 + 1}\n")


if __name__ == "__main__":
    main()
