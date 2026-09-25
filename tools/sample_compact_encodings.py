#!/usr/bin/env python3
"""Place every 16-bit C674x opcode in a compact fetch packet.

Usage: tools/sample_compact_encodings.py OUTPUT [HEADER_EXPANSION]

Each packet puts two opcode values in word 0, fill in words 1..6, and a
compact header in word 7. The header expansion uses bits 20..14 (PROT, RS,
DSZ, BR, SAT); layout bit 0 is set. The default expansion is zero. This is
an encoding probe, so most halfwords are expected to be undefined.
"""

import argparse
from pathlib import Path
import struct


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("header_expansion", nargs="?", type=lambda s: int(s, 0),
                        default=0)
    args = parser.parse_args()
    if not 0 <= args.header_expansion < 128:
        parser.error("header expansion must fit in seven bits")

    header = 0xE0000000 | (1 << 21) | (args.header_expansion << 14)
    with args.output.open("wb") as image:
        for first in range(0, 65536, 2):
            image.write(struct.pack("<I", first | ((first + 1) << 16)))
            image.write(struct.pack("<6I", *([0xFFFFFFFF] * 6)))
            image.write(struct.pack("<I", header))


if __name__ == "__main__":
    main()
