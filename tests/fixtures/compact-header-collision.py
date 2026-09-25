#!/usr/bin/env python3
"""Make a compact packet whose first word resembles a CPKT header.

Usage: compact-header-collision.py OUTPUT [be]

The first fetch packet has an E-prefixed word outside the header position;
it is undefined. The second has two valid compact instructions in word 0,
whose upper halfword begins with E, followed by the actual header at word 7.
"""

from pathlib import Path
import struct
import sys


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    big_endian = len(sys.argv) == 3
    words = [0xE0000000] + [0xFFFFFFFF] * 7
    words += [0xEA3BE5BE if big_endian else 0xE5BEEA3B]
    words += [0xFFFFFFFF] * 6 + [0xE0200000]
    Path(sys.argv[1]).write_bytes(struct.pack((">" if big_endian else "<") + "16I", *words))


if __name__ == "__main__":
    main()
