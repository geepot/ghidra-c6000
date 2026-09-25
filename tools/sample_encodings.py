#!/usr/bin/env python3
"""Generate a deterministic exploratory sample of noncompact 32-bit C6x words.

Usage: tools/sample_encodings.py OUTPUT [WORDS] [SEED]

The high nibble is zero, giving unpredicated instructions and excluding compact
packet headers. This samples invalid as well as valid encodings; differences
with another disassembler require manual validation against the architecture
manual before changing the decoder.
"""

from pathlib import Path
import random
import struct
import sys


def main():
    if len(sys.argv) not in (2, 3, 4):
        print(__doc__, file=sys.stderr)
        return 2
    output = Path(sys.argv[1])
    count = int(sys.argv[2], 0) if len(sys.argv) > 2 else 32768
    seed = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0xC674
    if count <= 0 or count % 8:
        raise ValueError("word count must be positive and a multiple of eight")
    rng = random.Random(seed)
    with output.open("wb") as image:
        for _ in range(count):
            image.write(struct.pack("<I", rng.getrandbits(28)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
