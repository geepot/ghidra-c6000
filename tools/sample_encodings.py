#!/usr/bin/env python3
"""Generate a deterministic exploratory sample of noncompact 32-bit C6x words.

Usage: tools/sample_encodings.py OUTPUT [WORDS] [SEED] [--predicated]

By default the high nibble is zero, giving unpredicated instructions. With
--predicated it selects one of the twelve valid conditional high nibbles
(creg 1..6, either polarity). Neither mode produces compact packet headers.
Both sample invalid as well as valid encodings; differences with another
disassembler require manual validation against the architecture manual.
"""

from pathlib import Path
import argparse
import random
import struct


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("count", nargs="?", type=lambda s: int(s, 0), default=32768)
    parser.add_argument("seed", nargs="?", type=lambda s: int(s, 0), default=0xC674)
    parser.add_argument("--predicated", action="store_true")
    args = parser.parse_args()
    output, count, seed = args.output, args.count, args.seed
    if count <= 0 or count % 8:
        raise ValueError("word count must be positive and a multiple of eight")
    rng = random.Random(seed)
    with output.open("wb") as image:
        for _ in range(count):
            low = rng.getrandbits(28)
            predicate = rng.randrange(2, 14) if args.predicated else 0
            image.write(struct.pack("<I", low | (predicate << 28)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
