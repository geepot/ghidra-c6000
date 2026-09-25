#!/usr/bin/env python3
"""Generate direction-specific MVC control-register cases. IMAGE CASES.tsv [be]."""

from pathlib import Path
import struct
import sys


# direction, crlo, crhi, cross path, target register, execution mode
CASES = [
    ("write", 7, 8, 0, "NRP", "run"),
    ("write", 2, 2, 1, "ISR", "run"),
    ("write", 3, 3, 0, "ICR", "run"),
    ("write", 29, 0, 0, "ECR", "run"),
    ("write", 0, 15, 0, "AMR", "run"),
    ("read", 7, 8, 0, "NRP", "run"),
    ("read", 2, 0, 0, "IFR", "run"),
    ("read", 2, 2, 0, "IFR", "run"),
    ("read", 29, 0, 0, "EFR", "run"),
    ("read", 16, 16, 0, "PCE1", "decode"),
    ("read", 0, 15, 0, "AMR", "run"),
    ("write", 7, 16, 0, "-", "invalid"),
    ("write", 16, 0, 0, "-", "invalid"),
    ("read", 3, 0, 0, "-", "invalid"),
    ("read", 2, 3, 0, "-", "invalid"),
    ("read", 8, 0, 0, "-", "invalid"),
]


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (direction, crlo, crhi, cross, target, mode) in enumerate(CASES):
            if direction == "write":
                word = (crlo << 23) | (4 << 18) | (crhi << 13) | (cross << 12) | 0x3a2
            else:
                word = (8 << 23) | (crlo << 18) | (crhi << 13) | (cross << 12) | 0x3e2
            out.write(struct.pack(endian + "I", word) + bytes(28))
            rows.write(f"{index}\t{direction}\t{target}\t{cross}\t{mode}\n")


if __name__ == "__main__":
    main()
