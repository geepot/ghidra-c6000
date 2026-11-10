#!/usr/bin/env python3
"""Generate direction-specific MVC control-register cases. IMAGE CASES.tsv [be]."""

from pathlib import Path
import struct
import sys


# direction, crlo, crhi, cross path, target register, execution mode[, effect]
# effect: source value, register checked, its preset, expected value (#40).
CASES = [
    ("write", 7, 8, 0, "NRP", "run"),
    ("write", 2, 2, 1, "ISR", "run", (0xffff0025, "IFR", 0, 0x20)),
    ("write", 3, 3, 0, "ICR", "run", (0xffff001f, "IFR", 0xffff, 0xffef)),
    ("write", 29, 0, 0, "ECR", "run", (0xffffffff, "EFR", 0xc0000003, 0)),
    ("write", 29, 0, 1, "ECR", "run", (0x80000001, "EFR", 0xc0000003, 0x40000002)),
    # CSR: CPU ID, REVISION ID and EN are read-only; MVC clears SAT but never sets it.
    ("write", 1, 0, 0, "CSR", "run", (0x00000001, "CSR", 0x14000300, 0x14000101)),
    ("write", 1, 0, 1, "CSR", "run", (0xffffffff, "CSR", 0, 0x0000fcff)),
    ("write", 1, 0, 0, "CSR", "run", (0xffffffff, "CSR", 0x02030300, 0x0203ffff)),
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
        for index, (direction, crlo, crhi, cross, target, mode, *effect) in enumerate(CASES):
            if direction == "write":
                word = (crlo << 23) | (4 << 18) | (crhi << 13) | (cross << 12) | 0x3a2
            else:
                word = (8 << 23) | (crlo << 18) | (crhi << 13) | (cross << 12) | 0x3e2
            out.write(struct.pack(endian + "I", word) + bytes(28))
            extra = "".join(f"\t{v:x}" if isinstance(v, int) else f"\t{v}" for v in (effect[0] if effect else ()))
            rows.write(f"{index}\t{direction}\t{target}\t{cross}\t{mode}{extra}\n")


if __name__ == "__main__":
    main()
