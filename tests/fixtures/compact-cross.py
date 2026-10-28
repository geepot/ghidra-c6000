#!/usr/bin/env python3
"""Compact cross-path unit names (SPRUFE8B appendices C-G). Usage: IMAGE CASES.tsv [be]"""

import struct
import sys
from pathlib import Path

X = 1 << 12

# expected mnemonic, opcode (src fields 0, RS = SAT = BR = 0)
CASES = [
    ("ADD.L1X", X | 0x0000),
    ("ADD.L2", 0x0001),
    ("AND.L1X", X | 0x0408),
    ("AND.L2X", X | 0x0409),
    ("AND.L1", 0x0408),
    ("MPY.M2X", X | 0x001f),
    ("ADD.S1X", X | 0x000a),
    ("SHL.S2X", X | 0x040b),
    ("ADD.D1X", X | 0x0036),
    ("ADDAW.D1X", 0x0436),
    ("ADDAW.D2", 0x0437),
    ("MV.L1X", X | 0x0006),
    ("MV.D2X", X | 0x0057),
]


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    header = 0xe0000000 | (1 << 21)
    with image.open("wb") as output, manifest.open("w") as cases:
        for index, (name, opcode) in enumerate(CASES):
            output.write(struct.pack(endian + "H", opcode))
            output.write(bytes(26))
            output.write(struct.pack(endian + "I", header))
            cases.write(f"{index}\t{name}\n")


if __name__ == "__main__":
    main()
