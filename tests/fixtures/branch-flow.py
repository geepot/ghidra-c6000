#!/usr/bin/env python3
"""Build direct 32-bit branch flow cases. Usage: IMAGE CASES [be].

Words are encoded from SPRUFE8B's B, BNOP, CALLP, BDEC, and BPOS opcode
diagrams. Each instruction branches or calls to the next fetch packet,
except the last: a 32-bit BNOP in a header-based (compact) fetch packet counts
its displacement in halfwords, so 8 reaches word 4 of its own packet.
"""

from pathlib import Path
import struct
import sys


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "be"):
        raise SystemExit(__doc__)
    image, manifest = Path(sys.argv[1]), Path(sys.argv[2])
    endian = ">" if len(sys.argv) == 4 else "<"
    cases = [
        ("B.S1", "jump", 0x10 | (8 << 7)),
        ("B.S1", "conditional", 0xc0000010 | (8 << 7)),
        ("BNOP.S1", "jump", 0x120 | (5 << 13) | (8 << 16)),
        ("BNOP.S2", "conditional", 0xc0000122 | (3 << 13) | (8 << 16)),
        ("CALLP.S2", "call", 0x10000012 | (8 << 7)),
        ("BDEC.S1", "conditional", 0x1020 | (8 << 13)),
        ("BPOS.S2", "conditional", 0x22 | (8 << 13)),
        ("BNOP.S1", "jump", 0x120 | (5 << 13) | (8 << 16), 16, 0xE0000000),
    ]
    with image.open("wb") as binary, manifest.open("w") as rows:
        for index, (mnemonic, kind, word, *packet) in enumerate(cases):
            address = 0x1000 + 32 * index
            offset, header = packet or (32, 0)
            binary.write(struct.pack(endian + "I", word) + bytes(24) +
                         struct.pack(endian + "I", header))
            rows.write(f"{address:x}\t{mnemonic}\t{address + offset:x}\t{kind}\n")
        binary.write(bytes(32))


if __name__ == "__main__":
    main()
