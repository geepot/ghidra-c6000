#!/usr/bin/env python3
"""Build C64x+ LL/SL/CMTL opcode cases. IMAGE CASES.tsv [be]."""

from pathlib import Path
import struct
import sys


OPCODES = (("LL.D2T2", 0x642, "c6000_link_load"),
           ("SL.D2T2", 0x6c2, "c6000_link_store"),
           ("CMTL.D2T2", 0x742, "c6000_link_commit"))


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        index = -1
        for mnemonic, low, userop in OPCODES:
            index += 1
            word = (21 << 23) | (5 << 18) | low
            out.write(struct.pack(endian + "I", word) + bytes(28))
            rows.write(f"{index}\t{mnemonic}\t{userop}\n")
        for low in (0x640, 0x6c0, 0x740, 0x642 | (1 << 13),
                    0x6c2 | (1 << 12), 0x742 | (1 << 17)):
            index += 1
            word = (21 << 23) | (5 << 18) | low
            out.write(struct.pack(endian + "I", word) + bytes(28))
            rows.write(f"{index}\t-\t-\n")


if __name__ == "__main__":
    main()
