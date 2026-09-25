#!/usr/bin/env python3
"""Generate reverse-operand SUB.S cases. IMAGE CASES.tsv [be]."""

from pathlib import Path
import struct
import sys


# side, cross path, predicated, predicate value
CASES = [(1, 0, 0, 0), (2, 0, 0, 0), (1, 1, 0, 0),
         (2, 1, 0, 0), (1, 0, 1, 0), (2, 1, 1, 1)]


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (side, cross, predicated, predicate) in enumerate(CASES):
            bank = "A" if side == 1 else "B"
            other = "B" if side == 1 else "A"
            src1 = bank + "4"
            src2 = (other if cross else bank) + "5"
            dst = bank + "6"
            # The reverse form computes src2 - src1; x only selects src2's bank.
            word = (6 << 23) | (5 << 18) | (4 << 13) | (cross << 12)
            word |= (0x35 << 6) | 0x30 | ((side - 1) << 1)
            if predicated:
                word |= 1 << 29  # B0, positive sense
            out.write(struct.pack(endian + "I", word) + bytes(28))
            expected = 0x55 if predicated and predicate == 0 else 0x10 - 3
            mnemonic = ("[B0]" if predicated else "") + f"SUB.S{side}"
            rows.write(f"{index}\t{mnemonic}\t{src1}\t{src2}\t{dst}\t"
                       f"{predicate}\t{expected:08x}\n")


if __name__ == "__main__":
    main()
