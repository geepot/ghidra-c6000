#!/usr/bin/env python3
"""Generate MVKH/MVK opcode and p-code checks. IMAGE CASES.tsv [be]."""

from pathlib import Path
import struct
import sys


# side, dst, encoded halfword, old dst, B0 predicate, creg, z, mnemonic
CASES = [
    (2, 0, 0x1180, 0x12345678, 0, 0, 0, "MVKH.S2"),
    (1, 4, 0xabcd, 0x76544321, 0, 0, 0, "MVKH.S1"),
    (2, 4, 0xffff, 0x12345678, 1, 1, 0, "[B0]MVKH.S2"),
    (2, 4, 0x789a, 0x12345678, 0, 1, 0, "[B0]MVKH.S2"),
    (2, 4, 0x789a, 0x12345678, 0, 1, 1, "[!B0]MVKH.S2"),
    (2, 4, 0x789a, 0x12345678, 1, 1, 1, "[!B0]MVKH.S2"),
    (1, 4, 0x9234, 0x76544321, 0, 0, 0, "MVK.S1"),
]


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (side, dst, half, old, predicate, creg, z, mnemonic) in enumerate(CASES):
            high = mnemonic.split(".")[0].endswith("MVKH")
            opcode = (creg << 29) | (z << 28) | (dst << 23) | (half << 7)
            opcode |= (0x68 if high else 0x28) | ((side - 1) << 1)
            out.write(struct.pack(endian + "I", opcode) + bytes(28))
            bank = "A" if side == 1 else "B"
            reg = f"{bank}{dst}"
            executes = creg == 0 or (predicate == 0 if z else predicate != 0)
            if not executes:
                expected = old
            elif high:
                expected = (half << 16) | (old & 0xffff)
            else:
                expected = half if half < 0x8000 else half | 0xffff0000
            rows.write(f"{index}\t{mnemonic}\t{reg}\t{old:08x}\t{predicate:08x}\t{expected:08x}\n")


if __name__ == "__main__":
    main()
