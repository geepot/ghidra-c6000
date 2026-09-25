#!/usr/bin/env python3
"""Generate 32-bit AND/OR/XOR signed-immediate forms for both endians.

Usage: logical-immediate.py IMAGE CASES [be]

Each instruction is at the start of its own ordinary fetch packet. The
opfields and fixed bits come from SPRUFE8B's AND, OR, and XOR opcode tables.
"""

from pathlib import Path
import struct
import sys


OPS = {
    "AND": {"L": 0x7A, "S": 0x1E, "D": 0x7},
    "OR": {"L": 0x7E, "S": 0x1A, "D": 0x3},
    "XOR": {"L": 0x6E, "S": 0x0A, "D": 0xF},
}
SOURCE_VALUE = 0xA5F0F0A5


def opcode(name, unit, side, signed_imm):
    op = OPS[name][unit]
    fixed = {"L": (op << 5) | 0x18,
             "S": (op << 6) | 0x20,
             "D": (op << 6) | 0x830}[unit]
    return ((6 << 23) | (4 << 18) | ((signed_imm & 31) << 13)
            | fixed | (side << 1))


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "be"):
        raise SystemExit(__doc__)
    image, cases = Path(sys.argv[1]), Path(sys.argv[2])
    endian = ">" if len(sys.argv) == 4 else "<"
    rows = []
    with image.open("wb") as binary:
        for name in OPS:
            for unit in "LSD":
                for side in (0, 1):
                    for imm in (-8, 7):
                        index = len(rows)
                        word = opcode(name, unit, side, imm)
                        binary.write(struct.pack(endian + "8I", word,
                                                 *([0xFFFFFFFF] * 7)))
                        arg = imm & 0xFFFFFFFF
                        expected = {"AND": SOURCE_VALUE & arg,
                                    "OR": SOURCE_VALUE | arg,
                                    "XOR": SOURCE_VALUE ^ arg}[name]
                        bank = "A" if side == 0 else "B"
                        rows.append(f"{index}\t{name}.{unit}{side + 1}\t{bank}4\t"
                                    f"{bank}6\t{bank}{imm & 31}\t"
                                    f"{SOURCE_VALUE:08x}\t{expected:08x}")
    cases.write_text("\n".join(rows) + "\n")


if __name__ == "__main__":
    main()
