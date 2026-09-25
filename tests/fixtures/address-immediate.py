#!/usr/bin/env python3
"""Generate .D address arithmetic with unsigned five-bit immediate counts.

Usage: address-immediate.py IMAGE CASES [be]

Each ordinary fetch packet starts with one ADDAB/ADDAD/ADDAH/ADDAW or
SUBAB/SUBAH/SUBAW instruction. Opcode fields follow SPRUFE8B section 3.12.
"""

from pathlib import Path
import struct
import sys


OPS = {
    "ADDAB": (0x32, 0, 1), "ADDAD": (0x3D, 3, 1),
    "ADDAH": (0x36, 1, 1), "ADDAW": (0x3A, 2, 1),
    "SUBAB": (0x33, 0, -1), "SUBAH": (0x37, 1, -1),
    "SUBAW": (0x3B, 2, -1),
}
BASE_VALUE = 0x1000


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "be"):
        raise SystemExit(__doc__)
    image, cases = Path(sys.argv[1]), Path(sys.argv[2])
    endian = ">" if len(sys.argv) == 4 else "<"
    rows = []
    with image.open("wb") as binary:
        for name, (op, shift, sign) in OPS.items():
            for side in (0, 1):
                for count in (1, 17):
                    index = len(rows)
                    word = ((6 << 23) | (4 << 18) | (count << 13)
                            | (op << 7) | 0x40 | (side << 1))
                    binary.write(struct.pack(endian + "8I", word,
                                             *([0xFFFFFFFF] * 7)))
                    expected = (BASE_VALUE + sign * (count << shift)) & 0xFFFFFFFF
                    bank = "A" if side == 0 else "B"
                    rows.append(f"{index}\t{name}.D{side + 1}\t{bank}4\t"
                                f"{bank}6\t{bank}{count}\t"
                                f"{BASE_VALUE:08x}\t{expected:08x}")
    cases.write_text("\n".join(rows) + "\n")


if __name__ == "__main__":
    main()
