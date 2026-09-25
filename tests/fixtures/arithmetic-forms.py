#!/usr/bin/env python3
"""Generate 32/40-bit ADD/SUB operand-form cases. IMAGE CASES.tsv [be]."""

from pathlib import Path
import struct
import sys


REGS = {"A4": 0x7fffffff, "B4": 0x80000001,
        "A6": 0xfffffffe, "B6": 8,
        "A7": 0xabcdef80, "B7": 0x12345678}
MASK40 = (1 << 40) - 1

# mnemonic, unit, low opcode, side, x, first operand, second operand, dst pair
CASES = [
    ("ADD", "L", 0x03, 1, 1, "A4", "B6", False),
    ("ADD", "L", 0x23, 1, 1, "A4", "B6", True),
    ("ADD", "L", 0x21, 1, 1, "B4", "A7:A6", True),
    ("ADD", "L", 0x02, 1, 1, "-3", "B6", False),
    ("ADD", "L", 0x20, 1, 0, "-3", "A7:A6", True),
    ("SUB", "L", 0x07, 1, 1, "A4", "B6", False),
    ("SUB", "L", 0x17, 1, 1, "B4", "A6", False),
    ("SUB", "L", 0x27, 1, 1, "A4", "B6", True),
    ("SUB", "L", 0x37, 1, 1, "B4", "A6", True),
    ("SUB", "L", 0x06, 1, 1, "-3", "B6", False),
    ("SUB", "L", 0x24, 1, 0, "-3", "A7:A6", True),
    ("ADD", "S", 0x06, 2, 1, "-3", "A6", False),
    ("SUB", "S", 0x16, 2, 1, "-3", "A6", False),
    ("ADD", "D", 0x10, 1, 0, "A6", "A4", False),
    ("ADD", "D", 0x12, 1, 0, "A6", "5", False),
    ("SUB", "D", 0x11, 1, 0, "A6", "A4", False),
    ("SUB", "D", 0x13, 1, 0, "A6", "5", False),
    ("ADD", "DX", 0xAF0, 2, 1, "A6", "-3", False),
    ("SUB", "DX", 0xB30, 2, 1, "B4", "A6", False),
]


def value(name):
    if ":" in name:
        high, low = name.split(":")
        raw = ((REGS[high] & 0xff) << 32) | REGS[low]
        return raw - (1 << 40) if raw & (1 << 39) else raw
    if name in REGS:
        raw = REGS[name]
        return raw - (1 << 32) if raw & (1 << 31) else raw
    return int(name)


def word(unit, op, side, cross, first, second, dst=8, src2=6):
    if unit == "L":
        src1 = 29 if first == "-3" else 4
        low = (op << 5) | 0x18
    elif unit == "S":
        src1 = 29 if first == "-3" else 4
        low = (op << 6) | 0x20
    elif unit == "D":
        src1 = 5 if second == "5" else 4
        low = (op << 7) | 0x40
    else:
        src1 = 29 if second == "-3" else 4
        low = op
    return ((dst << 23) | (src2 << 18) | (src1 << 13) |
            (cross << 12) | low | ((side - 1) << 1))


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (name, unit, op, side, cross, first, second, pair) in enumerate(CASES):
            out.write(struct.pack(endian + "I", word(unit, op, side, cross,
                                                       first, second)) + bytes(28))
            result = value(first) + value(second) if name == "ADD" \
                else value(first) - value(second)
            result &= MASK40 if pair else 0xffffffff
            expected = result if pair else (0x66 << 32) | result
            unit_name = "D" if unit == "DX" else unit
            rows.write(f"{index}\t{name}.{unit_name}{side}\t{side}\t"
                       f"{expected:016x}\n")
        invalid = [("ADD", "L", 0x23, 1, 1, "A4", "B6", 9, 6),
                   ("ADD", "L", 0x21, 1, 1, "B4", "A7:A6", 8, 7),
                   ("SUB", "L", 0x24, 1, 1, "-3", "A7:A6", 8, 6)]
        for name, unit, op, side, cross, first, second, dst, src2 in invalid:
            index += 1
            out.write(struct.pack(endian + "I", word(unit, op, side, cross,
                                                       first, second, dst, src2)) + bytes(28))
            rows.write(f"{index}\t-\t{side}\t-\n")


if __name__ == "__main__":
    main()
