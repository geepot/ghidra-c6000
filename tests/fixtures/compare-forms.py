#!/usr/bin/env python3
"""Generate scalar/40-bit compare and ADDU opcode checks. IMAGE CASES.tsv [be]."""

from pathlib import Path
import struct
import sys


REGS = {"A4": 0xffffffff, "B4": 0x80000000,
        "A6": 0xfffffffd, "B6": 0x80000001,
        "A7": 0xffffffff, "B7": 0x12345600}
OPS = {"CMPEQ": (0x53, 0x52, 0x51, 0x50),
       "CMPGT": (0x47, 0x46, 0x45, 0x44),
       "CMPLT": (0x57, 0x56, 0x55, 0x54),
       "CMPGTU": (0x4f, 0x4e, 0x4d, 0x4c),
       "CMPLTU": (0x5f, 0x5e, 0x5d, 0x5c)}
MASK40 = (1 << 40) - 1


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def encoded(op, side, x, src1=4, src2=6, dst=8):
    return ((dst << 23) | (src2 << 18) | (src1 << 13) |
            (x << 12) | (op << 5) | 0x18 | ((side - 1) << 1))


def operand_values(name, side, x, immediate, pair):
    own, other = ("A", "B") if side == 1 else ("B", "A")
    unsigned = name.endswith("U") or name == "ADDU"
    if immediate:
        a = 31 if unsigned else -3
    else:
        a_bank = other if pair and x else own
        a = REGS[a_bank + "4"]
        if not unsigned:
            a = signed(a, 32)
    if pair:
        b = ((REGS[own + "7"] & 0xff) << 32) | REGS[own + "6"]
        if not unsigned:
            b = signed(b, 40)
    else:
        b_bank = other if x else own
        b = REGS[b_bank + "6"]
        if not unsigned:
            b = signed(b, 32)
    return a, b


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    cases = []
    for name, forms in OPS.items():
        for form, op in enumerate(forms):
            pair = form >= 2
            immediate = form % 2 == 1
            side = 2 if pair and not immediate else 1
            x = 0 if pair and immediate else 1
            cases.append((name, op, side, x, immediate, pair))
    cases.extend([("ADDU", 0x2b, 1, 1, False, False),
                  ("ADDU", 0x29, 2, 1, False, True)])
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (name, op, side, x, immediate, pair) in enumerate(cases):
            src1 = (31 if name.endswith("U") else 29) if immediate else 4
            out.write(struct.pack(endian + "I", encoded(op, side, x, src1)) + bytes(28))
            a, b = operand_values(name, side, x, immediate, pair)
            if name == "ADDU":
                result = (a + b) & MASK40
                expected = result
            else:
                result = {"CMPEQ": lambda: a == b,
                          "CMPGT": lambda: a > b,
                          "CMPLT": lambda: a < b,
                          "CMPGTU": lambda: a > b,
                          "CMPLTU": lambda: a < b}[name]()
                expected = (0x66 << 32) | int(result)
            rows.write(f"{index}\t{name}.L{side}\t{side}\t{expected:016x}\n")
        invalid = [(0x50, 1, 1, 29, 6, 8),  # signed long immediate has no cross path
                   (0x45, 1, 0, 4, 7, 8),   # pair source must be even
                   (0x2b, 1, 0, 4, 6, 9)]  # long destination must be even
        for op, side, x, src1, src2, dst in invalid:
            index += 1
            out.write(struct.pack(endian + "I", encoded(op, side, x, src1,
                                                        src2, dst)) + bytes(28))
            rows.write(f"{index}\t-\t{side}\t-\n")


if __name__ == "__main__":
    main()
