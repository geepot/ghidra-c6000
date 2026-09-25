#!/usr/bin/env python3
"""Generate exact integer-to-SP rounding and FADCR cases. IMAGE CASES.tsv [be]."""
import random
import re
import struct
import sys
from pathlib import Path


VALUES = [
    0, 1, 2, 0x7fffffff, 0x80000000, 0xffffffff,
    0x00ffffff, 0x01000000, 0x01000001, 0x01000002,
    0x01000003, 0x01000005, 0x19651127, 0x7fffff80,
    0x7fffff81, 0xffffff00, 0xffffff01,
]
random_cases = random.Random(0x1a75)
VALUES.extend(random_cases.getrandbits(32) for _ in range(50))


def expected(raw, unsigned, mode):
    number = raw if unsigned or raw < 0x80000000 else raw - 0x100000000
    if number == 0:
        return 0, 0
    sign = 0x80000000 if number < 0 else 0
    magnitude = abs(number)
    exponent = magnitude.bit_length() - 1
    if exponent <= 23:
        significand = magnitude << (23 - exponent)
        return sign | ((exponent + 127) << 23) | (significand & 0x7fffff), 0
    shift = exponent - 23
    significand = magnitude >> shift
    remainder = magnitude & ((1 << shift) - 1)
    if remainder:
        half = 1 << (shift - 1)
        round_up = ((mode == 0 and (remainder > half or
                     (remainder == half and significand & 1))) or
                    (mode == 2 and not sign) or (mode == 3 and sign))
        if round_up:
            significand += 1
            if significand == 1 << 24:
                significand >>= 1
                exponent += 1
    bits = sign | ((exponent + 127) << 23) | (significand & 0x7fffff)
    return bits, 0x80 if remainder else 0


def opcode(mnemonic, side, cross):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(f":{mnemonic}.L{side} "))
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    return (sum(value << bit for bit, value in fixed.items()) |
            (1 << 18) | (4 << 23) | (int(cross) << 12))


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        index = 0
        for mnemonic in ("INTSP", "INTSPU"):
            for side in (1, 2):
                bank = "A" if side == 1 else "B"
                other = "B" if side == 1 else "A"
                for mode in range(4):
                    for case_index, raw in enumerate(VALUES):
                        cross = case_index == 12
                        bits, flags = expected(raw, mnemonic == "INTSPU", mode)
                        out.write(struct.pack(endian + "I", opcode(mnemonic, side, cross)))
                        out.write(bytes(28))
                        shift = 16 if side == 2 else 0
                        preset = (mode << (9 + shift)) | (1 if side == 2 else 0x10000)
                        expected_flags = preset | (flags << shift)
                        rows.write(f"{index}\t{mnemonic}.L{side}\t"
                                   f"{other if cross else bank}1\t{bank}4\t"
                                   f"{raw:x}\t{bits:x}\t{preset:x}\t{expected_flags:x}\n")
                        index += 1


if __name__ == "__main__":
    main()
