#!/usr/bin/env python3
"""Generate floating-point comparison and FAUCR cases. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


OPERANDS = [
    ("equal", 0x3f800000, 0x3f800000, 0x3ff0000000000000, 0x3ff0000000000000),
    ("greater", 0x40000000, 0x3f800000, 0x4000000000000000, 0x3ff0000000000000),
    ("less", 0xbf800000, 0x3f800000, 0xbff0000000000000, 0x3ff0000000000000),
    ("signed-zero", 0x00000000, 0x80000000, 0, 0x8000000000000000),
    ("denormal-left", 0x00000001, 0, 1, 0),
    ("denormal-right", 0, 0x80000001, 0, 0x8000000000000001),
    ("both-denormal", 1, 0x80000001, 1, 0x8000000000000001),
    ("nan-left", 0x7fc00001, 0x3f800000, 0x7ff8000000000001, 0x3ff0000000000000),
    ("nan-right", 0x3f800000, 0x7f800001, 0x3ff0000000000000, 0x7ff0000000000001),
    ("both-nan", 0x7fc00001, 0x7f800001, 0x7ff8000000000001, 0x7ff0000000000001),
    ("infinity", 0x7f800000, 0x7f800000, 0x7ff0000000000000, 0x7ff0000000000000),
]


def expected(mnemonic, left, right, dp):
    exp_bits, frac_bits = (11, 52) if dp else (8, 23)
    exp_mask = (1 << exp_bits) - 1
    frac_mask = (1 << frac_bits) - 1
    sign_mask = 1 << (exp_bits + frac_bits)
    flags = 0
    values = []
    for raw, nan_bit, den_bit in ((left, 1, 4), (right, 2, 8)):
        exponent = (raw >> frac_bits) & exp_mask
        fraction = raw & frac_mask
        if exponent == exp_mask and fraction:
            flags |= nan_bit
        if exponent == 0 and fraction:
            flags |= den_bit
            raw &= sign_mask
        values.append(struct.unpack(">d" if dp else ">f", raw.to_bytes(8 if dp else 4, "big"))[0])
    if flags & 3:
        flags |= 0x200
        if mnemonic != "CMPEQ":
            flags |= 0x10
        return 0, flags
    a, b = values
    return int({"CMPEQ": a == b, "CMPGT": a > b, "CMPLT": a < b}[mnemonic]), flags


def opcode(mnemonic, side, dp):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    suffix = "DP" if dp else "SP"
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(f":{mnemonic}{suffix}.S{side} "))
    fixed = {int(bit): int(value) for bit, value in re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    return word | ((0 if dp else 1) << 13) | (2 << 18) | (4 << 23)


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        index = 0
        for dp in (False, True):
            suffix = "DP" if dp else "SP"
            for mnemonic in ("CMPEQ", "CMPGT", "CMPLT"):
                for side in (1, 2):
                    bank = "A" if side == 1 else "B"
                    src1 = f"{bank}1_{bank}0" if dp else f"{bank}1"
                    src2 = f"{bank}3_{bank}2" if dp else f"{bank}2"
                    dst = f"{bank}4"
                    for label, sp1, sp2, dp1, dp2 in OPERANDS:
                        left, right = (dp1, dp2) if dp else (sp1, sp2)
                        result, flags = expected(mnemonic, left, right, dp)
                        preset = 0x100 if label == "equal" else 0
                        flags = (flags << (16 if side == 2 else 0)) | preset
                        out.write(struct.pack(endian + "I", opcode(mnemonic, side, dp)))
                        out.write(bytes(28))
                        rows.write(f"{index}\t{mnemonic}{suffix}.S{side}\t{src1}\t{src2}\t{dst}\t"
                                   f"{left:x}\t{right:x}\t{result:x}\t{preset:x}\t{flags:x}\n")
                        index += 1


if __name__ == "__main__":
    main()
