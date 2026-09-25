#!/usr/bin/env python3
"""Build MPYSPDP/MPYSP2DP fixtures. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# mnemonic, side, cross, single-precision src1, second source
CASES = [
    ("MPYSPDP", 1, 0, 1.5, 2.25),
    ("MPYSPDP", 2, 1, -0.5, -0.2),
    ("MPYSPDP", 1, 1, 3.1415927, 1.25),
    ("MPYSPDP", 2, 0, -0.0, 3.0),
    ("MPYSP2DP", 1, 0, 1.5, -2.25),
    ("MPYSP2DP", 2, 1, -0.75, 2.5),
    ("MPYSP2DP", 2, 0, 0.1, 0.1),
    ("MPYSP2DP", 1, 1, 2**-20, 2**20),
]


def bits32(value):
    return struct.unpack(">I", struct.pack(">f", value))[0]


def bits64(value):
    return struct.unpack(">Q", struct.pack(">d", value))[0]


def rounded32(value):
    return struct.unpack(">f", struct.pack(">f", value))[0]


def opcode(mnemonic, side, cross):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    prefix = f":{mnemonic}.M{side} "
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(prefix))
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    word |= 1 << 13  # src1
    word |= 2 << 18  # src2, scalar or B3:B2/A3:A2 pair
    word |= 2 << 24  # destination A5:A4/B5:B4
    word |= cross << 12
    return word


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (mnemonic, side, cross, a, b) in enumerate(CASES):
            out.write(struct.pack(endian + "I", opcode(mnemonic, side, cross)))
            out.write(bytes(28))
            own, other = ("A", "B") if side == 1 else ("B", "A")
            src2_side = other if cross else own
            src2 = f"{src2_side}3_{src2_side}2" if mnemonic == "MPYSPDP" else f"{src2_side}2"
            a32 = rounded32(a)
            second = bits64(b) if mnemonic == "MPYSPDP" else bits32(b)
            b_value = b if mnemonic == "MPYSPDP" else rounded32(b)
            rows.write(f"{index}\t{mnemonic}.M{side}\t{own}1\t{src2}\t{own}5_{own}4\t"
                       f"{bits32(a):08x}\t{second:016x}\t"
                       f"{bits64(a32 * b_value):016x}\t0\t0\n")


if __name__ == "__main__":
    main()
