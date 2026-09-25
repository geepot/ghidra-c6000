#!/usr/bin/env python3
"""Build SSHVL/SSHVR saturation fixtures. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# mnemonic, signed source value, signed count value
CASES = [
    ("SSHVL", 0x10000000, 3),
    ("SSHVL", -0x10000000, 3),
    ("SSHVL", 1, 1),
    ("SSHVL", -8, -1),
    ("SSHVL", 1, 32),
    ("SSHVL", -1, -32),
    ("SSHVL", -1, -0x80000000),
    ("SSHVR", -8, 1),
    ("SSHVR", 0x40000000, -1),
    ("SSHVR", -0x40000001, -1),
    ("SSHVR", 3, -1),
    ("SSHVR", -1, 32),
    ("SSHVR", 1, -32),
    ("SSHVR", 1, -0x80000000),
]


def opcode(mnemonic, side, cross):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    prefix = f":{mnemonic}.M{side} "
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(prefix))
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    word |= 1 << 13
    word |= 2 << 18
    word |= 3 << 23
    word |= cross << 12
    return word


def expected(mnemonic, source, count):
    left = count >= 0 if mnemonic == "SSHVL" else count < 0
    magnitude = min(abs(count), 31)
    if not left:
        return (source >> magnitude) & 0xffffffff, 0
    result = source << magnitude
    sat = result > 0x7fffffff or result < -0x80000000
    result = min(max(result, -0x80000000), 0x7fffffff)
    return result & 0xffffffff, int(sat)


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (mnemonic, source, count) in enumerate(CASES):
            side = 1 if index % 2 == 0 else 2
            cross = index % 3 == 0
            word = opcode(mnemonic, side, cross)
            out.write(struct.pack(endian + "I", word))
            out.write(bytes(28))
            own, other = ("A", "B") if side == 1 else ("B", "A")
            src_reg = (other if cross else own) + "2"
            result, sat = expected(mnemonic, source, count)
            rows.write(f"{index}\t{mnemonic}.M{side}\t{src_reg}\t{own}1\t"
                       f"{own}3\t{source & 0xffffffff:08x}\t"
                       f"{count & 0xffffffff:08x}\t{result:08x}\t{sat}\n")


if __name__ == "__main__":
    main()
