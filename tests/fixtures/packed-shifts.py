#!/usr/bin/env python3
"""Build SHR2/SHRU2 register and constant shift fixtures. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# mnemonic, register-count form, source word, count register/constant value
CASES = [
    ("SHR2", False, 0x80017fff, 0),
    ("SHR2", True, 0x8001ffff, 1),
    ("SHR2", False, 0x80017fff, 15),
    ("SHR2", True, 0x80017fff, 16),
    ("SHR2", False, 0x80017fff, 31),
    ("SHR2", True, 0x80017fff, 0x1234fff0),
    ("SHRU2", False, 0x8001ffff, 0),
    ("SHRU2", True, 0x8001ffff, 1),
    ("SHRU2", False, 0x8001ffff, 15),
    ("SHRU2", True, 0x8001ffff, 16),
    ("SHRU2", False, 0x8001ffff, 31),
    ("SHRU2", True, 0x8001ffff, 0x1234ffe1),
]


def opcode(mnemonic, side, register_count, count, cross):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    prefix = f":{mnemonic}.S{side} "
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(prefix) and ("UCst5" in line) != register_count)
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    word |= (1 if register_count else count & 31) << 13
    word |= 2 << 18
    word |= 3 << 23
    word |= cross << 12
    return word


def expected(mnemonic, src, count):
    count &= 31
    if mnemonic == "SHR2":
        count = min(count, 15)
    out = 0
    for lane in range(2):
        value = (src >> (16 * lane)) & 0xffff
        if mnemonic == "SHR2" and value & 0x8000:
            value -= 0x10000
        out |= ((value >> count) & 0xffff) << (16 * lane)
    return out


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (mnemonic, register_count, src, count) in enumerate(CASES):
            side = 1 if index % 2 == 0 else 2
            cross = index % 3 == 0
            word = opcode(mnemonic, side, register_count, count, cross)
            out.write(struct.pack(endian + "I", word))
            out.write(bytes(28))
            own, other = ("A", "B") if side == 1 else ("B", "A")
            src_reg = (other if cross else own) + "2"
            count_reg = own + "1" if register_count else "-"
            rows.write(f"{index}\t{mnemonic}.S{side}\t{src_reg}\t{count_reg}\t"
                       f"{own}3\t{src:08x}\t{count:08x}\t"
                       f"{expected(mnemonic, src, count):08x}\n")


if __name__ == "__main__":
    main()
