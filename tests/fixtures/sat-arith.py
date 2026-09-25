#!/usr/bin/env python3
"""Build SADD/SSUB 32-bit and 40-bit fixtures. Usage: IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# name, instruction, unit, side, opfield (None for .S), cross, src1, src2
CASES = [
    ("sadd32-positive", "SADD", "L", 1, "0010011", 0, 0x7fffffff, 1),
    ("sadd32-cross", "SADD", "L", 2, "0010011", 1, 12, 7),
    ("sadd32-constant", "SADD", "L", 1, "0010010", 0, -16, -0x80000000),
    ("sadd32-s-cross", "SADD", "S", 2, None, 1, 5, 7),
    ("sadd40-cross", "SADD", "L", 1, "0110001", 1, 2, 0x7ffffffffe),
    ("sadd40-constant", "SADD", "L", 2, "0110000", 0, -3, 0x8000000001),
    ("sadd40-normal", "SADD", "L", 1, "0110001", 0, -2, 3),
    ("sadd40-negative", "SADD", "L", 1, "0110001", 0, -2, 0x8000000000),
    ("ssub32-negative", "SSUB", "L", 1, "0001111", 0, -0x80000000, 1),
    ("ssub32-src2-cross", "SSUB", "L", 1, "0001111", 1, 12, 7),
    ("ssub32-cross", "SSUB", "L", 2, "0011111", 1, 0x7fffffff, -1),
    ("ssub32-constant", "SSUB", "L", 1, "0001110", 0, -3, 0x7fffffff),
    ("ssub40-positive", "SSUB", "L", 1, "0101100", 0, 0, 0x8000000000),
    ("ssub40-normal", "SSUB", "L", 2, "0101100", 0, -3, 5),
    ("ssub40-negative", "SSUB", "L", 2, "0101100", 0, -3, 0x7fffffffff),
]


def signed(value, bits):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def encoding(mnemonic, unit, side, variant, cross, a, long_result):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    prefix = f":{mnemonic}.{unit}{side} "
    for line in decode.read_text().splitlines():
        if not line.startswith(prefix):
            continue
        fixed = {int(bit): int(value) for bit, value in
                 re.findall(r"\bi(\d+)=(\d)\b", line)}
        word = sum(value << bit for bit, value in fixed.items())
        if variant is not None and ((word >> 5) & 127) != int(variant, 2):
            continue
        if ("DstPair" in line) != long_result:
            continue
        word |= (a & 31 if "SCst5" in line else 1) << 13
        word |= 2 << 18
        word |= (4 if long_result else 3) << 23
        word |= cross << 12
        return word, "SCst5" in line
    raise ValueError((mnemonic, unit, side, variant))


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (name, mnemonic, unit, side, variant, cross, a, b) in enumerate(CASES):
            is_long = "40" in name
            word, immediate = encoding(mnemonic, unit, side, variant, cross, a, is_long)
            out.write(struct.pack(endian + "I", word))
            out.write(bytes(28))
            own, other = ("A", "B") if side == 1 else ("B", "A")
            cross_src1 = (mnemonic == "SADD" and variant == "0110001") or (
                mnemonic == "SSUB" and variant == "0011111")
            src1 = "-" if immediate else (other if cross_src1 and cross else own) + "1"
            cross_src2 = not is_long and not cross_src1
            src2file = other if cross_src2 and cross else own
            src2 = own + "3_" + own + "2" if is_long else src2file + "2"
            dst = own + "5_" + own + "4" if is_long else own + "3"
            bits = 40 if is_long else 32
            result = signed(a, 32) + signed(b, bits) if mnemonic == "SADD" \
                else signed(a, 32) - signed(b, bits)
            ceiling, floor = (1 << (bits - 1)) - 1, -(1 << (bits - 1))
            sat = result > ceiling or result < floor
            result = min(max(result, floor), ceiling) & ((1 << bits) - 1)
            rows.write(f"{index}\t{name}\t{mnemonic}.{unit}{side}\t"
                       f"{src1}\t{src2}\t{dst}\t{a & 0xffffffff:08x}\t"
                       f"{b & 0xffffffffffffffff:016x}\t{result:016x}\t{int(sat)}\n")


if __name__ == "__main__":
    main()
