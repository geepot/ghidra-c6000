#!/usr/bin/env python3
"""Build paired ALU, DMV and UNPKLU4 fixtures. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# mnemonic, unit, side, cross, src1, src2, result, CSR.SAT, SSR.L1/L2
# Register values and expected results follow the operation descriptions and
# examples in SPRUFE8B (ADDSUB, ADDSUB2, DMV, SADDSUB, SADDSUB2, UNPKLU4).
CASES = [
    ("ADDSUB", "L", 1, 0, 0x0700C005, 0xFFFFFFFF, 0x0700C0040700C006, 0, 0),
    ("ADDSUB", "L", 2, 1, 0x7FFFFFFF, 0x00000001, 0x800000007FFFFFFE, 0, 0),
    ("ADDSUB2", "L", 1, 0, 0x0700C005, 0xFFFF0001, 0x06FFC0060701C004, 0, 0),
    ("ADDSUB2", "L", 2, 1, 0x7FFF8000, 0x0001FFFF, 0x80007FFF7FFE8001, 0, 0),
    ("SADDSUB", "L", 1, 0, 0x80000000, 0x00000001, 0x8000000180000000, 1, 1),
    ("SADDSUB", "L", 2, 1, 0x7FFFFFFF, 0x00000001, 0x7FFFFFFF7FFFFFFE, 1, 2),
    ("SADDSUB", "L", 2, 0, 0x0700C005, 0xFFFFFFFF, 0x0700C0040700C006, 0, 0),
    ("SADDSUB2", "L", 1, 0, 0x7FFF8000, 0xFFFFFFFF, 0x7FFE80007FFF8001, 0, 0),
    ("SADDSUB2", "L", 2, 1, 0x80007FFF, 0x0001FFFF, 0x80017FFE80007FFF, 0, 0),
    ("DMV", "S", 1, 0, 0x87654321, 0x12345678, 0x8765432112345678, 0, 0),
    ("DMV", "S", 2, 1, 0x00070009, 0x12345678, 0x0007000912345678, 0, 0),
    ("UNPKLU4", "L", 1, 0, None, 0xB1746CA4, 0x00006C00A4, 0, 0),
    ("UNPKLU4", "S", 2, 1, None, 0x123456FF, 0x00005600FF, 0, 0),
]


def opcode(mnemonic, unit, side, cross, pair):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    prefix = f":{mnemonic}.{unit}{side} "
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(prefix))
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    if pair:
        word |= 1 << 24  # destination A3:A2 / B3:B2
        word |= 1 << 13  # src1 A1/B1
    else:
        word |= 3 << 23  # scalar destination A3/B3
    word |= 2 << 18     # src2 A2/B2
    word |= cross << 12
    return word


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (mnemonic, unit, side, cross, a, b, result, sat, ssr) in enumerate(CASES):
            pair = mnemonic != "UNPKLU4"
            out.write(struct.pack(endian + "I", opcode(mnemonic, unit, side, cross, pair)))
            out.write(bytes(28))
            own, other = ("A", "B") if side == 1 else ("B", "A")
            src1 = f"{own}1" if pair else "-"
            src2 = f"{other if cross else own}2"
            dst = f"{own}3_{own}2" if pair else f"{own}3"
            rows.write(f"{index}\t{mnemonic}.{unit}{side}\t{src1}\t{src2}\t{dst}\t"
                       f"{(a or 0):08x}\t{b:08x}\t{result:016x}\t{sat}\t{ssr}\n")


if __name__ == "__main__":
    main()
