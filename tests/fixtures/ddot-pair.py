#!/usr/bin/env python3
"""Build DDOTPH2/PL2 and rounded variants. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# mnemonic, side, cross, src1_o:src1_e, src2, result, CSR.SAT, SSR.M1/M2
# The operands and outputs are from SPRUFE8B's instruction examples.
CASES = [
    ("DDOTPH2", 1, 0, 0x0002000400050003, 0x00070001, 0x0000001200000021, 0, 0),
    ("DDOTPL2", 1, 0, 0x0002000400050003, 0x00070001, 0x0000002100000026, 0, 0),
    ("DDOTPH2", 1, 0, 0x1234800080005678, 0x80008000, 0x36E600007FFFFFFF, 1, 0x10),
    ("DDOTPL2", 1, 0, 0x1234800080005678, 0x80008000, 0x7FFFFFFF14C40000, 1, 0x10),
    ("DDOTPH2", 2, 1, 0xBBAED16946B416BA, 0x340BF73B, 0xF3B4FAADF41B4AFF, 0, 0),
    ("DDOTPL2", 2, 1, 0xBBAED16946B416BA, 0x340BF73B, 0xF41B4AFF0D984C9A, 0, 0),
    ("DDOTPH2R", 1, 0, 0xBBAED16946B416BA, 0x340BF73B, 0xF3B5F41B, 0, 0),
    ("DDOTPL2R", 1, 0, 0xBBAED16946B416BA, 0x340BF73B, 0xF41B0D98, 0, 0),
    ("DDOTPH2R", 1, 0, 0x1234800080005678, 0x80008001, 0x36E67FFF, 1, 0x10),
    ("DDOTPL2R", 1, 0, 0x1234800080005678, 0x80008001, 0x7FFF14C4, 1, 0x10),
    ("DDOTPH2R", 2, 0, 0x8000800080008000, 0x80008001, 0x7FFF7FFF, 1, 0x20),
    ("DDOTPL2R", 2, 0, 0x8000800080008000, 0x80008001, 0x7FFF7FFF, 1, 0x20),
]


def opcode(mnemonic, side, cross):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    prefix = f":{mnemonic}.M{side} "
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(prefix))
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    word = sum(value << bit for bit, value in fixed.items())
    word |= 4 << 13  # source pair A5:A4 / B5:B4
    word |= 6 << 18  # src2 A6/B6
    word |= (8 << 23) if mnemonic.endswith("R") else (4 << 24)
    word |= cross << 12
    return word


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (mnemonic, side, cross, a, b, expected, sat, ssr) in enumerate(CASES):
            out.write(struct.pack(endian + "I", opcode(mnemonic, side, cross)))
            out.write(bytes(28))
            own, other = ("A", "B") if side == 1 else ("B", "A")
            src1 = f"{own}5_{own}4"
            src2 = f"{other if cross else own}6"
            dst = f"{own}8" if mnemonic.endswith("R") else f"{own}9_{own}8"
            rows.write(f"{index}\t{mnemonic}.M{side}\t{src1}\t{src2}\t{dst}\t"
                       f"{a:016x}\t{b:08x}\t{expected:016x}\t{sat}\t{ssr}\n")


if __name__ == "__main__":
    main()
