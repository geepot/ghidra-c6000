#!/usr/bin/env python3
"""Generate DINT/RINT register-transition cases. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# The first four opcodes also form DINT,DINT,RINT,RINT for the nested test.
CASES = [
    ("DINT", 0x001, 0x001, 0x002, 0x000),
    ("DINT", 0x003, 0x003, 0x002, 0x002),
    ("RINT", 0x002, 0x000, 0x001, 0x001),
    ("RINT", 0x003, 0x003, 0x001, 0x003),
    ("DINT", 0x145, 0x203, 0x146, 0x202),
    ("RINT", 0x146, 0x202, 0x145, 0x203),
    ("DINT", 0x142, 0x202, 0x140, 0x202),
    ("RINT", 0x145, 0x202, 0x144, 0x202),
]


def opcode(mnemonic):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(f":{mnemonic} is "))
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    return sum(value << bit for bit, value in fixed.items())


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (mnemonic, tsr, csr, expected_tsr, expected_csr) in enumerate(CASES):
            out.write(struct.pack(endian + "I", opcode(mnemonic)))
            out.write(bytes(28))
            rows.write(f"{index}\t{mnemonic}\t{tsr:x}\t{csr:x}\t"
                       f"{expected_tsr:x}\t{expected_csr:x}\n")
        out.write(struct.pack(endian + "I", opcode("IDLE")))
        out.write(bytes(28))


if __name__ == "__main__":
    main()
