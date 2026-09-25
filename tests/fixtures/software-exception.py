#!/usr/bin/env python3
"""Build isolated SWE/SWENR instruction cases. IMAGE CASES.tsv [be]."""
import re
import struct
import sys
from pathlib import Path


# mnemonic, initial TSR. GEE=0 and GEE=1 are exercised for each opcode.
CASES = [("SWE", 0x43), ("SWE", 0x47),
         ("SWENR", 0x43), ("SWENR", 0x47)]


def opcode(mnemonic):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(f":{mnemonic} is "))
    fixed = {int(bit): int(value) for bit, value in
             re.findall(r"\bi(\d+)=(\d)\b", line)}
    return sum(value << bit for bit, value in fixed.items())


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (mnemonic, tsr) in enumerate(CASES):
            address = 0x1000 + 32 * index
            out.write(struct.pack(endian + "I", opcode(mnemonic)))
            out.write(bytes(28))
            enabled = (tsr & 4) != 0
            final_tsr = ((tsr & 0x14) | 0x400) if enabled else (
                tsr | (0x8000 if mnemonic == "SWENR" else 0))
            final_ntsr = tsr if enabled and mnemonic == "SWE" else 0x22
            final_nrp = address + 4 if enabled and mnemonic == "SWE" else 0x5678
            final_pc = (0x1020 if mnemonic == "SWE" else 0x1060) if enabled else address + 4
            rows.write(f"{index}\t{mnemonic}\t{tsr:x}\t2\t10022\t5678\t1000\t1060\t"
                       f"{final_tsr:x}\t3\t{final_ntsr:x}\t{final_nrp:x}\t{final_pc:x}\n")


if __name__ == "__main__":
    main()
