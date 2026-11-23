#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build one nonaligned transfer per fetch packet. Usage: IMAGE MANIFEST [be].

Load at 0x1000 without auto-analysis. Encodings come from the generated
decode table (SPRUFE8B LDNW p.295, LDNDW p.292, STNW, STNDW), offset zero, so
each transfer uses its base register's value; each packet ends in NOP 5:

  1000  LDNW.D1   *+A4[0],A5
  1020  LDNDW.D1  *+A4[0],A7:A6
  1040  STNW.D1   A5,*+A4[0]
  1060  STNDW.D1  A7:A6,*+A4[0]

C6000AnalysisNonalignedTest.java checks that the analysis languages lift each
as one access of the whole width and the exact languages byte by byte, and
that all four languages move the same bytes with AMR zero.
"""

from pathlib import Path
import re
import struct
import sys

# mnemonic, data register, width in bytes
CASES = [
    ("LDNW.D1", "A5", 4),
    ("LDNDW.D1", "A7_A6", 8),
    ("STNW.D1", "A5", 4),
    ("STNDW.D1", "A7_A6", 8),
]


def encode(mnemonic, target):
    decode = Path(__file__).resolve().parents[2] / "data/languages/c6000_decode.sinc"
    line = next(line for line in decode.read_text().splitlines()
                if line.startswith(f':^Cond^"{mnemonic}" ') and "mode=0x1 " in line)
    word = sum(int(value) << int(bit) for bit, value in
               re.findall(r"\bi(\d+)=(\d)\b", line))
    word |= 1 << 9  # *+base[offset], with offset zero
    word |= 4 << 18  # base A4
    if "_" in target:
        word |= (int(target.split("_")[1][1:]) // 2) << 24
    else:
        word |= int(target[1:]) << 23
    return word


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "be"):
        raise SystemExit(__doc__)
    image, manifest = map(Path, sys.argv[1:3])
    endian = ">" if len(sys.argv) == 4 else "<"
    data = bytearray(0x80)
    for index, (mnemonic, target, _) in enumerate(CASES):
        struct.pack_into(endian + "I", data, index * 32, encode(mnemonic, target))
        struct.pack_into(endian + "I", data, index * 32 + 4, 4 << 13)  # NOP 5
    image.parent.mkdir(parents=True, exist_ok=True)
    image.write_bytes(data)
    manifest.write_text("".join(f"{index}\t{mnemonic}\t{target}\t{width}\n"
                                for index, (mnemonic, target, width) in enumerate(CASES)))


if __name__ == "__main__":
    main()
