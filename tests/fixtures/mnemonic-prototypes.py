#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Every compact word, compact words under each header field value, and 32-bit words.

Usage: mnemonic-prototypes.py IMAGE [be]

C6000MnemonicPrototypesTest decodes the image and checks that every instruction of one
prototype prints the same mnemonic, with no operand text in it: C6000CallAnalyzer.mnemonic()
keeps one mnemonic per prototype. Nine compact constructors once joined their operands to the
mnemonic ("MVK.D1 0, A3"), and which instruction was asked first decided what the others saw.

Compact packets (SPRUFE8B 3.10.2): header word 7 with layout 0x7f (words 0-6 compact) and all
p-bits clear, 14 halfwords to a packet. The base header (PROT=RS=DSZ=BR=SAT=0) holds all 65,536
halfwords. Each header with one field changed from the base (PROT=1, RS=1, BR=1, SAT=1, DSZ=1..7)
holds 8,192 halfwords from a fixed seed. The 32-bit packets hold 32,768 words from a fixed seed,
none of them a header in word 7. Packet priming dominates the run time, so the image is kept small.
"""
from pathlib import Path
import random
import struct
import sys

import compact_order

compact_order.big_endian_on_exit()

SAMPLE32 = 32_768
SAMPLE16 = 8_192


def header(prot=0, rs=0, dsz=0, br=0, sat=0):
    return (0xE0000000 | 0x7F << 21 | prot << 20 | rs << 19 | dsz << 16 | br << 15 | sat << 14)


def variants():
    yield header()
    yield header(prot=1)
    yield header(rs=1)
    yield header(br=1)
    yield header(sat=1)
    for dsz in range(1, 8):
        yield header(dsz=dsz)


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    out = bytearray()
    rng = random.Random(0x6000)
    for index, head in enumerate(variants()):
        words = list(range(0x10000)) if index == 0 else [rng.getrandbits(16) for _ in range(SAMPLE16)]
        words += [0] * (-len(words) % 14)
        for at in range(0, len(words), 14):
            out += struct.pack(endian + "14H", *words[at:at + 14]) + struct.pack(endian + "I", head)
    for _ in range(SAMPLE32 // 8):
        packet = [rng.getrandbits(32) for _ in range(8)]
        while packet[7] >> 28 == 0xE:
            packet[7] = rng.getrandbits(32)
        out += struct.pack(endian + "8I", *packet)
    Path(sys.argv[1]).write_bytes(bytes(out))


if __name__ == "__main__":
    main()
