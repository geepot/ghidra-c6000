#!/usr/bin/env python3
"""Build compact SAT-bit edge cases from SPRUFE8B Figures D-4/D-5/E-5/F-22..26.

Each case occupies one 32-byte compact fetch packet.  The first halfword is
the instruction under test; the header sets layout word 0 and the requested
SAT bit.  Output is a raw image and a TSV of expected register/CSR values for
C6000CompactSaturationTest.java.  No assembler-specific compact directives are
needed to exercise header-dependent decoding.
"""

import struct
import sys
from pathlib import Path


def l3(op):
    return (1 << 13) | (op << 11) | (2 << 7) | (3 << 4)


def m3(op):
    return (1 << 13) | (3 << 10) | (2 << 7) | (op << 5) | 0x1e


def s3(op):
    return (1 << 13) | (op << 11) | (2 << 7) | (3 << 4) | 0x0a


def sshl_imm(count):
    return sh5(2, count)


def s2sh(op):
    return (1 << 13) | (op << 11) | (1 << 10) | (2 << 7) | 0x62


def l3i():
    return (1 << 10) | (2 << 7) | (3 << 4)


def s3i():
    return (1 << 10) | (2 << 7) | (3 << 4) | 0x0a


def sh5(op, count):
    return ((count & 7) << 13) | ((count >> 3) << 11) | (1 << 10) | (2 << 7) | (op << 5) | 2


# name, opcode, SAT, A1, A2, destination, expected result, CSR.SAT, optional BR
CASES = [
    ("SADD-positive", l3(0), 1, 0x7fffffff, 1, "A3", 0x7fffffff, 1),
    ("SADD-normal", l3(0), 1, 0xfffffffc, 3, "A3", 0xffffffff, 0),
    ("SSUB-negative", l3(1), 1, 0x80000000, 1, "A3", 0x80000000, 1),
    ("SSUB-positive", l3(1), 1, 0x7fffffff, 0xffffffff, "A3", 0x7fffffff, 1),
    ("SMPY", m3(0), 1, 0x00008000, 0x00008000, "A6", 0x7fffffff, 1),
    ("SMPYH", m3(1), 1, 0x80000000, 0x80000000, "A6", 0x7fffffff, 1),
    ("SMPYLH", m3(2), 1, 0x00008000, 0x80000000, "A6", 0x7fffffff, 1),
    ("SMPYHL", m3(3), 1, 0x80000000, 0x00008000, "A6", 0x7fffffff, 1),
    ("SMPY-normal", m3(0), 1, 0x00007fff, 2, "A6", 0x0001fffc, 0),
    ("SADD-S", s3(0), 1, 0x7fffffff, 1, "A3", 0x7fffffff, 1),
    ("SSHL-immediate", sshl_imm(1), 1, 0, 0x40000000, "A2", 0x7fffffff, 1),
    ("SSHL-register", s2sh(3), 0, 1, 0xa0000000, "A2", 0x80000000, 1),
    ("SSHL-large", s2sh(3), 0, 32, 1, "A2", 0x7fffffff, 1),
    ("SSHL-zero", s2sh(3), 0, 32, 0, "A2", 0, 0),
    ("SHL-sat-ignored", s2sh(0), 1, 1, 0x40000000, "A2", 0x80000000, 0),
    ("SHL-six-bit-count", s2sh(0), 1, 32, 1, "A2", 0, 0),
    ("ADD-immediate-sat-ignored", l3i(), 1, 0, 2, "A3", 10, 0),
    ("SHL-immediate-sat-ignored", s3i(), 1, 0, 2, "A3", 0x20000, 0),
    ("SHL-sh5-sat-ignored", sh5(0, 1), 1, 0, 0x40000000, "A2", 0x80000000, 0),
    # F-25..F-28 have no BR column in their opcode maps.  The firmware uses
    # these formats in packets whose BR expansion bit is set.
    ("SHL-br", sh5(0, 1), 0, 0, 0x40000000, "A2", 0x80000000, 0, 1),
    ("SSHL-br", sshl_imm(1), 1, 0, 0x40000000, "A2", 0x7fffffff, 1, 1),
    ("SET-br", (1 << 13) | (2 << 7) | (1 << 5) | 2, 0,
     0, 0, "A2", 2, 0, 1),
    ("EXT-br", (1 << 13) | (2 << 7) | 0x62, 0,
     0, 0x1234ffff, "A1", 0xffffffff, 0, 1),
]


def main():
    image = Path(sys.argv[1])
    manifest = Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as output, manifest.open("w") as cases:
        for index, (name, opcode, sat, a1, a2, dst, expected, csr_sat, *rest) in enumerate(CASES):
            br = rest[0] if rest else 0
            header = 0xe0000000 | (1 << 21) | (br << 15) | (sat << 14)
            output.write(struct.pack(endian + "H", opcode))
            output.write(bytes(26))
            output.write(struct.pack(endian + "I", header))
            cases.write(f"{index}\t{name}\t{a1:08x}\t{a2:08x}\t{dst}\t{expected:08x}\t{csr_sat}\n")


if __name__ == "__main__":
    main()
