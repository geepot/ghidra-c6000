#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Floating-point arithmetic, conversion and compare forms on exact values. IMAGE CASES.json [be].

Load at 0x1000 without auto-analysis. One instruction per 32-byte fetch packet,
followed by NOP 9 and a return, so each is also a function with an exact schedule;
src1 A2 or A3:A2, src2 A12 or A13:A12, dst A4 or A5:A4. The opcode fields are
checked against GNU objdump; no firmware bytes. Every value is exact, and no
SPINT/DPINT input is a halfway case, so the default languages' bit-exact models
and the analysis languages' plain p-code give the same result.
C6000AnalysisFloatTest.java checks the results in all four language variants,
emulated and through the exact schedule, and that the analysis variants use
floating-point p-code and one status userop.
"""
import json
from pathlib import Path
import struct
import sys


def d(value):
    bits = struct.unpack('<Q', struct.pack('<d', value))[0]
    return bits & 0xffffffff, bits >> 32


def f(value):
    return struct.unpack('<I', struct.pack('<f', value))[0]


def pair(name, value):
    lo, hi = d(value)
    return {f'A{name}': lo, f'A{name + 1}': hi}


# (mnemonic, opcode fields, inputs, outputs)
CASES = [
    ('ABSDP', 0xb20, pair(12, -2.5), pair(4, 2.5)),
    ('ABSSP', 0xf20, {'A12': f(-2.5)}, {'A4': f(2.5)}),
    ('MPYSP', 0xe00, {'A2': f(1.5), 'A12': f(2.25)}, {'A4': f(3.375)}),
    ('ADDSP', 0x218, {'A2': f(1.5), 'A12': f(2.25)}, {'A4': f(3.75)}),
    ('ADDDP', 0x318, {**pair(2, 1.5), **pair(12, 2.25)}, pair(4, 3.75)),
    ('SUBDP', 0x338, {**pair(2, 1.5), **pair(12, 2.25)}, pair(4, -0.75)),
    ('MPYDP', 0x700, {**pair(2, 1.5), **pair(12, 2.25)}, pair(4, 3.375)),
    ('MPYSPDP', 0x5b0, {'A2': f(1.5), **pair(12, 2.25)}, pair(4, 3.375)),
    ('MPYSP2DP', 0x5f0, {'A2': f(1.5), 'A12': f(2.25)}, pair(4, 3.375)),
    ('SPDP', 0x0a0, {'A12': f(1.5)}, pair(4, 1.5)),
    ('DPSP', 0x138, pair(12, 2.25), {'A4': f(2.25)}),
    ('SPINT', 0x158, {'A12': f(2.75)}, {'A4': 3}),
    ('SPTRUNC', 0x178, {'A12': f(-2.75)}, {'A4': 0xfffffffe}),
    ('DPINT', 0x118, pair(12, -2.75), {'A4': 0xfffffffd}),
    ('DPTRUNC', 0x038, pair(12, 2.75), {'A4': 2}),
    ('CMPEQDP', 0xa20, {**pair(2, 1.5), **pair(12, 1.5)}, {'A4': 1}),
    ('CMPGTDP', 0xa60, {**pair(2, 2.25), **pair(12, 1.5)}, {'A4': 1}),
    ('CMPLTDP', 0xaa0, {**pair(2, 2.25), **pair(12, 1.5)}, {'A4': 0}),
]
UNARY = {'ABSSP', 'SPDP', 'SPINT', 'SPTRUNC'}
# A unary pair source is encoded as cl6x and GNU as do: src2 the odd register, src1 the low one
# (see dp-convert-src1.py and unary-dp-src1.py).
PAIR_SOURCE = {'ABSDP', 'DPSP', 'DPINT', 'DPTRUNC'}


def main():
    if len(sys.argv) not in (3, 4) or len(sys.argv) == 4 and sys.argv[3] != 'be':
        raise SystemExit(__doc__)
    endian = '>' if len(sys.argv) == 4 else '<'
    image, rows = bytearray(32 * len(CASES)), []
    for index, (mnemonic, low, inputs, outputs) in enumerate(CASES):
        src2, src1 = (13, 12) if mnemonic in PAIR_SOURCE else (12, 0 if mnemonic in UNARY else 2)
        # NOP 9 lets every result land before B B3 ; NOP 5 returns
        for k, word in enumerate((4 << 23 | src2 << 18 | src1 << 13 | low, 8 << 13, 3 << 18 | 0x362, 4 << 13)):
            struct.pack_into(endian + 'I', image, 32 * index + 4 * k, word)
        rows.append(dict(index=index, mnemonic=mnemonic, input=inputs, expected=outputs))
    Path(sys.argv[1]).write_bytes(image)
    Path(sys.argv[2]).write_text(json.dumps(rows, indent=2) + '\n')


if __name__ == '__main__':
    main()
