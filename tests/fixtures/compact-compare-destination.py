#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic SPRUFE8B Figures D-7/D-9/D-10: IMAGE MANIFEST [be]."""
import json
from pathlib import Path
import struct
import sys


def result(operation, a, b):
    signed = lambda x: x if x < 0x80000000 else x - 0x100000000
    return {'AND': lambda: a & b, 'OR': lambda: a | b, 'XOR': lambda: a ^ b,
            'CMPEQ': lambda: int(a == b), 'CMPLT': lambda: int(signed(a) < signed(b)),
            'CMPGT': lambda: int(signed(a) > signed(b)), 'CMPLTU': lambda: int(a < b),
            'CMPGTU': lambda: int(a > b)}[operation]()


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = '>' if len(sys.argv) > 3 and sys.argv[3] == 'be' else '<'
    cases = []
    for side in (0, 1):
        bank, opposite = ('A', 'B') if side == 0 else ('B', 'A')
        for rs in (0, 1):
            for dst in (0, 1):
                common = dict(destination=bank + str(dst), shadow=bank + str(16 + dst),
                              header=0xe0200000 | rs << 19)
                # D-9 exhaustive three-bit immediate and source fields.
                for immediate in range(8):
                    for source in range(8):
                        cases.append(dict(common, word=0x26 | side | dst << 11 | source << 7 | immediate << 13,
                            operation='CMPEQ', mnemonic='CMPEQ.L' + str(side + 1), source1=None,
                            source2=bank + str(16 * rs + source), immediate=immediate,
                            checks=[[immediate, immediate, 1], [immediate, immediate ^ 0x80000000, 0]]))
                # D-7 all operations, cross paths, sides, RS values and destinations.
                for op, operation in enumerate(('AND', 'OR', 'XOR', 'CMPEQ', 'CMPLT', 'CMPGT', 'CMPLTU', 'CMPGTU')):
                    for cross in (0, 1):
                        values = [(5, 5), (0x80000000, 1)]
                        cases.append(dict(common, word=0x408 | side | dst << 4 | 3 << 13 | 4 << 7 | cross << 12 | (op >> 2) << 11 | (op & 3) << 5,
                            operation=operation, mnemonic=operation + '.L' + str(side + 1) + ('X' if cross else ''),
                            source1=bank + str(16 * rs + 3), source2=(opposite if cross else bank) + str(16 * rs + 4), immediate=0,
                            checks=[[a, b, result(operation, a, b)] for a, b in values]))
                # D-10 comparison direction, signedness, immediate bit and both results.
                for op, operation in enumerate(('CMPLT', 'CMPGT', 'CMPLTU', 'CMPGTU')):
                    for immediate in (0, 1):
                        values = (immediate, 0x80000000, 0xffffffff)
                        cases.append(dict(common, word=0x1026 | side | dst << 11 | 6 << 7 | immediate << 13 | op << 14,
                            operation=operation, mnemonic=operation + '.L' + str(side + 1), source1=None,
                            source2=bank + str(16 * rs + 6), immediate=immediate,
                            checks=[[immediate, value, result(operation, immediate, value)] for value in values]))
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open('wb') as binary, manifest.open('w') as text:
        for case in cases:
            binary.write(struct.pack(endian + 'HH', case.pop('word'), 0) + bytes(24) + struct.pack(endian + 'I', case.pop('header')))
            text.write(json.dumps(case) + '\n')
    print('cases', len(cases), 'executions', sum(len(case['checks']) for case in cases))


if __name__ == '__main__':
    main()
