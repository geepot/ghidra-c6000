#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""BNOP inserted-idle counts, SPRUFE8B F-17/F-18/F-20/F-21/F-32.

IMAGE CASES.json [be]. Fixed-five forms have literal, not Scalar, operands.
Displacement functions take 15 cycles; register returns take seven.
"""
import json
from pathlib import Path
import struct
import sys
import compact_order

compact_order.big_endian_on_exit()


def main():
    if len(sys.argv) not in (3, 4) or len(sys.argv) == 4 and sys.argv[3] != 'be':
        raise SystemExit(__doc__)
    endian = '>' if len(sys.argv) == 4 else '<'
    image, rows = bytearray(0x8000), []

    def emit(kind, side, count, rs=0, inverted=None, predicate=1, backward=False, br=1):
        base = 0x1000 + len(rows) * 0x100
        entry = base + (64 if backward else 0)
        target = base if backward else base + 96
        packet = entry & ~31
        branch = entry + 4
        compact = kind != 'full_register'
        predicated = inverted is not None
        taken = not predicated or ((predicate == 0) if inverted else predicate != 0)

        def full(at, word):
            struct.pack_into(endian + 'I', image, at - 0x1000, word)

        # LDW.D1 *A10[0],A4: E1 issue, E5 data. It must complete during
        # the branch window; an incorrect implicit count executes the guard.
        full(entry, 4 << 23 | 10 << 18 | 0x264)
        if kind == 'fixed':
            word = 0xc00a | ((target - packet) // 2) << 6 | side
        elif kind == 'variable':
            word = count << 13 | (((target - packet) // 2) & 127) << 6 | 0xa | side
        elif kind == 'register':
            word = count << 13 | 3 << 7 | 0x6f  # BNOP.S2 B3,N3, BR-independent
        else:
            word = 1 << 23 | 3 << 18 | count << 13 | 0x362
        if predicated:
            word |= 0x20 | inverted << 4
        if compact:
            struct.pack_into(endian + 'HH', image, branch - 0x1000, word, 0x0c6e)
            # Branch and NOP 1 share their EP; only word 2 is compact.
            full(packet + 28, 0xe0400004 | br << 15 | rs << 19)

        else:
            full(branch, word)
        cursor = entry + 8
        for _ in range(5 - count):
            full(cursor, 0)
            cursor += 4
            if compact and cursor == packet + 28:
                cursor += 4
        # Fallthrough guard must execute only when a predicate is false.
        for word in (8 << 23 | 0x22 << 7 | 0x28, 6 << 23 | 4 << 18 | 0xfd8, 0x008ca362):
            if compact and cursor == packet + 28:
                cursor += 4
            full(cursor, word)
            cursor += 4
        # Taken target: read the loaded word, mark this path, return.
        full(target, 6 << 23 | 4 << 18 | 0xfd8)
        full(target + 4, 7 << 23 | 0x77 << 7 | 0x28)
        full(target + 8, 0x008ca362)
        inputs = {'A4': 0x13579bdf, 'A10': 0x20000, 'B1': target,
                  'B3': 0x9000, 'CSR': 0x2468, 'AMR': 0}
        if predicated:
            inputs['AB'[side] + '0'] = predicate
        expected = dict(inputs)
        expected.update(A4=0x89abcdef, A6=0x89abcdef,
                        A7=0x77 if taken else 0, A8=0 if taken else 0x22, PC=0x9000)
        register = kind in ('register', 'full_register')
        if register:
            expected.update(A6=0, A7=0, A8=0)
        rows.append(dict(name=f'{len(rows)}_{kind}_s{side+1}_n{count}_rs{rs}_z{inverted}_p{predicate:x}',
                         entry=entry, start=base, end=base+0xf0, branch=branch,
                         input=inputs, expected=expected, count=count, cycles=7 if register else 15,
                         literal=kind == 'fixed'))

    for side in (0, 1):
        for rs in (0, 1):
            emit('fixed', side, 5, rs)
            for inverted in (0, 1):
                for predicate in (0, 1, 0xffffffff):
                    emit('fixed', side, 5, rs, inverted, predicate)
        for count in range(6):
            emit('variable', side, count)
            emit('variable', side, count, backward=True)
            for inverted in (0, 1):
                for predicate in (0, 1):
                    emit('variable', side, count, inverted=inverted, predicate=predicate)
    for count in range(6):
        for br in (0, 1):
            emit('register', 1, count, br=br)
        emit('full_register', 1, count)
    assert len(rows) == 118
    Path(sys.argv[1]).write_bytes(image)
    Path(sys.argv[2]).write_text(json.dumps(rows, indent=2) + '\n')


if __name__ == '__main__':
    main()
