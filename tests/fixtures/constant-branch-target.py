#!/usr/bin/env python3
"""Synthetic MVK/MVKH/register-branch reference checks. IMAGE CASES.tsv [be].

Encodings and expectations: SPRUFE8B MVK/MVKL pp. 381/385,
MVKH pp. 383-384, B register and pipeline Table 4-11.
No firmware bytes or another disassembler's implementation are used.
"""
from pathlib import Path
import struct
import sys

# bank, register, low half, high half, predicated high, parallel high, alternate entry
CASES = [
    (1, 4, 0xcc40, 0xc004, False, False, False),
    (2, 10, 0xcc40, 0xc004, False, False, False),
    (2, 4, 0x2340, 0x1180, False, False, False),
    (1, 5, 0x9340, 0x1180, False, False, False),
    (2, 6, 0xcc40, 0xc004, True, False, False),
    (2, 7, 0xcc40, 0xc004, False, True, False),
    (2, 8, 0xcc40, 0xc004, False, False, True),
    (2, 9, 0xcc42, 0xc004, False, False, False),
    # A later MVK in the branch's own execute packet: the branch reads the address built before it.
    (2, 11, 0xcc40, 0xc004, False, False, False, 0x2340),
]

def main():
    image, cases = map(Path, sys.argv[1:3])
    endian = '>' if len(sys.argv) > 3 and sys.argv[3] == 'be' else '<'
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open('wb') as out, cases.open('w') as rows:
        for i, (bank, reg, low, high, predicate, parallel, entry, *stale) in enumerate(CASES):
            side = (bank - 1) << 1
            mvk = (reg << 23) | (low << 7) | 0x28 | side
            mvkh = (reg << 23) | (high << 7) | 0x68 | side
            if predicate: mvkh |= 1 << 29  # [B0]
            if parallel: mvkh |= 1
            branch = (reg << 18) | 0x362 | (0x1000 if bank == 1 else 0)
            words = [mvk, mvkh, branch, 0x8000] + [0] * 4  # NOP 5
            if stale:  # MVK stale,reg || B reg
                words = [mvk, mvkh, (reg << 23) | (stale[0] << 7) | 0x28 | side | 1, branch, 0x8000] + [0] * 3
            out.write(struct.pack(endian + '8I', *words))
            exact = (high << 16) | low
            intermediate = low if low < 0x8000 else low | 0xffff0000
            # An entry at the MVKH leaves the low half unknown on that path, which no target can
            # stand for: the address built from the top is the one known target. An address that
            # is not word-aligned is still the one the unpredicated pair builds.
            mode = 'entered' if entry or (exact & 3) else 'conservative' if predicate or parallel else 'exact'
            rows.write(f'{0x1000+32*i:x}\t{exact:08x}\t{intermediate:08x}\t{mode}\t{int(entry)}\t{12 if stale else 8}\n')

if __name__ == '__main__':
    main()
