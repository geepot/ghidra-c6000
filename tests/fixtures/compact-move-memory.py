#!/usr/bin/env python3
"""Synthetic compact extended-register and NDW scale regressions.

Usage: compact-move-memory.py IMAGE CASES.tsv [be]
Authority: SPRUFE8B G-1/G-2, C-9/C-11/C-13/C-15 and Table C-2.
No firmware or external assembler input is needed.
"""
from pathlib import Path
import struct
import sys


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != 'be'):
        raise SystemExit(__doc__)
    endian = '>' if len(sys.argv) == 4 else '<'
    image, manifest = map(Path, sys.argv[1:3])
    packets, rows = [], []

    def emit(word, rs, dsz, kind, mnemonic, a, b, base='-', index='-',
             count=0, na=0, mode='-'):
        header = 0xe0200000 | (rs << 19) | (dsz << 16)
        packets.append(struct.pack(endian + 'H', word) + bytes(26) +
                       struct.pack(endian + 'I', header))
        rows.append(f'{len(rows)}\t{kind}\t{mnemonic}\t{a}\t{b}\t{base}\t'
                    f'{index}\t{count}\t{na}\t{mode}')

    # One operand is explicit five-bit srcms:src2 or dstms:dst. RS only
    # selects the other three-bit operand. Sweep every extended value.
    for direction in ('to', 'from'):
        for rs in (0, 1):
            for side in (0, 1):
                for cross in (0, 1):
                    for unit, ubits in [('L', 0), ('S', 1), ('D', 2)]:
                        for wide in range(32):
                            small = 4
                            if direction == 'to':
                                word = ((small << 13) | (cross << 12) | (wide << 7)
                                        | (ubits << 3) | 6 | side)
                                src = f'{"AB"[side ^ cross]}{wide}'
                                dst = f'{"AB"[side]}{16 * rs + small}'
                            else:
                                word = (((wide & 7) << 13) | (cross << 12)
                                        | ((wide >> 3) << 10) | (small << 7)
                                        | (ubits << 3) | 0x46 | side)
                                src = f'{"AB"[side ^ cross]}{16 * rs + small}'
                                dst = f'{"AB"[side]}{wide}'
                            emit(word, rs, 0, 'move', f'MV.{unit}{side + 1}{"X" if cross else ""}', src, dst)

    # Offset/indirect NDW uses bytes; NDW inc/dec is always scaled by8.
    # Aligned DW is a control: it remains scaled by8 in every format.
    for mode in ('offset', 'indirect', 'increment', 'decrement'):
        for na in (0, 1):
            for rs in (0, 1):
                for side in (0, 1):
                    for data_side in (0, 1):
                        for load in (0, 1):
                            counts = (1, 8) if mode == 'offset' else ((1, 3) if mode == 'indirect' else (1, 2))
                            for count in counts:
                                if mode == 'offset':
                                    fixed = ((count & 7) << 13) | ((count >> 3) << 11)
                                elif mode == 'indirect':
                                    fixed = (1 << 13) | 0x400
                                else:
                                    fixed = ((count - 1) << 13) | 0xc00
                                    if mode == 'decrement':
                                        fixed |= 0x4000
                                word = (fixed | (data_side << 12) | (2 << 7) | (2 << 5)
                                        | (na << 4) | (load << 3) | 4 | side)
                                low = 16 * rs + 4
                                suffix = 'NDW' if na else 'DW'
                                mnemonic = ('LD' if load else 'ST') + suffix + f'.D{side + 1}'
                                emit(word, rs, 4, 'load' if load else 'store', mnemonic,
                                     f'{"AB"[data_side]}{low}', f'{"AB"[data_side]}{low + 1}',
                                     f'{"AB"[side]}6', f'{"AB"[side]}{16 * rs + 1}', count, na, mode)

    image.parent.mkdir(parents=True, exist_ok=True)
    data = b''.join(packets)
    # Code ends before0x10000;0x20000 is a mapped guarded memory arena.
    image.write_bytes(data + bytes(max(0, 0x21000 - len(data))))
    manifest.write_text('\n'.join(rows) + '\n')
    print(f'cases={len(rows)} endian={endian}')


if __name__ == '__main__':
    main()
