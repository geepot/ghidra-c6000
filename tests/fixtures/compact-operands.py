#!/usr/bin/env python3
"""Generate independent compact operand and signed MVK regressions.

Usage: compact-operands.py IMAGE CASES.tsv [be]
Encoding authority: SPRUFE8B Figures C-12/C-13/C-16, G-4 and MVK
(.L/.D) opcode/execution descriptions pp. 380-381. No firmware bytes.
"""
from pathlib import Path
import struct
import sys
import compact_order

compact_order.big_endian_on_exit()


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != 'be'):
        raise SystemExit(__doc__)
    endian = '>' if len(sys.argv) == 4 else '<'
    image, manifest = map(Path, sys.argv[1:3])
    packets, rows = [], []

    def case(kind, word, compact, rs, dsz, mnemonic, reg, ptr='-', count=0,
             size=0, immediate=0, predicate=-1):
        index = len(rows)
        header = 0xe0000000 | (int(compact) << 21) | (rs << 19) | (dsz << 16)
        packet = (struct.pack(endian + 'H', word) + bytes(26)
                  if compact else struct.pack(endian + 'I', word) + bytes(24))
        packets.append(packet + struct.pack(endian + 'I', header))
        rows.append(f'{index}\t{kind}\t{2 if compact else 4}\t{mnemonic}\t'
                    f'{reg}\t{ptr}\t{count}\t{size}\t{immediate}\t{predicate}')

    # C-16: ucst1:0 in bits14:13; ucst4:2 in bits9:7. Distinct
    # values in every stack word expose the erroneous reversed concatenation.
    for rs in (0, 1):
        for data_side in (0, 1):
            reg = f'{"AB"[data_side]}{16 * rs + 3}'
            for load in (0, 1):
                for offset in range(32):
                    opcode = (0x8c05 | ((offset & 3) << 13) | (data_side << 12)
                              | ((offset >> 2) << 7) | (3 << 4) | (load << 3))
                    mnemonic = ('LDW' if load else 'STW') + '.D2'
                    case('stack-load' if load else 'stack-store', opcode, True,
                         rs, 0, mnemonic, reg, 'B15', offset, 4)

    # C-12/C-13: postincrement uses old pointer for access and increments
    # by (encoded ucst0+1)*access size. Exercise both files, RS and t.
    for rs in (0, 1):
        for side in (0, 1):
            for data_side in (0, 1):
                for load in (0, 1):
                    for size, dsz, sz, suffix in [(1, 0, 1, 'BU'), (2, 2, 1, 'HU'),
                                                (4, 0, 0, 'W'), (8, 4, 0, 'DW')]:
                        for count in (1, 2):
                            opcode = (0x0c04 | ((count - 1) << 13) | (data_side << 12)
                                      | (sz << 9) | (2 << 7) | (4 << 4)
                                      | (load << 3) | side)
                            reg = f'{"AB"[data_side]}{16 * rs + 4}'
                            ptr = f'{"AB"[side]}6'  # Table C-2: ptr ignores header RS.
                            suffix = suffix if load else suffix.rstrip('U')
                            case('post-load' if load else 'post-store', opcode, True,
                                 rs, dsz, ('LD' if load else 'ST') + suffix + f'.D{side + 1}',
                                 reg, ptr, count, size)

    # The store-width helper is shared by the offset, indirect and
    # predecrement formats too (C-8/C-10/C-14): guard their adjacent bytes.
    for kind, fixed in [('offset-store', 0), ('indirect-store', 0x400),
                        ('decrement-store', 0x6c00)]:
        for size, dsz, suffix in [(1, 0, 'B'), (2, 2, 'H')]:
            high = 2 << 13 if kind == 'offset-store' else 1 << 13
            opcode = high | fixed | (1 << 9) | (2 << 7) | (4 << 4) | 4
            case(kind, opcode, True, 0, dsz, 'ST' + suffix + '.D1', 'A4', 'A6', 2, size)

    # G-4's ADD and XOR have explicit src,1,dst with src=dst. Checking
    # all legal unit encodings also catches operand rendering hidden in mnemonic.
    for rs in (0, 1):
        for side in (0, 1):
            for unit, unit_bits in [('L', 0), ('S', 1), ('D', 2)]:
                for op, name in [(5, 'ADD'), (7, 'XOR')]:
                    opcode = ((op << 13) | 0x1866 | (unit_bits << 3) | (5 << 7) | side)
                    reg = f'{"AB"[side]}{16 * rs + 5}'
                    case(name.lower(), opcode, True, rs, 0, f'{name}.{unit}{side + 1}', reg)

    # .L and .D signed five-bit MVK: all constants and both register files.
    # .L's field is bits22:18; .D's is bits17:13. x is not an operand.
    for unit in ('L', 'D'):
        for side in (0, 1):
            for bits in range(32):
                signed = bits if bits < 16 else bits - 32
                word = ((5 << 23) | ((bits << 18) | 0xa358 if unit == 'L'
                                      else (bits << 13) | 0x40) | (side << 1))
                case('mvk', word, False, 0, 0, f'MVK.{unit}{side + 1}',
                     f'{"AB"[side]}5', immediate=signed)
            for signed in (-16, -1):
                for predicate in (0, 1):
                    bits = signed & 31
                    word = ((6 << 29) | (5 << 23) |
                            ((bits << 18) | 0xa358 if unit == 'L' else (bits << 13) | 0x40)
                            | (side << 1))
                    case('mvk', word, False, 0, 0, f'[A0]MVK.{unit}{side + 1}',
                         f'{"AB"[side]}5', immediate=signed, predicate=predicate)

    image.parent.mkdir(parents=True, exist_ok=True)
    data = b''.join(packets)
    # Mapped scratch memory at0x8000 for memory semantics and guard bytes.
    image.write_bytes(data + bytes(max(0, 0x10000 - len(data))))
    manifest.write_text('\n'.join(rows) + '\n')
    print(f'cases={len(rows)} endian={endian}')


if __name__ == '__main__':
    main()
