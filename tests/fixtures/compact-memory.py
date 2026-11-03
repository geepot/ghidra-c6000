#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compact AMR and overlapping memory operands: IMAGE CASES.json [be].

Independent encodings and byte-level expectations from SPRUFE8B 2.8.3,
3.9.2, 4.2.5-4.2.6 and Figures C-8..C-15. No firmware or assembler input.
"""
import json
from pathlib import Path
import struct
import sys
import compact_order

compact_order.big_endian_on_exit()


ARENA = 0x20000
MEMORY = bytes((0x81 + 37 * i) & 255 for i in range(512))
# name, size, DSZ, sz, na, signed load
FORMATS = [
    ('BU', 1, 0, 1, 0, False), ('B', 1, 1, 1, 0, True),
    ('HU', 2, 2, 1, 0, False), ('H', 2, 3, 1, 0, True),
    ('W', 4, 0, 0, 0, False), ('DW', 8, 4, 0, 0, False),
    ('NW', 4, 6, 1, 0, False), ('NDW', 8, 4, 0, 1, False),
]


def main():
    if len(sys.argv) not in (3, 4) or len(sys.argv) == 4 and sys.argv[3] != 'be':
        raise SystemExit(__doc__)
    image, manifest = map(Path, sys.argv[1:3])
    big = len(sys.argv) == 4
    endian, byteorder = ('>', 'big') if big else ('<', 'little')
    packets, cases = [], []

    def emit(fmt, mode, load, side, rs, amode, pointer, data_side, low, alias=False):
        suffix, size, dsz, sz, na, signed = fmt
        bank, data_bank = 'AB'[side], 'AB'[data_side]
        base_reg, data_reg = f'{bank}{pointer}', f'{data_bank}{16 * rs + low}'
        index_reg = f'{bank}{16 * rs + 1}'
        nonaligned = suffix in ('NW', 'NDW')
        # Distinct BK0/BK1 sizes catch the wrong selector, register or side.
        amr = (4 << 16) | (5 << 21) | (amode << (2 * (pointer - 4) + 8 * side))
        block_size = 64 if amode == 2 else 32
        block = ARENA + 128
        count = 3 if mode == 'offset' else 9 if mode == 'indirect' else 2
        # Nonaligned post-increment also crosses the edge within the transfer.
        base = block if mode == 'decrement' else block + block_size - (1 if nonaligned else size)
        if nonaligned and mode == 'decrement':
            base += 1
        scale = 1 if suffix == 'NDW' and mode in ('offset', 'indirect') else size
        delta = count * scale * (-1 if mode == 'decrement' else 1)

        def address(value):
            return block + (value - block) % block_size if amode else value

        effective = address(base + delta)
        access = base if mode == 'increment' else effective
        next_base = effective if mode in ('increment', 'decrement') else base
        inputs = {'AMR': amr, 'CSR': 0x2468, 'B3': 0x9000,
                  data_reg: 0x89abcdef}
        if size == 8:
            inputs[f'{data_bank}{16 * rs + low + 1}'] = 0x12345678
        inputs.update({base_reg: base, index_reg: count})
        expected = dict(inputs)
        expected[base_reg] = next_base
        memory = bytearray(MEMORY)
        addresses = [address(access + i) if nonaligned else access + i for i in range(size)]
        if load:
            value = int.from_bytes(bytes(memory[a - ARENA] for a in addresses), byteorder, signed=signed)
            expected[data_reg] = value & 0xffffffff
            if size == 8:
                expected[f'{data_bank}{16 * rs + low + 1}'] = value >> 32
        else:
            value = inputs[data_reg]
            if size == 8:
                value |= inputs[f'{data_bank}{16 * rs + low + 1}'] << 32
            for a, byte in zip(addresses, (value & ((1 << (8 * size)) - 1)).to_bytes(size, byteorder)):
                memory[a - ARENA] = byte

        # Direct manual fields. ptr is fixed-low; data/index obey header RS.
        if mode == 'offset':
            bits = ((count & 7) << 13) | ((count >> 3) << 11)
        elif mode == 'indirect':
            bits = (1 << 13) | 0x400
        else:
            bits = ((count - 1) << 13) | 0xc00 | (0x4000 if mode == 'decrement' else 0)
        word = (bits | data_side << 12 | (pointer - 4) << 7 | low << 4
                | na << 4 | sz << 9 | int(load) << 3 | 4 | side)
        header = 0xe0200000 | rs << 19 | dsz << 16

        def move(src, dst, file):
            return dst << 23 | src << 18 | 0xfd8 | file << 1

        # Observe E1 pointer writeback before E5 load data, then observe the
        # loaded/source data after E5. BNOP's five idle cycles drain stores.
        words = [move(pointer, 24, side), 0x2000,
                 move(16 * rs + low, 25, data_side),
                 move(16 * rs + low + 1, 26, data_side) if size == 8 else 0,
                 0x008ca362, 0]
        packet = struct.pack(endian + 'HH6II', word, 0x0c6e, *words, header)
        assert len(packet) == 32
        packets.append(packet)
        scheduled = dict(expected)
        scheduled[f'{bank}24'] = next_base
        scheduled[f'{data_bank}25'] = expected[data_reg]
        if size == 8:
            scheduled[f'{data_bank}26'] = expected[f'{data_bank}{16 * rs + low + 1}']

        mnemonic = ('LD' + suffix if load else 'ST' + suffix.rstrip('U')) + f'.D{side + 1}'
        left, right = ('(', ')') if suffix == 'NDW' and mode in ('offset', 'indirect') else ('[', ']')
        offset = index_reg if mode == 'indirect' else f'0x{count:x}'
        operand = ('*--' if mode == 'decrement' else '*') + base_reg
        operand += ('++' if mode == 'increment' else '') + left + offset + right
        data = f'{data_bank}{16 * rs + low + 1}:' + data_reg if size == 8 else data_reg
        assembly = mnemonic + ' ' + (operand + ',' + data if load else data + ',' + operand)
        cases.append(dict(name=f'{len(cases)}_{suffix}_{mode}_mode{amode}' + ('_alias' if alias else ''),
                          assembly=assembly, input=inputs, raw_expected=expected,
                          scheduled_expected=scheduled, memory=memory.hex(), alias=alias))

    for fmt_index, fmt in enumerate(FORMATS):
        for mode_index, mode in enumerate(('offset', 'indirect', 'increment', 'decrement')):
            for load in (False, True):
                for side in (0, 1):
                    for rs in (0, 1):
                        for amode in (0, 1, 2):
                            # Cover all four eligible pointers and both data
                            # sides without a redundant full Cartesian product.
                            pointer = 4 + (fmt_index + mode_index + amode + rs) % 4
                            emit(fmt, mode, load, side, rs, amode, pointer,
                                 side ^ ((fmt_index + mode_index + amode) % 2),
                                 0 if fmt[1] == 8 else 2)

    # Isolate predecrement source aliases from AMR, then combine both fixes.
    # Pair cases overlap either the even or the odd word of the source/dst.
    for fmt in FORMATS:
        if fmt[0] in ('BU', 'HU'):
            continue
        for side in (0, 1):
            for load in (False, True):
                for mode in ('increment', 'decrement'):
                    for amode in (0, 1, 2):
                        for pointer in ((4, 5) if fmt[1] == 8 else (4,)):
                            emit(fmt, mode, load, side, 0, amode, pointer, side, 4, True)

    assert len(cases) == 960
    image.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    image.write_bytes(b''.join(packets))
    manifest.write_text(json.dumps(cases, indent=2) + '\n')
    print(f'cases={len(cases)} alias_cases={sum(c["alias"] for c in cases)}')


if __name__ == '__main__':
    main()
