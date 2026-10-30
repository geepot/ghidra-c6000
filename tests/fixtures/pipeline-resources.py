#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Physical packet resources, even for false/complementary predicates.

IMAGE CASES.json [be]. SPRUFE8B 3.6, 3.8.1, 3.8.5; SPRU733A
3.6, 3.7.1, 3.7.4. Synthetic manual encodings; no assembler dependency.
"""
import json
from pathlib import Path
import struct
import sys


# Keep the data arena outside the complete generated instruction image.
ARENA = 0x20000


def operation(unit, side, dst, predicate=0):
    # MV .L/.S/.D (OR/ADD aliases), MPY .M. Manual full32 fields.
    opcode = {'L': 0xfd8, 'S': 0x6a0, 'D': 0x940, 'M': 0xc80}[unit]
    return (predicate << 28 | dst << 23 | 4 << 18 |
            (5 << 13 if unit == 'M' else 0) | opcode | side << 1)


def memory(load, side, bank, data, predicate=0):
    # SPRUFE8B 3.9.3: mode=0001 (*base), y chooses .D, s chooses T.
    return (predicate << 28 | data << 23 | 4 << 18 | 1 << 9 |
            (0x64 if load else 0x74) | side << 7 | bank << 1)


def main():
    if len(sys.argv) not in (3, 4) or len(sys.argv) == 4 and sys.argv[3] != 'be':
        raise SystemExit(__doc__)
    endian = '>' if len(sys.argv) == 4 else '<'
    image, rows = bytearray(), []

    def emit(name, words, inputs, expected=None, refusal=None, prefix=(), expected_memory=None):
        at = 0x1000 + len(image)
        packet = [word | int(i < len(words) - 1) for i, word in enumerate(words)]
        code = [*prefix, *packet, 0xc0362, 0x8000]  # B.S2 B3; NOP 5
        image.extend(struct.pack(endian + str(len(code)) + 'I', *code) + bytes(128 - 4 * len(code)))
        rows.append(dict(name=name, entry=at, input=inputs, expected=expected or {},
                         refusal=refusal, memory={str(ARENA-4): 0xabcdef01, str(ARENA): 0x11223344, str(ARENA+4): 0xfeedface,
                                                  str(ARENA+12): 0x10293847, str(ARENA+16): 0x55667788, str(ARENA+20): 0x76543210},
                         expected_memory=expected_memory or {}))

    predicates = [('B0', 2), ('B1', 4), ('B2', 6), ('A1', 8), ('A2', 10), ('A0', 12)]
    for side, bank in enumerate('AB'):
        for unit in 'LSDM':
            emit(f'{unit}{side+1}_unconditional_collision',
                 [operation(unit, side, 6), operation(unit, side, 7)], {}, refusal='functional-unit collision')
            for preg, encoding in predicates:
                emit(f'{unit}{side+1}_{preg}_complementary_collision',
                     [operation(unit, side, 6, encoding), operation(unit, side, 7, encoding | 1)],
                     {}, refusal='functional-unit collision')
            # A preceding constant proves one instruction is disabled. The
            # physical functional-unit allocation must still be rejected.
            emit(f'{unit}{side+1}_known_false_collision',
                 [operation(unit, side, 6, 12), operation(unit, side, 7, 13)],
                 {}, refusal='functional-unit collision', prefix=[0x28])  # MVK.S1 0,A0
        for left, right in [('L', 'S'), ('D', 'M')]:
            for preg, encoding in predicates:
                for value in (0, 1, 0xffffffff):
                    inputs = {bank+'4': 11, bank+'5': 3, bank+'6': 0x1234, bank+'7': 0x5678, preg: value}
                    result = {'L': 11, 'S': 11, 'D': 11, 'M': 33}
                    emit(f'{left}{right}{side+1}_{preg}_{value}_separate_units',
                         [operation(left, side, 6, encoding), operation(right, side, 7, encoding | 1)], inputs,
                         {bank+'6': result[left] if value else 0x1234,
                          bank+'7': 0x5678 if value else result[right]})

        # Predicates can suppress register writes on different functional units.
        # Do not confuse this legal case with physical issue-unit allocation.
        for preg, encoding in predicates:
            for value in (0, 1, 0xffffffff):
                emit(f'{bank}_{preg}_{value}_shared_destination',
                     [operation('L', side, 6, encoding), operation('S', side, 6, encoding | 1) + (1 << 18)],
                     {bank+'4': 11, bank+'5': 3, preg: value}, {bank+'6': 11 if value else 3})

    for bank in (0, 1):
        for first_load in (False, True):
            for second_load in (False, True):
                for predicated in (False, True):
                    emit(f'T{bank+1}_{first_load}_{second_load}_pred{predicated}_collision',
                         [memory(first_load, 0, bank, 6, 2 if predicated else 0),
                          memory(second_load, 1, bank, 7, 3 if predicated else 0)], {},
                         refusal='memory-transfer path collision')
                for value in (None, 0, 1):
                    inputs = {'A4': ARENA, 'B4': ARENA+16, 'AB'[bank]+'6': 0xaabbccdd,
                              'AB'[1-bank]+'7': 0x10203040, 'B0': value or 0}
                    expected, stored = {}, {}
                    for load, data_bank, register, address, data, enabled in (
                            (first_load, bank, 6, ARENA, 0x11223344, value is None or bool(value)),
                            (second_load, 1-bank, 7, ARENA+16, 0x55667788, value is None or not value)):
                        if enabled:
                            if load:
                                expected['AB'[data_bank]+str(register)] = data
                            else:
                                stored[str(address)] = inputs['AB'[data_bank]+str(register)]
                    emit(f'T{bank+1}_{first_load}_{second_load}_p{value}_separate_paths',
                         [memory(first_load, 0, bank, 6, 2 if value is not None else 0),
                          memory(second_load, 1, 1-bank, 7, 3 if value is not None else 0)],
                         inputs, expected, expected_memory=stored)

    # C674x compact C-8/C-12 formats: independent .D/address and T/data
    # selectors, with both header RS values and a shared compact payload word.
    for rs in (0, 1):
        for bank in (0, 1):
            for first_load in (False, True):
                for second_load in (False, True):
                    for same in (False, True):
                        second_bank = bank if same else 1-bank
                        first_reg, second_reg = 16*rs+6, 16*rs+7
                        inputs = {'A4': ARENA, 'B4': ARENA+16, 'AB'[bank]+str(first_reg): 0xaabbccdd,
                                  'AB'[second_bank]+str(second_reg): 0x10203040}
                        expected, stored = {}, {}
                        for load, data_bank, register, address, data in (
                                (first_load, bank, first_reg, ARENA, 0x11223344),
                                (second_load, second_bank, second_reg, ARENA+16, 0x55667788)):
                            if load:
                                expected['AB'[data_bank]+str(register)] = data
                            else:
                                stored[str(address)] = inputs['AB'[data_bank]+str(register)]
                        emit(f'compact_rs{rs}_T{bank+1}_{first_load}_{second_load}_same{same}',
                             [0], inputs, expected, 'memory-transfer path collision' if same else None,
                             expected_memory=stored)
                        struct.pack_into(endian+'HH', image, len(image)-128,
                                         bank << 12 | 6 << 4 | int(first_load) << 3 | 4,
                                         second_bank << 12 | 7 << 4 | int(second_load) << 3 | 5)
                        struct.pack_into(endian+'I', image, len(image)-128+28, 0xe0200001 | rs << 19)

    assert len(rows) == 244
    assert 0x1000 + len(image) < ARENA-4
    Path(sys.argv[1]).write_bytes(image)
    Path(sys.argv[2]).write_text(json.dumps(rows, indent=2) + '\n')


if __name__ == '__main__':
    main()
