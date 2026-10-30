#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Cross-path timing profiles, SPRU198K 6.3.2.2 / SPRUFE8B 3.8.4.

Synthetic instructions only. Usage: IMAGE CASES.json [be].
"""
from pathlib import Path
import json
import struct
import sys


def main():
    endian = '>' if len(sys.argv) > 3 and sys.argv[3] == 'be' else '<'
    image, rows = bytearray(), []
    ret = [0xc0362, 0x8000]  # B.S2 B3; NOP 5: six advances.

    def mvk(value, reg, side=0):
        return (reg << 23) | ((value & 0xffff) << 7) | 0x28 | (side << 1)

    def move(reg, dst, side=0, cross=False):
        return (dst << 23) | (reg << 18) | 0x58 | (side << 1) | (0x1000 if cross else 0)

    def emit(name, words, inputs, expected, cycles, stalls=0, incoming=(), memory=None, amr=False):
        at = 0x1000 + len(image)
        words += ret
        image.extend(struct.pack(endian + str(len(words)) + 'I', *words) + bytes(128 - 4 * len(words)))
        rows.append(dict(name=name, entry=at, input=inputs, expected=expected,
                         cycles=cycles, stalls=stalls, incoming=list(incoming),
                         memory=memory or {}, amr=amr))

    # Both cross paths; both possible writer predicate outcomes.
    for side, bank, other in [(0, 'A', 'B'), (1, 'B', 'A')]:
        for predicate in [None, 0, 1]:
            writer = mvk(5, 4, side) | (0x20000000 if predicate is not None else 0)  # [B0]
            value = 5 if predicate is None or predicate else 17
            emit(f'{bank}_to_{other}_{predicate}', [writer, move(4, 6, 1-side, True)],
                 {bank+'4': 17, 'B0': predicate or 0}, {other+'6': value}, 8,
                 1 if predicate is None or predicate else 0)
        emit(f'{bank}_incoming', [move(4, 6, 1-side, True)],
             {bank+'4': 5}, {other+'6': 5}, 7, 1, [bank+'4'])
        emit(f'{bank}_local', [mvk(5, 4, side), move(4, 6, side)],
             {}, {bank+'6': 5}, 8)

    ldw = (5 << 23) | (4 << 18) | 0x264
    emit('load_destination_not_e1', [ldw, 0x6000, move(5, 6, 1, True)],
         {'A4': 0x8000}, {'B6': 0x11223344}, 12, memory={'32768': 0x11223344})
    # An updating load still has an E1 base write even though its data arrives in E5.
    updating_ldw = (ldw & ~(15 << 9)) | (9 << 9) | (1 << 13)
    emit('load_base_is_e1', [updating_ldw, move(4, 6, 1, True), 0x6000],
         {'A4': 0x8000}, {'A4': 0x8004, 'B6': 0x8004, 'A5': 23}, 12, 1,
         memory={'32772': 23})
    emit('pending_load_during_stall', [ldw, mvk(5, 4, 1), move(4, 6, 0, True), 0x6000],
         {'A4': 0x8000}, {'A6': 5, 'A5': 0x11223344}, 13, 1, memory={'32768': 0x11223344})

    # ADDDP samples high words in E2. The parallel writer changes B9 in E1,
    # so the late cross-port read stalls on C64x/C674x, not on C67x.
    dp = (4 << 23) | (8 << 18) | 0x1318
    high_writer = (9 << 23) | (0x4000 << 7) | 0x6a  # MVKH.S2 0x4000,B9
    emit('dp_late_cross_port', [dp | 1, high_writer, 0xe000],
         {'A1': 0x3ff00000, 'B9': 0x40100000}, {'A4': 0, 'A5': 0x40080000}, 15, 1)

    # AMR hazards use a separate rule; disabling X-path stalls must not remove it.
    mvc_amr = (0 << 23) | (0 << 18) | 0x3a2  # MVC.S2 B0,AMR
    emit('amr_rule_retained', [mvc_amr, ldw, 0x8000],
         {'B0': 1, 'A4': 0x8000}, {'A5': 23}, 13, 1, memory={'32768': 23}, amr=True)

    Path(sys.argv[1]).write_bytes(image)
    Path(sys.argv[2]).write_text(json.dumps(rows, indent=2) + '\n')


if __name__ == '__main__':
    main()
