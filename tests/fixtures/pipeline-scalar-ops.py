#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""16x16 MPY family, ADDU/SUBU/SUBC, INTSPU, RCPSP/RSQRSP phase contracts,
SPRUFE8B pp.135-136,278,320-350,411-412,420-421,539-540,546-547. IMAGE CASES.json [be]."""
import json
from pathlib import Path
import struct
import sys

MASK40 = (1 << 40) - 1
# (mnemonic, src1 half, src1 signed, src2 half, src2 signed); half 0 = bits 15:0.
MULTIPLY = [('MPY', 0, 1, 0, 1), ('MPYU', 0, 0, 0, 0), ('MPYUS', 0, 0, 0, 1), ('MPYSU', 0, 1, 0, 0),
            ('MPYH', 1, 1, 1, 1), ('MPYHU', 1, 0, 1, 0), ('MPYHUS', 1, 0, 1, 1), ('MPYHSU', 1, 1, 1, 0),
            ('MPYHL', 1, 1, 0, 1), ('MPYHLU', 1, 0, 0, 0), ('MPYHULS', 1, 0, 0, 1), ('MPYHSLU', 1, 1, 0, 0),
            ('MPYLH', 0, 1, 1, 1), ('MPYLHU', 0, 0, 1, 0), ('MPYLUHS', 0, 0, 1, 1), ('MPYLSHU', 0, 1, 1, 0)]
# .M op field (bits 11:7), SPRUFE8B opcode maps; checked against cl6x 8.3.15 words.
MULTIPLY_OP = {'MPY': 0x19, 'MPYU': 0x1f, 'MPYUS': 0x1d, 'MPYSU': 0x1b, 'MPYH': 0x01, 'MPYHU': 0x07,
               'MPYHUS': 0x05, 'MPYHSU': 0x03, 'MPYHL': 0x09, 'MPYHLU': 0x0f, 'MPYHULS': 0x0d,
               'MPYHSLU': 0x0b, 'MPYLH': 0x11, 'MPYLHU': 0x17, 'MPYLUHS': 0x15, 'MPYLSHU': 0x13}


def half(value, high, signed):
    h = value >> 16 & 0xffff if high else value & 0xffff
    return h - 0x10000 if signed and h & 0x8000 else h


def m_unit(op, src1, src2, dst, side, cross=0, predicate=0):
    return predicate << 28 | dst << 23 | src2 << 18 | src1 << 13 | cross << 12 | op << 7 | side << 1


def l_unit(op, src1, src2, dst, side, cross=0, predicate=0):
    return predicate << 28 | dst << 23 | src2 << 18 | src1 << 13 | cross << 12 | op << 5 | 0x18 | side << 1


def s_unit(op, src2, dst, side, cross=0, predicate=0):
    return predicate << 28 | dst << 23 | src2 << 18 | cross << 12 | op << 6 | 0x20 | side << 1


def move(src, dst, side, unit):
    return dst << 23 | src << 18 | {'L': 0xfd8, 'S': 0x6a0}[unit] | side << 1


def single(value):
    return struct.unpack('<I', struct.pack('<f', value))[0]


def main():
    if len(sys.argv) not in (3, 4) or len(sys.argv) == 4 and sys.argv[3] != 'be':
        raise SystemExit(__doc__)
    endian = '>' if len(sys.argv) == 4 else '<'
    image = bytearray(0x10000)
    rows = []

    def emit(name, operation, packet, tail, inputs, expected, raw=None, match_raw=(), refused=None):
        packet = [w | int(i < len(packet) - 1) for i, w in enumerate(packet)]
        words = packet + tail + [0x000c0362, 0x00008000]
        entry = 0x1000 + len(rows) * 0x80
        assert len(words) <= 32
        for i, w in enumerate(words):
            struct.pack_into(endian + 'I', image, entry - 0x1000 + 4 * i, w)
        row = dict(name=name, operation=operation, entry=entry, packet=len(packet), input=inputs,
                   expected={**expected, 'PC': 0x9000}, words=[f'{w:08x}' for w in words])
        if raw is not None:
            row['raw'] = raw
            row['match_raw'] = list(match_raw)
        if refused:
            row['refused'] = refused
        rows.append(row)

    # form: operation, latency, unit, encoder(dst, side, cross, predicate, src1, src2), sources,
    # crossing source (1 or 2), oracle, pair destination, other unit for companions.
    forms = []
    for name, h1, s1, h2, s2 in MULTIPLY:
        forms.append((name, name, 2, 'M', lambda d, s, x, p, a, b, op=MULTIPLY_OP[name]:
                      m_unit(op, a, b, d, s, x, p), 2, 2,
                      lambda a, b, h1=h1, s1=s1, h2=h2, s2=s2: half(a, h1, s1) * half(b, h2, s2) & 0xffffffff,
                      False, 'L'))
    forms += [
        ('ADDU', 'ADDU', 1, 'L', lambda d, s, x, p, a, b: l_unit(0x2b, a, b, d, s, x, p), 2, 2,
         lambda a, b: (a + b) & MASK40, True, 'S'),
        # ADDU src1, src2 pair: the pair is local, src1 may cross.
        ('ADDU_pair', 'ADDU', 1, 'L', lambda d, s, x, p, a, b: l_unit(0x29, a, b, d, s, x, p), 2, 1,
         lambda a, b: (a + b) & MASK40, True, 'S'),
        ('SUBU', 'SUBU', 1, 'L', lambda d, s, x, p, a, b: l_unit(0x2f, a, b, d, s, x, p), 2, 2,
         lambda a, b: (a - b) & MASK40, True, 'S'),
        ('SUBU_x1', 'SUBU', 1, 'L', lambda d, s, x, p, a, b: l_unit(0x3f, a, b, d, s, x, p), 2, 1,
         lambda a, b: (a - b) & MASK40, True, 'S'),
        ('SUBC', 'SUBC', 1, 'L', lambda d, s, x, p, a, b: l_unit(0x4b, a, b, d, s, x, p), 2, 2,
         lambda a, b: ((a - b) << 1 | 1) & 0xffffffff if a >= b else a << 1 & 0xffffffff, False, 'S'),
        ('INTSPU', 'INTSPU', 4, 'L', lambda d, s, x, p, a, b: l_unit(0x49, 0, b, d, s, x, p), 1, 2,
         lambda a, b: single(float(b)), False, 'S'),
        ('RCPSP', 'RCPSP', 1, 'S', lambda d, s, x, p, a, b: s_unit(0x3d, b, d, s, x, p), 1, 2,
         lambda a, b: {0x40800000: 0x3e800000, 0x41000000: 0x3e000000}[b], False, 'L'),
        ('RSQRSP', 'RSQRSP', 1, 'S', lambda d, s, x, p, a, b: s_unit(0x3e, b, d, s, x, p), 1, 2,
         lambda a, b: {0x40800000: 0x3f000000, 0x41800000: 0x3e800000}[b], False, 'L'),
    ]
    values = {'M': (0x8765f432, 0xc3a19e27), 'L': (0x0000325a, 0xffffff12), 'S': (0x41000000, 0x40800000)}
    other_values = {'M': (0x7ffe8001, 0x12348765), 'L': (0xfffffff0, 0x00000011), 'S': (0x40800000, 0x41800000)}
    values['INTSPU'] = (0, 0xffffffde)  # SPRUFE8B INTSPU example, p.278
    other_values['INTSPU'] = (0, 0x80000001)  # inexact: FAUCR INEX
    other_values['RCPSP'] = (0, 0x41000000)

    for label, operation, latency, unit, encode, sources, crossing, oracle, pair, peer in forms:
        for side in (0, 1):
            bank = 'AB'[side]
            cross = side  # side 2 reads its crossing source from the A file
            x_bank = 'AB'[side ^ cross]
            src = {1: (bank, 2), 2: (bank, 13)}  # not B3, the return address
            src[crossing] = (x_bank, src[crossing][1])
            if pair and label == 'ADDU_pair':
                src[2] = (bank, 6)
            a, b = other_values.get(label, other_values[unit]) if side else values.get(label, values[unit])
            hi = 0x000000a5 if label == 'ADDU_pair' else 0

            def regs(a=a, b=b):
                r = {f'{src[2][0]}{src[2][1]}': b}
                if sources == 2:
                    r[f'{src[1][0]}{src[1][1]}'] = a
                if label == 'ADDU_pair':
                    r[f'{bank}7'] = hi
                return r

            def result(a=a, b=b):
                return oracle(a, (hi << 32 | b) if label == 'ADDU_pair' else b)

            new = result()
            old_lo, old_hi = 0x13579bdf, 0x2468ace0
            dst_regs = {f'{bank}4': old_lo, f'{bank}5': old_hi}
            after = {f'{bank}4': new & 0xffffffff}
            if pair:
                after[f'{bank}5'] = new >> 32
            raw = dict(after)
            match = {'S': ['FAUCR'], 'L': ['FADCR']}[unit] if label in ('INTSPU', 'RCPSP', 'RSQRSP') else []
            word = lambda p=0: encode(4, side, cross, p, src[1][1], src[2][1])
            stem = f'{label}_{unit}{side + 1}'

            # A same-packet reader sees the old destination; the result is
            # first visible to the packet issued `latency` cycles later.
            tail = [move(4, 8 + k, side, peer) for k in range(1, latency + 1)]
            seen = {f'{bank}{8 + k}': new & 0xffffffff if k >= latency else old_lo for k in range(1, latency + 1)}
            emit(f'{stem}_writeback_e{latency}', operation, [move(4, 8, side, peer), word()], tail,
                 {**regs(), **dst_regs}, {**after, f'{bank}8': old_lo, **seen}, raw, match)

            # A parallel writer listed first must not change a captured source.
            for which in range(3 - sources, 3):
                rb, rn = src[which]
                inputs = {**regs(), **dst_regs, f'{rb}10': 0xffffffff}
                emit(f'{stem}_capture_src{which}', operation,
                     [move(10, rn, 'AB'.index(rb), peer), word()], [0] * latency,
                     inputs, {**after, f'{rb}{rn}': 0xffffffff}, raw, match)

            # The predicate is sampled in E1, before a parallel write to it.
            for creg, preg in ((6, 'A0'), (1, 'B0')):
                for enabled in (1, 0):
                    inputs = {**regs(), **dst_regs, preg: enabled, f'{preg[0]}10': 1 - enabled}
                    emit(f'{stem}_{preg}_{"true" if enabled else "false"}', operation,
                         [move(10, int(preg[1]), 'AB'.index(preg[0]), peer), word(2 * creg)], [0] * latency,
                         inputs, {**(after if enabled else {f'{bank}4': old_lo, f'{bank}5': old_hi}),
                                  preg: 1 - enabled},
                         raw if enabled else {f'{bank}4': old_lo})

    # Two instructions on one unit in one packet are refused.
    for label, operation, unit, words in (
            ('MPYHLU', 'MPYHLU', 'M', [m_unit(0x0f, 2, 3, 4, 0), m_unit(0x0f, 2, 3, 5, 0)]),
            ('SUBU', 'SUBU', 'L', [l_unit(0x2f, 2, 3, 4, 0), l_unit(0x2f, 2, 3, 6, 0)]),
            ('RCPSP', 'RCPSP', 'S', [s_unit(0x3d, 2, 4, 0), s_unit(0x3d, 3, 5, 0)])):
        emit(f'{label}_{unit}1_unit_collision', operation, words, [], {}, {},
             refused='functional-unit collision')

    assert len(rows) == 333, len(rows)
    Path(sys.argv[1]).write_bytes(image)
    Path(sys.argv[2]).write_text(json.dumps(rows, indent=2) + '\n')


if __name__ == '__main__':
    main()
