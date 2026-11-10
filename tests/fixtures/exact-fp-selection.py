#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact SP arithmetic, aliases and predication. IMAGE CASES.tsv [be].

SPRUFE8B 3.12 ADDSP/SUBSP/MPYSP and 2.10.1/2.10.3. The result oracle
uses rational arithmetic, independently of the model's DP intermediates.
"""
import importlib.util
import random
import struct
import sys
from pathlib import Path


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'),
                                                Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


add = load('float-addsub-sp')
multiply = load('mpysp')


def product(a, b, mode):
    ae, be = (a >> 23) & 255, (b >> 23) & 255
    af, bf = a & 0x7fffff, b & 0x7fffff
    an, bn = ae == 255 and af != 0, be == 255 and bf != 0
    ad, bd = ae == 0 and af != 0, be == 0 and bf != 0
    sign = (a ^ b) & 0x80000000
    flags = int(an) | (int(bn) << 1) | (int(ad) << 2) | (int(bd) << 3)
    if (an and not af & 0x400000) or (bn and not bf & 0x400000):
        flags |= 0x10
    if ((ad and be != 255 and b & 0x7fffffff) or
            (bd and ae != 255 and a & 0x7fffffff)):
        flags |= 0x80
    if an or bn:
        return sign | 0x7fffffff, flags
    if ae == 255 or be == 255:
        if ae == 0 or be == 0:
            return sign | 0x7fffffff, flags | 0x10
        return sign | 0x7f800000, flags | 0x20
    exact = abs(add.value(a) * add.value(b))
    if not exact:
        return sign, flags
    return add.finite_bits(exact, sign, mode, flags)


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = '>' if len(sys.argv) > 3 and sys.argv[3] == 'be' else '<'
    pairs = list(add.OPERANDS[:21])
    pairs += [(a, b) for a, b, _, _ in multiply.CASES]
    rng = random.Random(0xe6ac7)
    pairs += [(rng.getrandbits(32), rng.getrandbits(32)) for _ in range(32)]
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open('wb') as out, manifest.open('w') as rows:
        index = 0
        for mnemonic in ('ADDSP', 'SUBSP', 'MPYSP'):
            unit = 'M' if mnemonic == 'MPYSP' else 'L'
            control = 'FMCR' if unit == 'M' else 'FADCR'
            for side in (1, 2):
                bank = 'A' if side == 1 else 'B'
                for mode in range(4):
                    for a, b in pairs:
                        for dst in (1, 2, 4):
                            # Same-bank src1/src2 aliases, with [A0]/[!A0] true/false.
                            for predicate in ('always', 'true', 'false'):
                                if unit == 'M':
                                    word = multiply.opcode(side, False)
                                    result, flags = product(a, b, mode)
                                else:
                                    field = '0010000' if mnemonic == 'ADDSP' else '0010001'
                                    word = add.opcode(mnemonic, unit, side, field, False)
                                    result, flags = add.expected(a, b, mnemonic == 'SUBSP', False, mode)
                                word = (word & ~(31 << 23)) | (dst << 23)
                                inverted = index & 1
                                pred_value = 1
                                if predicate != 'always':
                                    word |= (6 << 29) | (inverted << 28)
                                    pred_value = int(predicate == 'true') ^ inverted
                                initial = (mode << (9 + (16 if side == 2 else 0))) | 0x00410041
                                expected_flags = initial | (flags << (16 if side == 2 else 0))
                                if predicate == 'false':
                                    result = a if dst == 1 else b if dst == 2 else 0x5a5a5a5a
                                    expected_flags = initial
                                out.write(struct.pack(endian + 'I', word) + bytes(28))
                                values = [index, f'{mnemonic}.{unit}{side}', bank+'1', bank+'2',
                                          bank+str(dst), f'{a:x}', f'{b:x}', f'{result:x}',
                                          control, f'{initial:x}', f'{expected_flags:x}', pred_value]
                                rows.write('\t'.join(map(str, values))+'\n')
                                index += 1


if __name__ == '__main__':
    main()
