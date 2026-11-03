#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SPRUFE8B Figure G-3 predicate truth tables: IMAGE CASES.json [be].

Independent compact encodings, not firmware bytes. Each function contains
MVK, NOP and BNOP B3,5, permitting both raw and exact-schedule execution.
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
    image, manifest = map(Path, sys.argv[1:3])
    endian = '>' if len(sys.argv) == 4 else '<'
    packets, cases = [], []
    # Figure G-3: CC=00/01/10/11 selects A0/!A0/B0/!B0. The predicate
    # registers stay in the low bank regardless of the fetch header's RS.
    for cc, predicate in enumerate(('A0', '!A0', 'B0', '!B0')):
        predicate_register = predicate.lstrip('!')
        for immediate in (0, 1):
            for unit, unit_bits in (('L', 0), ('S', 1), ('D', 2)):
                destinations = [(side, rs, 5) for side in (0, 1) for rs in (0, 1)]
                # Overwriting the predicate itself must test its incoming value.
                destinations.append((int(predicate_register == 'B0'), 0, 0))
                for side, rs, dst in destinations:
                    bank = 'AB'[side]
                    destination = bank + str(16 * rs + dst)
                    alias = destination == predicate_register
                    word = cc << 14 | immediate << 13 | 0x0866 | dst << 7 | unit_bits << 3 | side
                    header = 0xe0200000 | rs << 19
                    # Full32 BNOP B3,5 from SPRUFE8B Figure F-1/Table 4-11.
                    packet = struct.pack(endian + 'HHI', word, 0x0c6e, 0x008ca362)
                    packets.append(packet + bytes(20) + struct.pack(endian + 'I', header))
                    checks = []
                    for value in (0, 1, 0xffffffff):
                        enabled = (value == 0) if predicate.startswith('!') else (value != 0)
                        initial = value if alias else 0x13579bdf
                        checks.append([value, immediate if enabled else initial])
                    cases.append(dict(
                        mnemonic=f'[{predicate}]MVK.{unit}{side + 1}',
                        immediate=immediate, predicate_register=predicate_register,
                        destination=destination, shadow=bank + str(16 * (1 - rs) + dst),
                        checks=checks))
    image.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    image.write_bytes(b''.join(packets))
    manifest.write_text(json.dumps(cases, indent=2) + '\n')
    print(f'cases={len(cases)} raw_checks={sum(len(c["checks"]) for c in cases)}')


if __name__ == '__main__':
    main()
