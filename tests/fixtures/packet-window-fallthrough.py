#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fall-through of windowed conditional jumps across mixed widths: IMAGE [be].

Hand-encoded words, checked against TI dis6x 8.3.15 (--data_as_text):

  1000: [A1] B.S1 0x1010       32-bit, parallel with the next instruction
  1004: || ADD.L1 A4,A5,A4     compact; ends the execute packet
  1006: BNOP.S2 B3,0           compact; a return in the jump's delay slots
  1008: NOP 5 | NOP            compact
  100c: NOP
  1010: B.S2 B3 | NOP 5 | NOP  header 0xe0c00000 (words 1 and 2 compact)

  1020: [A1] B.S1 0x1030       32-bit; five delay slots, 10 bytes
  1024: MVK.S1 2,A5            slot 1
  1028: ADD.L1 A4,A5,A4        slot 2
  102c: NOP 3                  compact; slots 3-5
  102e: ADD.L1 A4,A6,A4        compact; runs when A1 is zero
  1030: BNOP.S2 B3,0 | NOP 5   compact; header 0xe3000000 (words 3 and 4 compact)

The return in its slots keeps the first jump's full window from being proved,
so it keeps the packet primer's two-byte window. Ghidra's generic fall-through
re-parses delay slots with the jump's own context (Ghidra #10242): it gives
0x1004, the jump's own slot, for the first and 0x1030 for the second. The next
execute packets are 0x1006 and 0x102e (SPRUFE8B 3.5, 3.10).
"""
from pathlib import Path
import struct
import sys
import compact_order

compact_order.big_endian_on_exit()


def packet(endian, words, header):
    data = b''
    for word in words:
        # Compact words list their two slots in execution order.
        data += struct.pack(endian + 'HH', *word) if isinstance(word, tuple) else struct.pack(endian + 'I', word)
    return data + struct.pack(endian + 'I', header)


if __name__ == '__main__':
    if len(sys.argv) not in (2, 3) or len(sys.argv) == 3 and sys.argv[2] != 'be':
        raise SystemExit(__doc__)
    endian = '>' if len(sys.argv) == 3 else '<'
    image = packet(endian, [0x80000211, (0x82c0, 0x01ef), (0x8c6e, 0x0c6e), 0, 0x000c0362, 0x00008000, 0],
                   0xe0c00000)
    image += packet(endian, [0x80000210, 0x02800128, 0x02148078, (0x4c6e, 0x8340), (0x01ef, 0x8c6e), 0, 0],
                    0xe3000000)
    Path(sys.argv[1]).write_bytes(image)
