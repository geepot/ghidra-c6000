#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build 64-bit arguments and results in register pairs. Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000AbiPairsTest.java prepare declares the
six functions, as ELF symbols would. Words are TI cl6x 8.3.15 output
(-mv6740 --abi=eabi --no_compress -O2, linked at 0x1000) of:

  1000 long long twice64(long long x) { return x + x; }
  1014 void sink(int a, char *p, int n) { g = a + p[0] + n; }
  102c double second(int k, double y) { return y * (double)k; }
  1048 void pass(int a, char x) { char b[4]; b[0] = x; sink(a, b, 1); }
  1068 long long neg64(long long x) { return -x; }
  1084 long long callit(long long x) { return neg64(x) + twice64(x); }

A 64-bit x arrives in A5:A4, y in B5:B4, and a 64-bit result leaves in A5:A4.
pass hands its a to sink in A4 without touching it.
"""

from pathlib import Path
import struct
import sys

WORDS = [
    0x008C6362, 0x0294A079, 0x0193E9A0, 0x02946FF9, 0x021081E0, 0x021002A6, 0x00000000, 0x008C4362,
    0x01909078, 0x018CC078, 0x0180007C, 0x02100738, 0x03101FD8, 0x03941FD8, 0x00000000, 0x0210C700,
    0x00004000, 0x008CA362, 0x07BE09C2, 0x023D02B7, 0x023D005B, 0x000C1FD9, 0x1FFFFA93, 0x030000A8,
    0x00809362, 0x178004FE, 0x008C2362, 0x01940FD9, 0x02800028, 0x0210A5F8, 0x02971849, 0x018C00D8,
    0x02946078, 0x000C1FD9, 0x1FFFFD13, 0x041006A1, 0x039408F0, 0x04900FD8, 0x1FFFF013, 0x02200FD9,
    0x031406A1, 0x029C08F0, 0x00805362, 0x019406A1, 0x02248578, 0x018CA078, 0x02986078, 0x00000000,
]


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0xC0)
    for index, word in enumerate(WORDS):
        struct.pack_into(endian + "I", image, 4 * index, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
