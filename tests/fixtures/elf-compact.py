#!/usr/bin/env python3
"""cl6x compact (header-based) fetch packets in an ELF with a non-allocated
.TI.section.flags section, issues #31 and #33. Usage: IMAGE [be].

Bytes are cl6x 8.3.15 -mv6740 output; dis6x lists, in either byte order:
  1000 q1: ADD.L2 B5,B4,B4 | MV.L1 A4,A5 | BNOP.S2 B3,0 | NOP 5
  1008 f2: ADD.L1 | MV.L2 | ADD.L1 | MV.L2 | BNOP.S2 B3,0 | NOP 5 | NOP | NOP
  1020 f3: LDW.D2T2 *B4[0],B5 | NOP 4 | ADD.L2 | MV.L1 | ADD.L2 | MV.L1 | BNOP.S2 B3,0 | NOP 5
Each word holds its first instruction in the 16 LSBs (SPRUFE8B 3.10.2.3, Table 3-16).
"""

from pathlib import Path
import runpy
import sys

elf = runpy.run_path(str(Path(__file__).with_name("elf-local-label.py")))
HALVES = {
    0x1000: [0xa241, 0xa246, 0x01ef, 0x8c6e, 0x8240, 0xa247, 0xa240, 0xc2c7, 0x01ef, 0x8c6e],
    0x1020: [0x105d, 0x6c6e, 0xa2d1, 0xa246, 0xa241, 0xc2c6, 0x01ef, 0x8c6e],
}
HEADERS = {0x101c: 0xe3e00000, 0x103c: 0xe1e00000}
SYMS = [("q1", 0x1000, 1, 0), ("f2", 0x1008, 1, 0), ("f3", 0x1020, 1, 0)]


def words():
    text = dict(HEADERS)
    for base, halves in HALVES.items():
        for i in range(0, len(halves), 2):
            text[base + 2 * i] = halves[i + 1] << 16 | halves[i]
    return text


if __name__ == "__main__":
    Path(sys.argv[1]).write_bytes(elf["build"](len(sys.argv) > 2 and sys.argv[2] == "be",
                                               words(), SYMS, 0x40, b"\x01\x00\x00\x00"))
