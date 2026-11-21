#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a function that reads the time-stamp counter. Usage: IMAGE [be].

Load at 0x1000 without auto-analysis. Independent manual fields (SPRUFE8B MVC p.376,
2.9.14), checked against GNU objdump; no firmware bytes:

  1000  MVC.S2  TSCL,B4
  1004  MVC.S2  TSCH,B5
  1008  NOP
  100c  MV.L1X  B4,A4
  1010  MV.L1X  B5,A5
  1014  BNOP.S2 B3,5

C6000PipelineTscTest.java compiles its exact schedule and runs it with the
counter reads answering fixed values.
"""

from pathlib import Path
import struct
import sys


def mvc_from(control, dst):
    """MVC.S2 control,Bdst."""
    return dst << 23 | control << 18 | 0x3E2


def mv_cross(src, dst):
    """MV.L1X Bsrc,Adst."""
    return dst << 23 | src << 18 | 1 << 12 | 0xFD8


WORDS = [mvc_from(0x0A, 4), mvc_from(0x0B, 5), 0, mv_cross(4, 4), mv_cross(5, 5), 0x800362 | 3 << 18 | 5 << 13]


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x20)
    for index, word in enumerate(WORDS):
        struct.pack_into(endian + "I", image, 4 * index, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
