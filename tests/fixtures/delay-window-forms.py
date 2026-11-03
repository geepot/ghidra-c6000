#!/usr/bin/env python3
"""Delay windows of a B call and a predicated B, issue #34. Usage: IMAGE [be].

Load at 0x1000 with entries 0x1000 and 0x1030 and auto-analysis.
Words are cl6x 8.3.15 -mv6740 --no_compress output linked at 0x1000.

  1000 bcall_args: STW B3,*B15--[2]; B.S1 sink; MVKL/MVKH msg2,A4; MVK 2,B4;
                   MVKL/MVKH ret1,B3
  101c ret1:       LDW *++B15[2],B3; NOP 4; ADD 1,A4,A4; B B3; NOP 5
  1030 pred_slot:  MV A4,A1; [A1] B.S1 L1; MVK 7,A5; ADD A4,5,A4; NOP 3; MV A5,A4
  1048 L1:         B B3; NOP 5
  1050 sink:       ADD A4,B4,A4; B B3; NOP 5
  105c msg2:       "hello"
"""

from pathlib import Path
import struct
import sys

WORDS = [0x01bc54f6, 0x00000a10, 0x02082e28, 0x02000068, 0x0200012a, 0x01880e2a, 0x0180006a,
         0x01bc52e6, 0x00006000, 0x02102058, 0x000c0362, 0x00008000,
         0x00900fd8, 0x80000510, 0x028003a8, 0x0210a058, 0x00004000, 0x02140fd8,
         0x000c0362, 0x00008000,
         0x02109078, 0x000c0362, 0x00008000]

if __name__ == "__main__":
    endian = ">" if len(sys.argv) > 2 and sys.argv[2] == "be" else "<"
    image = b"".join(struct.pack(endian + "I", word) for word in WORDS) + b"hello\0\0\0"
    Path(sys.argv[1]).write_bytes(image)
