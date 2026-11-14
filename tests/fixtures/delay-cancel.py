#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Delay windows to lay and release while cancelling at every check. Usage: IMAGE CASES.json [be]

Load at 0x1000. Words are cl6x 8.3.15 -mv6740 --abi=eabi --no_compress output,
listed by dis6x, except the fetch-packet header (SPRUFE8B 3.10.2):

  1000 recover   MV A4,A1 ; [A1] B.S1 101c ; ADD 1..5,A4,A4 ; 101c: B B3 ; NOP 5
                 two windows: five ADD slots, and NOP 5 (SPRUFE8B 3.5, 4.2.6)
  1058 put-back  B B3 ; 105c: header 0xe0000000, all 32-bit words ; 1060: NOP 5
                 a function owns the header, so extending the window's owner fails
                 after the window is laid
  1080 relieve   MV A4,A1 ; MV A6,A2 ; five times: [A1] B.S1 m ; NOP 5 ; [A2] B.S1 s ;
                 ADD 1 ; m: ADD 2..5 ; s: ... B B3 ; NOP 5
                 five windows each entered at its second slot (as entered-window.py)
"""

import json
from pathlib import Path
import struct
import sys

B_B3, NOP5, MV_A4_A1, MV_A6_A2 = 0x000C0362, 0x00008000, 0x00900FD8, 0x01180FD8
ADD = [0x02102058, 0x02104058, 0x02106058, 0x02108058, 0x0210A058]  # ADD.L1 1..5,A4,A4
WORDS = {
    0x1000: [MV_A4_A1, 0x80000390] + ADD + [B_B3, NOP5],  # 1004: [A1] B.S1 0x101c
    0x1058: [B_B3, 0xE0000000, NOP5],
    # [A1] B.S1 m (PC+24) ; NOP 5 ; [A2] B.S1 s (PC+40) ; ADD 1..5
    0x1080: [MV_A4_A1, MV_A6_A2] + 5 * ([0x80000310, NOP5, 0xA0000510] + ADD) + [B_B3, NOP5],
}
# name, method, ranges to disassemble, functions [name, entry, body start, body end or 0 for flow],
# windows [branch, last slot], expected change after an uncancelled run, prepare by recovering first
CASES = [
    dict(name="recover", run="recover", code=[[0x1000, 0x1023]], functions=[["f", 0x1000, 0, 0]],
         windows=[[0x1004, 0x101B], [0x101C, 0x1023]], change="all", prepare=False),
    dict(name="put-back", run="recover", code=[[0x1058, 0x1063]],
         functions=[["owner", 0x1058, 0x1058, 0x105B], ["header", 0x105C, 0x105C, 0x105F]],
         windows=[[0x1058, 0x1063]], change="fails", prepare=False),
    dict(name="relieve", run="relieve", code=[[0x1080, 0x112F]], functions=[["g", 0x1080, 0, 0]],
         windows=[[0x1090 + 0x20 * i, 0x10A7 + 0x20 * i] for i in range(5)], change="counted", prepare=True),
]


def main():
    image, manifest = Path(sys.argv[1]), Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    data = bytearray(0x140)
    for base, words in WORDS.items():
        for index, word in enumerate(words):
            struct.pack_into(endian + "I", data, base - 0x1000 + 4 * index, word)
    image.write_bytes(data)
    manifest.write_text(json.dumps(CASES, indent=1) + "\n")


if __name__ == "__main__":
    main()
