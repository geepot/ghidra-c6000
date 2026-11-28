#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A call whose look-back a jump from 2 KB away enters. Usage: IMAGE CASES.json [be]

Load at 0x1000. Words are cl6x 8.5.0.LTS -mv6740 --abi=eabi --no_compress output, listed by
dis6x; the rest of the image is zero (NOP):

  1000 callee  B B3 ; NOP 5
  1020 caller  MVKL ret,B3 ; MVKH ret,B3
  1028 label   NOP                       ; entered by the jump at 1808
  102c         B callee ; NOP 5          ; a call: B3 holds ret on both ways in
  1034 ret     B B3 ; NOP 5
  1800 far     MVKL ret,B3 ; MVKH ret,B3
  1808         B label ; NOP 5

C6000FarEntryTest marks the B at 102c a tail call and recovers delay windows: the B sets
no link in its window, but B3 holds ret when it lands on both ways into the label, so it is
a call and its window is refused (SPRUFE8B 4.2.6). Then the MVKL at 1800 is changed to
MVKL 0x5678,B3: the jump now brings another link, B3 is unknown at the B, and it is a tail
call whose window is laid. The change is 2 KB from the B, outside any function and outside
the 512-byte reach of a distance rule; only what the B's proof read (the jump's look-back,
followed from the label) ties the two together.
"""

import json
from pathlib import Path
import struct
import sys

B_B3, NOP5 = 0x000C0362, 0x00008000
MVKL_RET_B3, MVKH_RET_B3 = 0x01881A2A, 0x0180006A  # ret = 0x1034
MVKL_OTHER_B3 = 0x01AB3C2A  # MVKL 0x5678,B3
WORDS = {
    0x1000: [B_B3, NOP5],
    0x1020: [MVKL_RET_B3, MVKH_RET_B3, 0x00000000, 0x0FFFFC10, NOP5, B_B3, NOP5],  # 102c: B 0x1000
    0x1800: [MVKL_RET_B3, MVKH_RET_B3, 0x0FFF0510, NOP5],  # 1808: B 0x1028
}
CASE = dict(code=[[0x1000, 0x1007], [0x1020, 0x103B], [0x1800, 0x180F]],
            branch=0x102C, label=0x1028, jump=0x1808, patch=[0x1800, MVKL_OTHER_B3])


def main():
    image, manifest = Path(sys.argv[1]), Path(sys.argv[2])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    data = bytearray(0x1000)
    for base, words in WORDS.items():
        for index, word in enumerate(words):
            struct.pack_into(endian + "I", data, base - 0x1000 + 4 * index, word)
    image.write_bytes(data)
    manifest.write_text(json.dumps(CASE, indent=1) + "\n")


if __name__ == "__main__":
    main()
