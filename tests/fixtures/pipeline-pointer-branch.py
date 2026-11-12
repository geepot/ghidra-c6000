#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""B IRP / B NRP in an exact schedule: no register or displacement target, refused (SPRUFE8B pp.155, 157).
IMAGE CASES.json [be]. Words are TI cl6x 8.3.15 output (-mv6740 --no_compress), no firmware bytes:

  1000 birp   B .S2 IRP ; NOP 5
  1040 bnrp   B .S2 NRP ; NOP 5
  1080 pirp   [B0] B .S2 IRP ; NOP 5
  10c0 pnrp   [!B0] B .S2 NRP ; NOP 5
  1100 ret    MVK .S1 0x22,A4 ; B .S2 B3 ; NOP 5     known-good: still scheduled
"""
from pathlib import Path
import json, struct, sys

NOP5 = 0x00008000
WORDS = {0x1000: [0x001800E2, NOP5], 0x1040: [0x001C00E2, NOP5], 0x1080: [0x201800E2, NOP5],
         0x10C0: [0x301C00E2, NOP5], 0x1100: [0x02001128, 0x000C0362, NOP5]}


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 4 else "<"
    image = bytearray(0x200)
    for entry, words in WORDS.items():
        for i, w in enumerate(words):
            struct.pack_into(endian + "I", image, entry - 0x1000 + 4 * i, w)
    rows = [dict(name=name, entry=entry, refused="unresolved branch target")
            for name, entry in (("birp", 0x1000), ("bnrp", 0x1040), ("pirp", 0x1080), ("pnrp", 0x10C0))]
    rows.append(dict(name="ret", entry=0x1100, input={"B3": 0x9000, "A4": 0x4444}, expected={"A4": 0x22, "PC": 0x9000}))
    Path(sys.argv[1]).write_bytes(image)
    Path(sys.argv[2]).write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
