#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Same-cycle writers under complementary predicates (SPRUFE8B 3.6, 3.8.8). IMAGE CASES.json [be].

An LDW issued four cycles before an E1 writer of B5 lands in the same cycle. The
predicate is tested in E1, so two writers whose predicates test one unchanged value
with opposite senses never both write; any other pair stays refused. B4 points at the
word 1, so B5 is 1 when B0 is zero and 7 otherwise. Words are TI cl6x 8.3.15 output
(-mv6740 --no_compress), listed by dis6x; no firmware bytes:

  1000 comp     [!B0] LDW *B4,B5 ; NOP 3 ; [B0] MVK 7,B5
  1020 copy     [!B0] LDW *B4,B5 || MV B0,B2 ; NOP 3 ; [B2] MVK 7,B5
  1040 first    [B0] MVK 7,B6 ; [!B0] LDW *B4,B5 ; NOP 3 ; [B0] MV B6,B5
  1060 rewr     [!B0] LDW *B4,B5 ; MV B6,B0 ; NOP 2 ; [B0] MVK 7,B5        refused
  1080 newcp    [!B0] LDW *B4,B5 ; MV B6,B0 ; MV B0,B2 ; NOP ; [B2] MVK    refused
  10a0 same     [!B0] LDW *B4,B5 ; NOP 3 ; [!B0] MVK 7,B5                  refused
  10c0 other    [!B0] LDW *B4,B5 ; NOP 3 ; [B1] MVK 7,B5                   refused
  10e0 unpred   LDW *B4,B5 ; NOP 3 ; MVK 7,B5                              refused
  1100 known    [!B0] LDW *B4,B5 ; MVK 1,B0 ; NOP 2 ; [B0] MVK 7,B5        refused
                each then NOP 5 ; B B3 ; NOP 5
"""
from pathlib import Path
import json, struct, sys

TAIL = [0x00008000, 0x000C0362, 0x00008000]
WORDS = {
    0x1000: [0x329002E6, 0x00004000, 0x228003AA] + TAIL,
    0x1020: [0x329002E7, 0x01000FDA, 0x00004000, 0x628003AA] + TAIL,
    0x1040: [0x230003AA, 0x329002E6, 0x00004000, 0x22980FDA] + TAIL,
    0x1060: [0x329002E6, 0x00180FDA, 0x00002000, 0x228003AA] + TAIL,
    0x1080: [0x329002E6, 0x00180FDA, 0x01000FDA, 0x00000000, 0x628003AA] + TAIL,
    0x10A0: [0x329002E6, 0x00004000, 0x328003AA] + TAIL,
    0x10C0: [0x329002E6, 0x00004000, 0x428003AA] + TAIL,
    0x10E0: [0x029002E6, 0x00004000, 0x028003AA] + TAIL,
    0x1100: [0x329002E6, 0x000000AA, 0x00002000, 0x228003AA] + TAIL,
}
ACCEPTED = {"comp": 0x1000, "copy": 0x1020, "first": 0x1040}
REFUSED = {"rewr": 0x1060, "newcp": 0x1080, "same": 0x10A0, "other": 0x10C0, "unpred": 0x10E0, "known": 0x1100}


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 4 else "<"
    image = bytearray(0x120)
    for entry, words in WORDS.items():
        for i, w in enumerate(words):
            struct.pack_into(endian + "I", image, entry - 0x1000 + 4 * i, w)
    rows = []
    for name, entry in ACCEPTED.items():
        for b0 in (0, 1, 0xFFFFFFFF):
            rows.append(dict(name=f"{name}_{b0:x}", entry=entry, input={"B0": b0, "B4": 0x8000, "B3": 0x9000},
                             expected={"B5": 1 if b0 == 0 else 7, "PC": 0x9000}))
    for name, entry in REFUSED.items():
        rows.append(dict(name=name, entry=entry, refused="potential simultaneous memory/register writes"))
    Path(sys.argv[1]).write_bytes(image)
    Path(sys.argv[2]).write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
