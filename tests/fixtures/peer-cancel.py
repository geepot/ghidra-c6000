#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute packets the packet-tail analyzer completes, for cancellation at every
check. Usage: IMAGE CASES.json [be]"""

import json
import struct
import sys
from pathlib import Path

# cl6x 8.3.15 -mv6740 --no_compress encodings; bit 0 is the p-bit (SPRUFE8B 3.5).
MVK_S1 = 0x008000A9  # MVK.S1 1,A1 ||
MVK_S2 = 0x020003AB  # MVK.S2 7,B4 ||
ADD_L1 = 0x01882078  # ADD.L1 A1,A2,A3
NOP1 = 0x0C6E        # compact NOP 1 (SPRUFE8B Figure H-9)


def main():
    image, manifest = Path(sys.argv[1]), Path(sys.argv[2])
    big = len(sys.argv) > 3 and sys.argv[3] == "be"
    words = [0] * 16
    # Packet 0: one 32-bit anchor and two 32-bit peers.
    words[0:3] = [MVK_S1, MVK_S2, ADD_L1]
    # Packet 1: a 32-bit anchor and a compact peer; header layout marks word 1
    # compact, p-bits clear (SPRUFE8B 3.10.2, Table 3-16).
    words[8] = MVK_S1
    words[9] = NOP1 | NOP1 << 16
    words[15] = 0xE0400000
    image.write_bytes(struct.pack((">" if big else "<") + "16I", *words))
    cases = [dict(name="full32", anchor=0x1000, peers=[[0x1004, 4], [0x1008, 4]]),
             dict(name="compact", anchor=0x1020, peers=[[0x1024, 2]])]
    manifest.write_text(json.dumps(cases, indent=1) + "\n")


if __name__ == "__main__":
    main()
