#!/usr/bin/env python3
"""Build MVC time-stamp counter cases for C6000MvcControlTest. IMAGE CASES.tsv [be]

Each word sits alone in a 32-byte packet. The valid words are as cl6x 8.3.15
(-mv6740) and GNU as 2.47 (-march=c674x) assemble them. Writing TSCL starts
the counter and the value is ignored (SPRUFE8B 2.9.14.2), and each read is
live (2.9.14.4), so each form must run its userop exactly when its predicate
holds and touch no other register. MVC is .S2 only, and Table 3-27 gives TSCL
and TSCH only crhi 00000 and TSCH no write; GNU objdump leaves the .S1, x=1
read, crhi and TSCH write forms undefined, though dis6x accepts them.
"""

from pathlib import Path
import struct
import sys

# word, direction, target, cross path, mode, userop, listing
CASES = [
    (0x051003A2, "write", "TSCL", 0, "event", "c6000_tsc_start", "MVC.S2 B4,TSCL"),
    (0x051013A2, "write", "TSCL", 1, "event", "c6000_tsc_start", "MVC.S2 A4,TSCL"),
    (0x050003A2, "write", "TSCL", 0, "event", "c6000_tsc_start", "MVC.S2 B0,TSCL"),
    (0x251003A2, "write", "TSCL", 0, "event", "c6000_tsc_start", "[B0]MVC.S2 B4,TSCL"),
    (0x951013A2, "write", "TSCL", 1, "event", "c6000_tsc_start", "[!A1]MVC.S2 A4,TSCL"),
    (0x042803E2, "read", "TSCL", 0, "event", "c6000_tscl_read", "MVC.S2 TSCL,B8"),
    (0x042C03E2, "read", "TSCH", 0, "event", "c6000_tsch_read", "MVC.S2 TSCH,B8"),
    (0x242803E2, "read", "TSCL", 0, "event", "c6000_tscl_read", "[B0]MVC.S2 TSCL,B8"),
    (0x942803E2, "read", "TSCL", 0, "event", "c6000_tscl_read", "[!A1]MVC.S2 TSCL,B8"),
    (0x342C03E2, "read", "TSCH", 0, "event", "c6000_tsch_read", "[!B0]MVC.S2 TSCH,B8"),
    (0x842C03E2, "read", "TSCH", 0, "event", "c6000_tsch_read", "[A1]MVC.S2 TSCH,B8"),
    (0x059003A2, "write", "-", 0, "invalid", "-", "-"),  # MVC .S2 B4,TSCH
    (0x051023A2, "write", "-", 0, "invalid", "-", "-"),  # TSCL write, crhi 00001
    (0x051203A2, "write", "-", 0, "invalid", "-", "-"),  # TSCL write, crhi 10000
    (0x051103A2, "write", "-", 0, "invalid", "-", "-"),  # TSCL write, crhi 01000
    (0x042823E2, "read", "-", 0, "invalid", "-", "-"),   # TSCL read, crhi 00001
    (0x042C23E2, "read", "-", 0, "invalid", "-", "-"),   # TSCH read, crhi 00001
    (0x051003A0, "write", "-", 0, "invalid", "-", "-"),  # TSCL write on .S1
    (0x042803E0, "read", "-", 0, "invalid", "-", "-"),   # TSCL read on .S1
    (0x042813E2, "read", "-", 0, "invalid", "-", "-"),   # TSCL read, x=1
    (0x042C13E2, "read", "-", 0, "invalid", "-", "-"),   # TSCH read, x=1
]


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (word, *fields) in enumerate(CASES):
            out.write(struct.pack(endian + "I", word) + bytes(28))
            rows.write("\t".join(map(str, [index, *fields])) + "\n")


if __name__ == "__main__":
    main()
