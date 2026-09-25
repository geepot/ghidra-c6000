#!/usr/bin/env python3
"""Audit a compact-opcode sweep against GNU and TI's encoding constraints.

Usage: tools/audit_compact_oracle.py IMAGE BASE C6000_LISTING

The image should come from sample_compact_encodings.py. GNU disassembly is an
external oracle, not the authority for whether an opcode is architecturally
valid. The two known disagreement classes are checked against SPRUFE8B Figures
F-31 and H-7.
"""

from collections import Counter
from pathlib import Path
import re
import struct
import sys

from oracle_compare import ALIASES, find_objdump, oracle_listing, our_name


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    image, base_text, listing = sys.argv[1:]
    base = int(base_text, 0)
    objdump = find_objdump()
    if objdump is None:
        print("no tic6x objdump found", file=sys.stderr)
        return 2
    data = Path(image).read_bytes()
    gnu = oracle_listing(objdump, image, base, None, None)
    ours = {}
    for line in Path(listing).read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]+)\s+(\d+)\s+(.+)", line)
        if match:
            ours[int(match[1], 16)] = (int(match[2]), *our_name(match[3]))

    def halfword(address):
        return struct.unpack_from("<H", data, address - base)[0]

    reasons = Counter()
    unknown = []
    for address in sorted(set(gnu) - set(ours)):
        length, name, unit = gnu[address]
        raw = halfword(address)
        if length == 2 and name == "MVC" and unit == ".S1" and raw & 1 == 0:
            reasons["GNU-only MVC with reserved s=0 (Figure F-31)"] += 1
        else:
            unknown.append((address, "GNU-only", name + unit, raw))
    for address in sorted(set(ours) - set(gnu)):
        length, name, unit = ours[address]
        if name == "NOP":  # GNU can elide trailing NOPs in a run.
            continue
        raw = halfword(address)
        if length == 2 and name == "SPKERNEL" and (raw & 0x3C7E) == 0x1C66:
            reasons["Ghidra-only SPKERNEL in synthetic packet (Figure H-7)"] += 1
        else:
            unknown.append((address, "Ghidra-only", name + unit, raw))
    for address in sorted(set(ours) & set(gnu)):
        length, name, unit = ours[address]
        glength, gname, gunit = gnu[address]
        if length != glength:
            unknown.append((address, "length mismatch", name + unit, halfword(address)))
        elif (name, unit) != (gname, gunit) and not (
                (name, gname) in ALIASES and unit == gunit):
            unknown.append((address, "name/unit mismatch", name + unit, halfword(address)))

    print(f"compared={len(set(ours) & set(gnu))}")
    for reason, count in sorted(reasons.items()):
        print(f"{reason}: {count}")
    for address, kind, name, raw in unknown[:20]:
        print(f"UNEXPLAINED 0x{address:08x} {kind} {name} opcode=0x{raw:04x}")
    print(f"unexplained={len(unknown)}")
    return 1 if unknown else 0


if __name__ == "__main__":
    raise SystemExit(main())
