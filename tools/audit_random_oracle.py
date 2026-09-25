#!/usr/bin/env python3
"""Classify GNU/Ghidra disagreements in a 32-bit C674x encoding sample.

Usage: tools/audit_random_oracle.py IMAGE BASE C6000_LISTING

GNU objdump is only an external oracle.  A GNU-only decode can be an invalid
word: the checks below come from the operand types and fixed fields in TI
SPRUFE8B section 3.12, not from GNU's implementation.
"""

from collections import Counter
from pathlib import Path
import re
import struct
import sys

from oracle_compare import ALIASES, find_objdump, oracle_listing, our_name


def field(word, low, width=1):
    return (word >> low) & ((1 << width) - 1)


def gnu_only_reason(name, word):
    if name == "GMPY4" and field(word, 28) == 0:
        return "GMPY4 requires bit 28 = 1"
    if name in {"DPINT", "DPSP", "DPTRUNC"} and field(word, 18) == 0:
        return "conversion DP source requires an odd encoded high register"
    if name in {"ABSDP", "RCPDP", "RSQRDP"}:
        # These .S unary maps fix bits 17..13 to zero and use an even
        # register number for the source pair (see their opcode diagrams).
        if field(word, 13, 5) != 0:
            return "unary DP opcode fixes bits 17..13 to zero"
        if field(word, 18) != 0:
            return "unary DP source pair requires an even encoded register"
    if name in {"SADD", "SSUB", "SUB"}:
        long_immediate_op = {"SADD": 0x30, "SSUB": 0x2c, "SUB": 0x24}[name]
        if field(word, 5, 7) == long_immediate_op and field(word, 12):
            return "long immediate source pair has no cross path"
    return None


def ghidra_only_reason(name, unit, word, previous):
    # The printed TI diagrams expose an x bit in both encodings, although
    # neither form reads a cross-path operand. GNU leaves x=1 undefined.
    if (name, unit) in {("MVK", ".L1"), ("MVK", ".L2"),
                        ("NORM", ".L1"), ("NORM", ".L2")} and field(word, 12):
        return "TI opcode diagram exposes x; GNU rejects x=1"
    if name in {"SPMASK", "SPMASKR"} and previous is not None and field(previous, 0):
        return "loop mask follows a parallel word; GNU enforces packet placement"
    return None


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

    def word_at(address):
        return struct.unpack_from("<I", data, address - base)[0]

    reasons = Counter()
    unknown = []
    for address in sorted(set(gnu) - set(ours)):
        name = gnu[address][1]
        reason = gnu_only_reason(name, word_at(address))
        if reason is None:
            unknown.append((address, "GNU-only", name, word_at(address)))
        else:
            reasons[("GNU-only", reason)] += 1
    for address in sorted(set(ours) - set(gnu)):
        _, name, unit = ours[address]
        if name == "NOP":  # GNU elides NOPs in a run.
            continue
        previous = word_at(address - 4) if address > base else None
        reason = ghidra_only_reason(name, unit, word_at(address), previous)
        if reason is None:
            unknown.append((address, "Ghidra-only", name + unit, word_at(address)))
        else:
            reasons[("Ghidra-only", reason)] += 1
    for address in sorted(set(ours) & set(gnu)):
        length, name, unit = ours[address]
        glength, gname, gunit = gnu[address]
        if length != glength:
            unknown.append((address, "length mismatch", name + unit, word_at(address)))
        elif (name, unit) != (gname, gunit) and not (
                (name, gname) in ALIASES and unit == gunit):
            unknown.append((address, "name mismatch", name + unit, word_at(address)))

    print(f"compared={len(set(ours) & set(gnu))}")
    for (side, reason), count in sorted(reasons.items()):
        print(f"{side}: {count} {reason}")
    for address, kind, name, word in unknown[:20]:
        print(f"UNEXPLAINED 0x{address:08x} {kind} {name} word=0x{word:08x}")
    print(f"unexplained={len(unknown)}")
    return 1 if unknown else 0


if __name__ == "__main__":
    sys.exit(main())
