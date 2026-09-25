#!/usr/bin/env python3
"""Compare directly rendered C6x operands with GNU's disassembly.

Usage: tools/oracle_operands.py IMAGE BASE C6000_FULL_LISTING [START END]

The full listing comes from C6000CorpusTest.java with C6000_FULL_LISTING set.
This checks instructions whose operand spelling is directly comparable after
case and radix normalization. Branch targets, MVK/MVKH/ADDK immediate display,
ADDKPC, memory addressing, and opcode aliases need separate checks.
"""

from collections import Counter
from pathlib import Path
import re
import subprocess
import sys

from oracle_compare import find_objdump


DISPLAY_EXCEPTIONS = {"B", "BNOP", "BDEC", "CALLP", "ADDKPC", "MVK", "MVKH", "ADDK"}


def normalize(operand):
    operand = operand.strip().lower().replace(" ", "")
    try:
        return int(operand, 0) & 0xFFFFFFFF
    except ValueError:
        return operand


def main():
    if len(sys.argv) not in (4, 6):
        print(__doc__, file=sys.stderr)
        return 2
    image, base_text, listing = sys.argv[1:4]
    base = int(base_text, 0)
    start = int(sys.argv[4], 0) if len(sys.argv) == 6 else base
    end = int(sys.argv[5], 0) if len(sys.argv) == 6 else base + Path(image).stat().st_size
    objdump = find_objdump()
    if objdump is None:
        print("no tic6x objdump found", file=sys.stderr)
        return 2

    ours = {}
    for line in Path(listing).read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]+)\s+(\d+)\s+(.+)", line)
        if match is None:
            continue
        address, length = int(match[1], 16), int(match[2])
        if not start <= address < end or length != 4:
            continue
        text = re.sub(r"^\[[^]]+\]\s*", "", match[3])
        instruction = re.fullmatch(r"([A-Z][A-Z0-9]*)\.([LSDM][12])(?:\s+(.*))?", text)
        if instruction:
            ours[address] = (instruction[1], instruction[2], instruction[3] or "")

    command = [objdump, "-D", "-b", "binary", "-m", "tic6x",
               "--endian=little", image]
    output = subprocess.run(command, capture_output=True, text=True, check=True).stdout
    compared = Counter()
    mismatches = []
    for line in output.splitlines():
        match = re.match(r"^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.*)$", line)
        if match is None:
            continue
        address = base + int(match[1], 16)
        if address not in ours:
            continue
        body = re.sub(r"^(?:\|\|\s*)?(?:\[[^]]+\]\s*)?", "", match[3].strip())
        body = re.sub(r"\s+\|\|\s+nop\b.*$", "", body)
        instruction = re.match(r"(?i)([a-z][a-z0-9]*)\s+\.([LSDM][12])"
                               r"(?:[XT][12]?)?\s*(.*)", body)
        if instruction is None:
            continue
        name, unit, operands = ours[address]
        if (name, unit) != (instruction[1].upper(), instruction[2].upper()):
            continue  # Naming and unit disagreements belong to oracle_compare.py.
        if name in DISPLAY_EXCEPTIONS or "*" in operands or "*" in instruction[3]:
            continue
        got = [normalize(part) for part in operands.split(",")]
        want = [normalize(part) for part in instruction[3].split(",")]
        compared[name] += 1
        if got != want:
            mismatches.append((address, name, operands, instruction[3]))

    print(f"compared={sum(compared.values())}")
    for address, name, got, want in mismatches[:20]:
        print(f"MISMATCH 0x{address:08x} {name} ours={got} gnu={want}")
    print(f"operand_mismatches={len(mismatches)}")
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
