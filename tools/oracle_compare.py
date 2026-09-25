#!/usr/bin/env python3
"""Compare a C6000CorpusTest listing against the GNU tic6x disassembler.

The listing is produced by `C6000CorpusTest.java` when C6000_LISTING is set;
each line is "<address> <length> <mnemonic>".  GNU binutils is GPL and is used
here purely as an external reference implementation - nothing it produces is
committed to the repository.

Usage:
    tools/oracle_compare.py IMAGE BASE LISTING [START END]

Requires a tic6x objdump, such as tic6x-unknown-elf-objdump or GNU gobjdump.
Compares instruction addresses, lengths, mnemonics and functional units, not
operands or execution semantics.  GNU may elide extra NOPs in a NOP run.
"""
import re
import shutil
import subprocess
import sys
import tempfile

OBJDUMP_NAMES = ("tic6x-unknown-elf-objdump", "tic6x-linux-gnu-objdump",
                 "tic6x-elf-objdump", "gobjdump",
                 "/opt/homebrew/opt/binutils/bin/gobjdump")

# GNU often prints the underlying arithmetic opcode where Ghidra chooses a
# documented pseudo-op with the same result.  Keep these visible separately.
ALIASES = {("MV", "OR"), ("MV", "ADD"), ("NEG", "SUB"),
           ("STBU", "STB"), ("STHU", "STH")}


def find_objdump():
    for n in OBJDUMP_NAMES:
        p = shutil.which(n)
        if p:
            return p
    return None


def oracle_listing(objdump, image, base, start, end):
    """Return {address: (length, mnemonic, unit)} from GNU objdump."""
    # objdump insists on at least one full fetch packet of input.
    data = open(image, "rb").read()
    if len(data) < 32:
        data = data + b"\x00" * (32 - len(data))
    with tempfile.NamedTemporaryFile(prefix="c6000-oracle-", suffix=".bin") as tmp:
        tmp.write(data)
        tmp.flush()
        cmd = [objdump, "-D", "-b", "binary", "-m", "tic6x",
               "--endian=little", tmp.name]
        out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    result = {}
    for line in out.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s+([0-9a-f]{4}|[0-9a-f]{8})\s+(.*)$", line)
        if not m:
            continue
        addr = base + int(m.group(1), 16)
        if start is not None and addr < start:
            continue
        if end is not None and addr >= end:
            continue
        body = re.sub(r"^(?:\|\|\s*)?(?:\[[^]]+\]\s*)?", "", m.group(3).strip())
        if body.startswith("<undefined"):
            continue
        if "fetch packet header" in body:
            result[addr] = (4, "CPKT", "")
            continue
        parts = body.split()
        if not parts:
            continue
        unit = parts[1] if len(parts) > 1 and parts[1].startswith(".") else ""
        result[addr] = (len(m.group(2)) // 2, parts[0].upper(), unit[:3].upper())
    return result


def our_name(raw):
    """Strip a displayed predicate and retain the functional unit."""
    raw = re.sub(r"^\[[^]]+\]\s*", "", raw)
    name, _, unit = raw.partition(".")
    return name.upper(), ("." + unit[:2].upper()) if unit else ""


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    image, base, listing = sys.argv[1], int(sys.argv[2], 0), sys.argv[3]
    start = int(sys.argv[4], 0) if len(sys.argv) > 4 else None
    end = int(sys.argv[5], 0) if len(sys.argv) > 5 else None
    objdump = find_objdump()
    if objdump is None:
        print("no tic6x objdump found on PATH", file=sys.stderr)
        return 2

    oracle = oracle_listing(objdump, image, base, start, end)
    ours = {}
    for line in open(listing):
        m = re.match(r"^([0-9a-f]+)\s+(\d+)\s+(.+)$", line)
        if m:
            address = int(m.group(1), 16)
            if start is not None and address < start:
                continue
            if end is not None and address >= end:
                continue
            ours[address] = (int(m.group(2)), *our_name(m.group(3).strip()))

    both = sorted(set(ours) & set(oracle))
    length_mismatch = [(a, ours[a][0], oracle[a][0]) for a in both
                       if ours[a][0] != oracle[a][0]]
    aliases = [(a, ours[a][1:], oracle[a][1:]) for a in both
               if (ours[a][1], oracle[a][1]) in ALIASES and ours[a][2] == oracle[a][2]]
    name_mismatch = [(a, ours[a][1:], oracle[a][1:]) for a in both
                     if ours[a][1:] != oracle[a][1:] and
                     not ((ours[a][1], oracle[a][1]) in ALIASES and
                          ours[a][2] == oracle[a][2])]
    gnu_only = sorted(set(oracle) - set(ours))
    ours_only = sorted(a for a in set(ours) - set(oracle) if ours[a][1] != "NOP")
    print("compared %d instructions" % len(both))
    print("GNU-only instructions: %d" % len(gnu_only))
    for a in gnu_only[:20]:
        print("  0x%08x GNU=%s" % (a, oracle[a]))
    print("Ghidra-only non-NOP instructions: %d" % len(ours_only))
    for a in ours_only[:20]:
        print("  0x%08x Ghidra=%s" % (a, ours[a]))
    print("length mismatches: %d" % len(length_mismatch))
    for a, o, g in length_mismatch[:20]:
        print("  0x%08x ours=%d gnu=%d" % (a, o, g))
    print("known naming differences: %d" % len(aliases))
    print("mnemonic/unit mismatches: %d" % len(name_mismatch))
    for a, o, g in name_mismatch[:20]:
        print("  0x%08x ours=%s gnu=%s" % (a, o, g))
    return 1 if (gnu_only or ours_only or length_mismatch or name_mismatch) else 0


if __name__ == "__main__":
    sys.exit(main())
