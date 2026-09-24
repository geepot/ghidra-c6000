#!/usr/bin/env python3
"""Compare a C6000CorpusTest listing against the GNU tic6x disassembler.

The listing is produced by `C6000CorpusTest.java` when C6000_LISTING is set;
each line is "<address> <length> <mnemonic>".  GNU binutils is GPL and is used
here purely as an external reference implementation - nothing it produces is
committed to the repository.

Usage:
    tools/oracle_compare.py IMAGE BASE LISTING [START END]

Requires a tic6x objdump on PATH (tic6x-unknown-elf-objdump etc.).
"""
import os
import re
import shutil
import subprocess
import sys

OBJDUMP_NAMES = ("tic6x-unknown-elf-objdump", "tic6x-linux-gnu-objdump",
                 "tic6x-elf-objdump")


def find_objdump():
    for n in OBJDUMP_NAMES:
        p = shutil.which(n)
        if p:
            return p
    return None


def oracle_listing(objdump, image, base, start, end):
    """Return {address: (length, mnemonic)} from GNU objdump."""
    # objdump insists on at least one full fetch packet of input.
    data = open(image, "rb").read()
    if len(data) < 32:
        data = data + b"\x00" * (32 - len(data))
    tmp = "/tmp/c6000_oracle.bin"
    open(tmp, "wb").write(data)
    cmd = [objdump, "-D", "-b", "binary", "-m", "tic6x",
           "--endian=little", tmp]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    result = {}
    for line in out.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.*)$", line)
        if not m:
            continue
        addr = base + int(m.group(1), 16)
        text = m.group(3).strip()
        # GNU prints "||" for parallel and "[cond]" for predication.
        text = text.replace("||", " ").strip()
        mn = text.split()[0] if text else "?"
        result[addr] = (4, mn)
    return result


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
        m = re.match(r"^([0-9a-f]+)\s+(\d+)\s+(\S+)", line)
        if m:
            ours[int(m.group(1), 16)] = (int(m.group(2)), m.group(3))

    both = sorted(set(ours) & set(oracle))
    length_mismatch = [(a, ours[a][0], oracle[a][0]) for a in both
                       if ours[a][0] != oracle[a][0]]
    # GNU renders mnemonics with spaces ("mvk .S2"), we render "MVK.S2".
    def norm(s):
        return s.replace(" ", "").replace(".", "").upper()
    name_mismatch = [(a, ours[a][1], oracle[a][1]) for a in both
                     if norm(ours[a][1]) != norm(oracle[a][1])]
    print("compared %d instructions" % len(both))
    print("length mismatches: %d" % len(length_mismatch))
    for a, o, g in length_mismatch[:20]:
        print("  0x%08x ours=%d gnu=%d" % (a, o, g))
    print("mnemonic mismatches: %d" % len(name_mismatch))
    for a, o, g in name_mismatch[:20]:
        print("  0x%08x ours=%s gnu=%s" % (a, o, g))
    return 1 if (length_mismatch or name_mismatch) else 0


if __name__ == "__main__":
    sys.exit(main())
