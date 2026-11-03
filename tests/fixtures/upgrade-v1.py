#!/usr/bin/env python3
"""Programs saved with language version 1, issue #31. Usage: IMAGE [be].

data/elf-compact-{le,be}-v1.gzf hold the elf-compact.py ELF imported and analysed
by the 1.1.1-era language (BE version 1, LE version 1.2) in Ghidra 12.1.3, the
oldest supported version, so every matrix row can read them. Importing the BE one
runs C6000BeDefaultLanguageTranslator, which primes each compact halfword and
re-decodes; the LE one needs no translation.
"""
from pathlib import Path
import shutil
import sys

if __name__ == "__main__":
    endian = "be" if len(sys.argv) > 2 and sys.argv[2] == "be" else "le"
    shutil.copyfile(Path(__file__).with_name("data") / f"elf-compact-{endian}-v1.gzf", sys.argv[1])
