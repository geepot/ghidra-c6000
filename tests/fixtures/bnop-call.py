#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TI-assembled BNOP calls (issue #69): IMAGE CASES.json [be].

Requires TI's C6000 assembler (TI_C6000_BIN as in pipeline-predicate-facts.py).
Each case is a function and its own f(x) = 2x, in one section loaded at
0x1000 + 0x80 * index; C6000BnopCallTest.java prepare declares both, as ELF
symbols would. A BNOP n spends n of its five delay cycles on NOPs, and one whose
remaining delay cycles set B3 to the address after them is a call returning
there (SPRUFE8B 3.12 BNOP, 4.2.6, ADDKPC). The known-bads are not calls: an
ADDKPC after a BNOP 5 never runs, a B3 set to another address is no return, and
a BNOP that leaves B3 alone is a tail call.
MVKL/MVKH operands are assembled once with labels and again with the label
addresses, so the object needs no relocation. Full32 only, so BE swaps each
word's bytes.
"""
from pathlib import Path
import importlib.util
import json
import os
import re
import subprocess
import sys

SIZE = 0x80
F = """{n}_f:
        B       .S2     B3
        ADD     .L1     A4,A4,A4
        NOP             4
"""
RET = """        LDW     .D2T2   *++B15[2],B3
        NOP             4
        B       .S2     B3
        NOP             5
"""
# name, a call, body; {n} is the case name, {n}_bnop the BNOP and {n}_ret its return point
CASES = [
    ("addkpc", True, """{n}:
        STW     .D2T2   B3,*B15--[2]
{n}_bnop:
        BNOP    .S1     {n}_f,1
        ADDKPC  .S2     {n}_ret,B3,3
{n}_ret:
        ADD     .L1     A4,1,A4
""" + RET),
    ("mvk", True, """{n}:
        STW     .D2T2   B3,*B15--[2]
        MVKL    .S2     {n}_ret,B3
        MVKH    .S2     {n}_ret,B3
{n}_bnop:
        BNOP    .S1     {n}_f,3
        MVK     .S1     7,A4
        MVK     .S1     8,A5
{n}_ret:
        ADD     .L1     A4,A5,A4
""" + RET),
    ("register", True, """{n}:
        STW     .D2T2   B3,*B15--[2]
        MVKL    .S2     {n}_ret,B3
        MVKH    .S2     {n}_ret,B3
        MVKL    .S1     {n}_f,A3
        MVKH    .S1     {n}_f,A3
{n}_bnop:
        BNOP    .S2X    A3,3
        MVK     .S1     7,A4
        MVK     .S1     8,A5
{n}_ret:
        ADD     .L1     A4,A5,A4
""" + RET),
    # BNOP 5 leaves no delay cycle: it lands before the ADDKPC issues
    ("late", False, """{n}:
{n}_bnop:
        BNOP    .S1     {n}_f,5
        ADDKPC  .S2     {n}_ret,B3,4
{n}_ret:
        B       .S2     B3
        NOP             5
"""),
    # B3 set in the window, but not to the address after it
    ("elsewhere", False, """{n}:
{n}_bnop:
        BNOP    .S1     {n}_f,3
        MVKL    .S2     {n}_other,B3
        MVKH    .S2     {n}_other,B3
{n}_ret:
        B       .S2     B3
        NOP             5
{n}_other:
        B       .S2     B3
        NOP             5
"""),
    # B3 untouched: a tail call
    ("tail", False, """{n}:
{n}_bnop:
        BNOP    .S1     {n}_f,3
        MVK     .S1     7,A4
        MVK     .S1     8,A5
{n}_ret:
        B       .S2     B3
        NOP             5
"""),
]
LINK = re.compile(r"(MVK[LH]\s+\.S[12]\s+)(\w+)")


def assemble(compiler, source, object_file, log):
    command = [str(compiler), "-mv6740", "--abi=eabi", "--no_compress", "-c",
               str(source), "--output_file=" + str(object_file)]
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log.write_text(completed.stdout)
    if completed.returncode:
        raise RuntimeError("TI assembly failed; see " + str(log))


def main():
    if len(sys.argv) not in (3, 4) or len(sys.argv) == 4 and sys.argv[3] != "be":
        raise SystemExit("Usage: bnop-call.py IMAGE CASES.json [be]")
    image_path, manifest_path = map(Path, sys.argv[1:3])
    image_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    prefix = image_path.parent / (image_path.stem + ".bnop-call")
    assembly, object_file, log = (Path(str(prefix) + suffix) for suffix in (".asm", ".obj", ".log"))
    binary = Path(os.environ.get("TI_C6000_BIN", "/Applications/ti/ti-cgt-c6000_8.3.15/bin"))
    tool = (lambda name: binary / name) if binary.is_dir() else (lambda name: binary.with_name(name))
    text = "\n".join(' .sect ".pf_' + name + '"\n .nocmp\n' + body.format(n=name) + F.format(n=name)
                     for name, _, body in CASES)
    assembly.write_text(text)
    assemble(tool("cl6x"), assembly, object_file, log)
    # Section offsets of every label: each case's labels are prefixed by its name.
    listed = subprocess.run([str(tool("nm6x")), str(object_file)], text=True, stdout=subprocess.PIPE, check=True).stdout
    offsets = {parts[2]: int(parts[0], 16) for parts in map(str.split, listed.splitlines())
               if len(parts) == 3 and parts[1] in "tT" and not parts[2].startswith(".")}
    addresses = {}
    for index, (name, _, _) in enumerate(CASES):
        for label, offset in offsets.items():
            if label == name or label.startswith(name + "_"):
                addresses[label] = 0x1000 + index * SIZE + offset
    assembly.write_text(LINK.sub(lambda m: m.group(1) + hex(addresses[m.group(2)]), text))
    assemble(tool("cl6x"), assembly, object_file, log)
    spec = importlib.util.spec_from_file_location(
        "predicate_facts", Path(__file__).with_name("pipeline-predicate-facts.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    code = module.object_sections(object_file)
    image = bytearray(len(CASES) * SIZE)
    manifest = []
    for index, (name, call, _) in enumerate(CASES):
        words = code[".pf_" + name]
        if len(words) > SIZE:
            raise ValueError("Section too long for " + name)
        image[index * SIZE:index * SIZE + len(words)] = words
        manifest.append(dict(name=name, entry=addresses[name], callee=addresses[name + "_f"],
                             ret=addresses[name + "_ret"], branch=addresses[name + "_bnop"], call=call))
    if len(sys.argv) == 4:
        image = b"".join(image[index:index + 4][::-1] for index in range(0, len(image), 4))
    image_path.write_bytes(image)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print("BNOP_CALL_FIXTURE_OK cases=" + str(len(manifest)))


if __name__ == "__main__":
    main()
