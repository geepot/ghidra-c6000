#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TI-assembled delayed calls whose return point only the call analyzer decodes: IMAGE CASES.json [be].

Requires TI's C6000 assembler (TI_C6000_BIN as in pipeline-predicate-facts.py).
Each case is f(a) = h(h(h(a) + 18) + N + 1) + 0x30 with h(x) = 2x, in one section loaded at
0x1000 + 0x200 * index; C6000LostFallthroughTest.java prepare declares f and h, as ELF
symbols would. Calls 0 and 1 set B3 in their delay slots; call 2 sets B3 by MVKL/MVKH
before its B and has ADD + NOP 4 in its slots. A B issues at E1 and its five delay slots
run before the target (SPRUFE8B 3.5, 4.2.6 B), so on hardware
f(a) = 2 * (2 * (2a + 18) + N + 1) + 0x30 = 8a + 2N + 0x7a, and every return resumes past its
window. Only call 2's distance from call 1 differs, N + 7 words; the code after each call is
decoded by the call analyzer itself. The check wants each return point decoded in f's body
and f's C to return h(...) + 0x30, with no unrecovered jump. Full32 only, so BE swaps each
word's bytes.
"""
from pathlib import Path
import importlib.util
import json
import os
import re
import subprocess
import sys

SIZE = 0x200
H = """{n}_h:
        B       .S2     B3
        ADD     .L1     A4,A4,A4
        NOP             4
"""
RET = """        LDW     .D2T2   *++B15[2],B3
        NOP             4
        B       .S2     B3
        NOP             5
"""
BODY = """{n}:
        STW     .D2T2   B3,*B15--[2]
        B       .S1     {n}_h           ; call 0: t0
        MVKL    .S2     {n}_r0,B3       ; t1: its link, set in its window
        MVKH    .S2     {n}_r0,B3       ; t2
        NOP             3               ; t3-t5
{n}_r0:
{fill0}        B       .S1     {n}_h           ; call 1: 22 words after call 0's B
        MVKL    .S2     {n}_r1,B3
        MVKH    .S2     {n}_r1,B3
        NOP             3
{n}_r1:
{fill}        MVKL    .S2     {n}_ret,B3      ; call 2's link, set before its B
        MVKH    .S2     {n}_ret,B3
        NOP
        B       .S1     {n}_h           ; call 2: t0, N + 7 words after call 1's B
        ADD     .L1     A4,1,A4         ; t1: the argument
        NOP             4               ; t2-t5
{n}_ret:
        ADDK    .S1     0x30,A4         ; after the return
"""
# name, N (ADDK 1 fillers between call 1's window and call 2's link)
CASES = [
    ("far", 36),    # call 2's B 43 words after call 1's B: past the call analyzer's 40-word rescan
    ("near", 18),   # control: 25 words, inside it
]
FILL0 = 18      # call 1's B 22 words after call 0's B in every case
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
        raise SystemExit("Usage: lost-fallthrough.py IMAGE CASES.json [be]")
    image_path, manifest_path = map(Path, sys.argv[1:3])
    image_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    prefix = image_path.parent / (image_path.stem + ".lost-fallthrough")
    assembly, object_file, log = (Path(str(prefix) + suffix) for suffix in (".asm", ".obj", ".log"))
    binary = Path(os.environ.get("TI_C6000_BIN", "/Applications/ti/ti-cgt-c6000_8.3.15/bin"))
    tool = (lambda name: binary / name) if binary.is_dir() else (lambda name: binary.with_name(name))
    sections = []
    for name, fill in CASES:
        add = "        ADDK    .S1     1,A4\n"
        body = BODY.format(n=name, fill0=add * FILL0, fill=add * fill) + RET
        sections.append(' .sect ".pf_' + name + '"\n .nocmp\n' + body + H.format(n=name))
    text = "\n".join(sections)
    assembly.write_text(text)
    assemble(tool("cl6x"), assembly, object_file, log)
    listed = subprocess.run([str(tool("nm6x")), str(object_file)], text=True, stdout=subprocess.PIPE, check=True).stdout
    offsets = {parts[2]: int(parts[0], 16) for parts in map(str.split, listed.splitlines())
               if len(parts) == 3 and parts[1] in "tT" and not parts[2].startswith(".")}
    addresses = {}
    for index, (name, _) in enumerate(CASES):
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
    for index, (name, fill) in enumerate(CASES):
        words = code[".pf_" + name]
        if len(words) > SIZE:
            raise ValueError("Section too long for " + name)
        image[index * SIZE:index * SIZE + len(words)] = words
        manifest.append(dict(name=name, entry=addresses[name], h=addresses[name + "_h"],
                             returns=[addresses[name + "_r0"], addresses[name + "_r1"], addresses[name + "_ret"]],
                             c=["return iVar1 + 0x30;"]))
    if len(sys.argv) == 4:
        image = b"".join(image[index:index + 4][::-1] for index in range(0, len(image), 4))
    image_path.write_bytes(image)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print("LOST_FALLTHROUGH_FIXTURE_OK cases=" + str(len(manifest)))


if __name__ == "__main__":
    main()
