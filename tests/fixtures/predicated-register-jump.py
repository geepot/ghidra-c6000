#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TI-assembled predicated register jumps with slot work (issue #70): IMAGE CASES.json [be].

Requires TI's C6000 assembler (TI_C6000_BIN as in pipeline-predicate-facts.py).
Each case is a function f(c, t, p) in one section loaded at 0x1000 + 0x40 * index.
A predicated B through a register issues its delay slots on both paths (SPRUFE8B
4.2.6, B), so a store in them precedes the condition in C; a store after the
window runs only when the branch is not taken. Full32 only, so BE swaps each
word's bytes.
"""
from pathlib import Path
import importlib.util
import json
import os
import subprocess
import sys

SIZE = 0x40
# name, store before the condition, body; {n}_slot is the store's MVK
CASES = [
    # #70's repro: *p = 5 on both paths, then a tail jump to t if c
    ("jump", True, """{n}:
        MV      .L1     A4,A1
  [A1]  B       .S2     B4
{n}_slot:
        MVK     .S1     5,A5
        STW     .D1T1   A5,*A6
        NOP             3
        B       .S2     B3
        NOP             5
"""),
    # The store after the window runs only on the fall-through path
    ("after", False, """{n}:
        MV      .L1     A4,A1
  [A1]  B       .S2     B4
        NOP             5
{n}_slot:
        MVK     .S1     5,A5
        STW     .D1T1   A5,*A6
        B       .S2     B3
        NOP             5
"""),
    # A predicated return: *p = 5 on both paths, then *p = 7 if !c
    ("return", True, """{n}:
        MV      .L1     A4,A1
  [A1]  B       .S2     B3
{n}_slot:
        MVK     .S1     5,A5
        STW     .D1T1   A5,*A6
        NOP             3
        MVK     .S1     7,A5
        STW     .D1T1   A5,*A6
        B       .S2     B3
        NOP             5
"""),
    # The store after a predicated return's window runs only on the fall-through path
    ("return_after", False, """{n}:
        MV      .L1     A4,A1
  [A1]  B       .S2     B3
        NOP             5
{n}_slot:
        MVK     .S1     5,A5
        STW     .D1T1   A5,*A6
        B       .S2     B3
        NOP             5
"""),
]


def main():
    if len(sys.argv) not in (3, 4) or len(sys.argv) == 4 and sys.argv[3] != "be":
        raise SystemExit("Usage: predicated-register-jump.py IMAGE CASES.json [be]")
    image_path, manifest_path = map(Path, sys.argv[1:3])
    image_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    prefix = image_path.parent / (image_path.stem + ".predicated-register-jump")
    assembly, object_file, log = (Path(str(prefix) + suffix) for suffix in (".asm", ".obj", ".log"))
    binary = Path(os.environ.get("TI_C6000_BIN", "/Applications/ti/ti-cgt-c6000_8.3.15/bin"))
    tool = (lambda name: binary / name) if binary.is_dir() else (lambda name: binary.with_name(name))
    assembly.write_text("\n".join(' .sect ".pf_' + name + '"\n .nocmp\n' + body.format(n=name)
                                  for name, _, body in CASES))
    command = [str(tool("cl6x")), "-mv6740", "--abi=eabi", "--no_compress", "-c",
               str(assembly), "--output_file=" + str(object_file)]
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log.write_text(completed.stdout)
    if completed.returncode:
        raise RuntimeError("TI assembly failed; see " + str(log))
    listed = subprocess.run([str(tool("nm6x")), str(object_file)], text=True, stdout=subprocess.PIPE, check=True).stdout
    offsets = {parts[2]: int(parts[0], 16) for parts in map(str.split, listed.splitlines())
               if len(parts) == 3 and parts[1] in "tT" and not parts[2].startswith(".")}
    spec = importlib.util.spec_from_file_location(
        "predicate_facts", Path(__file__).with_name("pipeline-predicate-facts.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    code = module.object_sections(object_file)
    image = bytearray(len(CASES) * SIZE)
    manifest = []
    for index, (name, first, _) in enumerate(CASES):
        words = code[".pf_" + name]
        if len(words) > SIZE:
            raise ValueError("Section too long for " + name)
        base = 0x1000 + index * SIZE
        image[index * SIZE:index * SIZE + len(words)] = words
        manifest.append(dict(name=name, entry=base + offsets[name], slot=base + offsets[name + "_slot"],
                             first=first))
    if len(sys.argv) == 4:
        image = b"".join(image[index:index + 4][::-1] for index in range(0, len(image), 4))
    image_path.write_bytes(image)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print("PREDICATED_REGISTER_JUMP_FIXTURE_OK cases=" + str(len(manifest)))


if __name__ == "__main__":
    main()
