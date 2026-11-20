#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TI-assembled same-packet register hazards (issue #71): IMAGE CASES.json [be].

Requires TI's C6000 assembler (TI_C6000_BIN as in pipeline-predicate-facts.py).
Each case is a function f(a, b) in one section loaded at 0x1000 + 0x40 * index.
Every member of an execute packet reads its operands before any member writes
(SPRUFE8B 3.5), but native lifting runs members one after another, so a member that
reads what an earlier member writes is warned. warn lists those members as offsets
from the entry. Full32 only, so BE swaps each word's bytes.
"""
from pathlib import Path
import importlib.util
import json
import os
import subprocess
import sys

SIZE = 0x40
RET = """        B       .S2     B3
        NOP             5
"""
# name, offsets of the warned members, body
CASES = [
    # #71's ps0: return b - a, but sequential MVs give 0
    ("ps0", [4], """{n}:
        MV      .L1X    B4,A4
||      MV      .S1     A4,A5
        SUB     .L1     A4,A5,A4
""" + RET),
    # ps0 with a TSCL write, which a schedule refuses as opaque
    ("timer", [4], """{n}:
        MV      .L1X    B4,A4
||      MV      .S1     A4,A5
||      MVC     .S2     B5,TSCL
        SUB     .L1     A4,A5,A4
""" + RET),
    # The return reads the caller's B3, not the B5 written beside it
    ("branch", [4], """{n}:
        MV      .L2     B5,B3
||      B       .S2     B3
        NOP             5
"""),
    # A new rounding mode in FADCR is not seen by an ADDSP in the same packet
    ("rounding", [4], """{n}:
        MVC     .S2     B0,FADCR
||      ADDSP   .L1     A4,A5,A4
""" + RET),
    # A write to the predicate register runs before a reader under the opposite predicate
    ("predicate", [8], """{n}:
        MV      .L2X    A4,B0
  [!B0] MVK     .S2     1,B0
||[B0]  ADD     .L1     A4,1,A4
""" + RET),
    # Opposite predicates on B0, which neither writes: at most one runs
    ("exclusive", [], """{n}:
        MV      .L2X    A4,B0
  [!B0] MVK     .S1     5,A4
||[B0]  ADD     .L1     A4,1,A4
""" + RET),
    # The same pair in a return's delay window
    ("slot", [], """{n}:
        MV      .L2X    A4,B0
        B       .S2     B3
  [!B0] MVK     .S1     5,A4
||[B0]  ADD     .L1     A4,1,A4
        NOP             4
"""),
    # Known-goods: two ADDSPs only OR sticky flags into FADCR, which commutes;
    # the reader comes first; the members are in separate packets
    ("sticky", [], """{n}:
        ADDSP   .L1     A4,A5,A4
||      ADDSP   .L2     B4,B5,B4
""" + RET),
    # The reader comes first, or the members are in separate packets
    ("order", [], """{n}:
        MV      .S1     A4,A5
||      MV      .L1X    B4,A4
        SUB     .L1     A4,A5,A4
""" + RET),
    ("serial", [], """{n}:
        MV      .L1X    B4,A4
        MV      .S1     A4,A5
        SUB     .L1     A4,A5,A4
""" + RET),
    # ps0 after an entry packet, which an active schedule makes its whole lifting;
    # the check activates a reviewed schedule for it
    ("reviewed", [8], """{n}:
        MVK     .S1     0,A6
        MV      .L1X    B4,A4
||      MV      .S1     A4,A5
        SUB     .L1     A4,A5,A4
""" + RET),
]


def main():
    if len(sys.argv) not in (3, 4) or len(sys.argv) == 4 and sys.argv[3] != "be":
        raise SystemExit("Usage: same-packet-hazard.py IMAGE CASES.json [be]")
    image_path, manifest_path = map(Path, sys.argv[1:3])
    image_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    prefix = image_path.parent / (image_path.stem + ".same-packet-hazard")
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
    spec = importlib.util.spec_from_file_location(
        "predicate_facts", Path(__file__).with_name("pipeline-predicate-facts.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    code = module.object_sections(object_file)
    image = bytearray(len(CASES) * SIZE)
    manifest = []
    for index, (name, warn, _) in enumerate(CASES):
        words = code[".pf_" + name]
        if len(words) > SIZE:
            raise ValueError("Section too long for " + name)
        base = 0x1000 + index * SIZE
        image[index * SIZE:index * SIZE + len(words)] = words
        manifest.append(dict(name=name, entry=base, end=base + SIZE - 1, warn=[base + w for w in warn]))
    if len(sys.argv) == 4:
        image = b"".join(image[index:index + 4][::-1] for index in range(0, len(image), 4))
    image_path.write_bytes(image)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print("SAME_PACKET_HAZARD_FIXTURE_OK cases=" + str(len(manifest)))


if __name__ == "__main__":
    main()
