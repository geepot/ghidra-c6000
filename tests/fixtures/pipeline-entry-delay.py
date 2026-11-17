#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TI-assembled exact schedule whose entry packet issues a jump: IMAGE CASES.json [be].

Requires TI's C6000 assembler (TI_C6000_BIN as in pipeline-predicate-facts.py).
cl6x 8.3.15 -mv6740 --no_compress assembles a jump issued by the entry packet, its
five delay slots, a skipped ADDK, the jump's target and return, and an outside jump
into the first slot. Full32 only, so BE swaps each word's bytes.
"""
from pathlib import Path
import importlib.util
import json
import os
import subprocess
import sys

SOURCE = """ .sect ".pf_entry_delay"
 .nocmp
entry_jump:
 B.S2 entry_tail
entry_jump_slot:
 MVK.S1 5,A4
 MVK.S2 7,B4
 ADD.L1 A4,1,A4
 ADD.L2 B4,1,B4
 MV.L1 A4,A5
skipped:
 ADDK.S1 1000,A4
entry_tail:
 ADD.L1X A4,B4,A4
 B.S2 B3
 NOP 5
 .space 0xd8
outside_jump:
 B.S2 entry_jump_slot
 NOP 5
"""


def main():
    if len(sys.argv) not in (3, 4) or len(sys.argv) == 4 and sys.argv[3] != "be":
        raise SystemExit("Usage: pipeline-entry-delay.py IMAGE CASES.json [be]")
    image_path, manifest_path = map(Path, sys.argv[1:3])
    image_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    prefix = image_path.parent / (image_path.stem + ".entry-delay")
    assembly, object_file, log = (Path(str(prefix) + suffix) for suffix in (".asm", ".obj", ".log"))
    assembly.write_text(SOURCE)
    binary = Path(os.environ.get("TI_C6000_BIN", "/Applications/ti/ti-cgt-c6000_8.3.15/bin"))
    compiler = binary / "cl6x" if binary.is_dir() else binary
    command = [str(compiler), "-mv6740", "--abi=eabi", "--no_compress", "-c",
               str(assembly), "--output_file=" + str(object_file)]
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log.write_text(completed.stdout)
    if completed.returncode:
        raise RuntimeError("TI assembly failed; see " + str(log))
    spec = importlib.util.spec_from_file_location(
        "predicate_facts", Path(__file__).with_name("pipeline-predicate-facts.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    code = module.object_sections(object_file)[".pf_entry_delay"]
    if len(code) != 0x120:  # padded to a fetch packet
        raise ValueError("Unexpected entry-delay section length " + hex(len(code)))
    image = bytearray(0x200)
    image[:len(code)] = code
    if len(sys.argv) == 4:
        image = b"".join(image[index:index + 4][::-1] for index in range(0, len(image), 4))
    image_path.write_bytes(image)
    manifest = dict(entry=0x1000, body_end=0x1027, window_end=0x1017, slot=0x1004, inside=0x1018,
                    outside=0x1100)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print("PIPELINE_ENTRY_DELAY_FIXTURE_OK")


if __name__ == "__main__":
    main()
