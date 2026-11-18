#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TI-assembled software-pipelined countdown loops: IMAGE CASES.json [be].

Requires TI's C6000 assembler (TI_C6000_BIN as in pipeline-predicate-facts.py).
Each case is a function whose 5-cycle kernel ends in [A1] B kernel, entered by a
prior B kernel so a branch is always in flight; the kernel counts passes in B5.
When a loop branch falls through, A1 == 0, and a write predicated on [A1] cannot
change a zero A1 (SPRUFE8B 3.5, 3.7), so the next loop branch falls through too.
The epilogue's LDW into B5 lands exactly when that next branch, if taken, would
re-enter the kernel's ADD to B5, so a compile that loses A1 == 0 at the backward
redirect refuses the function. The known-bad kernels can leave A1 nonzero.
Full32 only, so BE swaps each word's bytes.
"""
from pathlib import Path
import importlib.util
import json
import os
import subprocess
import sys

# name, accepted, decrement (k1), extra kernel op (k2), A1 truths the compiler may hold at the kernel (-1 unknown)
SPECS = [
    ("self_guarded", True, " [A1] SUB.L1 A1,1,A1", " NOP", [-1, 0]),
    ("unpredicated_decrement", False, " SUB.L1 A1,1,A1", " NOP", [-1]),
    ("other_register_guard", False, " [A2] SUB.L1 A1,1,A1", " NOP", [-1]),
    ("inverted_guard", False, " [!A1] SUB.L1 A1,1,A1", " NOP", [-1, 1]),
    ("unpredicated_rewrite", False, " [A1] SUB.L1 A1,1,A1", " ADD.L1 A6,A1,A1", [-1]),
    # issued while A1 is nonzero, the load lands after the decrement zeroes A1 and the branch falls through
    ("inflight_guarded_load", False, " [A1] LDW.D2T1 *B4,A1", " [A1] SUB.L1 A1,1,A1", [-1]),
]
SIZE = 0x80
KERNEL, BODY = 0xc, 0x3c  # kernel offset; body length (15 words)


def case(name, decrement, extra):
    tag = "pf_" + name
    return [' .sect ".' + tag + '"', " .nocmp", tag + ":",
            " ZERO.L2 B5",               # B5 counts kernel passes
            " MV.L1 A4,A1",              # A1 = n
            " B.S1 " + tag + "_kernel",  # the kernel runs as this branch's slots
            tag + "_kernel:",
            " ADD.L2 B5,1,B5",
            decrement,
            extra,
            " NOP",
            " [A1] B.S1 " + tag + "_kernel",
            " MV.L2 B5,B6",              # epilogue: e0
            " LDW.D2T2 *B4,B5",          # e1: lands in e5, where a taken loop branch would run ADD B5
            " NOP 4",
            " ADD.L2 B5,B6,B5",          # result: *B4 + passes
            " B.S2 B3",
            " MV.L1X B5,A4",
            " NOP 4"]


def main():
    if len(sys.argv) not in (3, 4) or len(sys.argv) == 4 and sys.argv[3] != "be":
        raise SystemExit("Usage: pipeline-selfguard-loop.py IMAGE CASES.json [be]")
    image_path, manifest_path = map(Path, sys.argv[1:3])
    image_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    prefix = image_path.parent / (image_path.stem + ".selfguard-loop")
    assembly, object_file, log = (Path(str(prefix) + suffix) for suffix in (".asm", ".obj", ".log"))
    lines, manifest = [], []
    for index, (name, accepted, decrement, extra, truths) in enumerate(SPECS):
        base = 0x1000 + index * SIZE
        lines += case(name, decrement, extra)
        manifest.append(dict(name=name, at=base, body_end=base + BODY - 1, kernel=base + KERNEL,
                             kernel_truths=truths, accepted=accepted))
    assembly.write_text("\n".join(lines) + "\n")
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
    sections = module.object_sections(object_file)
    image = bytearray(len(SPECS) * SIZE)
    for index, item in enumerate(manifest):
        code = sections[".pf_" + item["name"]]
        if len(code) != 0x40:  # padded to a fetch packet
            raise ValueError("Unexpected section length " + hex(len(code)) + " for " + item["name"])
        image[index * SIZE:index * SIZE + len(code)] = code
    if len(sys.argv) == 4:
        image = b"".join(image[index:index + 4][::-1] for index in range(0, len(image), 4))
    image_path.write_bytes(image)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print("PIPELINE_SELFGUARD_LOOP_FIXTURE_OK cases=" + str(len(manifest)))


if __name__ == "__main__":
    main()
