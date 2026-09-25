# ghidra-c6000

A free, open-source **Ghidra 12.x processor extension for the Texas Instruments
TMS320C6000 DSP family** (C64x, C64x+, C67x, C67x+ and C674x). Ghidra has no
C6000 support ([NationalSecurityAgency/ghidra#1807](https://github.com/NationalSecurityAgency/ghidra/issues/1807));
this module adds decoding, including compact 16-bit fetch packets, p-code
semantics for the decompiler, the C6000 C calling convention and C6000-specific
analyzers. It was written to reverse-engineer the C674x DSP firmware of the
Pioneer CDJ-2000NXS, independently from TI's public documentation
(principally [SPRUFE8B](https://www.ti.com/lit/ug/sprufe8b/sprufe8b.pdf)); no
disassembler source was copied, which is what allows the Apache-2.0 licence.
See [`NOTICE.md`](NOTICE.md) for provenance.

## Install

1. Download `ghidra_<version>_PUBLIC_<date>_C6000.zip` from
   [Releases](https://github.com/geepot/ghidra-c6000/releases), or
   [build it](#build).
2. In Ghidra: *File → Install Extensions*, **+**, pick the zip, restart Ghidra.

The zip is tied to the Ghidra version it was built against (the current
release targets 12.1.3); rebuild it for any other 12.x release.

## Quick start

- **Little-endian ELF:** just import it. An ELF loader opinion maps
  `EM_TI_C6000` (e_machine 140) to `C6000:LE:32:default`.
- **Raw image or big-endian ELF:** in the import dialog choose the language
  yourself and, for a raw image, set the base address.

| Language id | Use |
|---|---|
| `C6000:LE:32:default` | little-endian C674x / C64x+ / C64x / C67x+ / C67x |
| `C6000:BE:32:default` | big-endian variant |
| `C6000:LE:32:analysis` / `C6000:BE:32:analysis` | simplified single-precision p-code for *reading* float-heavy code; flag values are not suitable for emulation |

A raw binary also needs an entry point before auto-analysis finds code. In
the GUI, navigate to the address and run `C6000SetEntry.java` from Script
Manager; in headless Ghidra, use `-preScript C6000SetEntry.java <hexaddr>`.
The script rejects headless imports without an address or an address outside
loaded memory.
Compact packets decode only after the packet analyzer has primed the decode
context, which auto-analysis does before disassembly.

## Features and limitations

| Area | State |
|---|---|
| 32-bit decode | broad SPRUFE8B §3.12 coverage, legacy `MVC`, C64x+ `LL`/`SL`/`CMTL`; unknown words stay undefined rather than guessed |
| Compact 16-bit fetch packets | most observed forms decode, driven by the fetch-packet header (appendices C.4, D.4, E.4, F.4, G.3, H.4) |
| Branches and calls | PCE1-relative targets; delayed `B` + `ADDKPC` calls and `B3` returns recovered by analyzers |
| P-code | integer ALU, multiplies, saturating and packed arithmetic, bit fields, linear and AMR circular addressing, loads/stores, single- and selected double-precision FP, compares, shifts, branches, `MVC`; no unimplemented-instruction placeholders remain |
| Software loops (`SPLOOP` family) | decoded and annotated with bookmarks; a separate cycle scheduler replays loop buffers (`C6000LoopReplay.java`) |
| Calling convention | TI C6000 C ABI (A4/B4/A6/B6… arguments, A4 return, B3 return address, B15 stack) |
| Function ID | `tools/gen_fid.py` generator only; no database shipped (TI licence) |

Main limitations:

- Execute packets are not atomic: each instruction is lifted on its own, and
  delay slots are not modelled in p-code.
- Constant propagation is bounded to 512-byte windows to avoid heap
  exhaustion on large images.
- Floating-point status flags are incomplete for some instructions, and
  reciprocal-estimate seeds are not proven bit-exact.
- Linked-word operations and `IDLE` lift to named events for an external
  monitor or scheduler.
- Architecture-wide fidelity is not established: firmware coverage and oracle
  samples are regression evidence, not a completeness proof.

More detail:

- [docs/limitations.md](docs/limitations.md): every known limitation, including the software-loop model.
- [docs/internals.md](docs/internals.md): compact packets, execute packets and delay slots, branch targets, analyzers, calling convention, source layout.
- [docs/verification.md](docs/verification.md): measured firmware coverage, GNU-oracle comparisons, and the per-instruction test fixtures.
- [docs/software-loop-conformance.md](docs/software-loop-conformance.md): the software-loop behaviour contract for an emulator.

## Build

Requirements: **Ghidra 12.x** and **JDK 21** (Ghidra 12 rejects newer JDKs).

```sh
tools/build.sh                             # compile SLEIGH, build dist/*_C6000.zip
tools/build.sh --install /path/to/ghidra   # ... and unzip it into <ghidra>/Ghidra/Extensions
```

Set `GHIDRA_INSTALL_DIR` and `JAVA_HOME` if Ghidra and JDK 21 are not in
Homebrew's default locations. The script exists because Gradle's
`buildExtension` does **not** compile SLEIGH: a zip built without the `.sla`
files installs cleanly and then fails at import with `Unsupported language`.
`build.sh` compiles every `.slaspec` first and checks that the zip contains all
four compiled language variants and the loader opinion.

## Testing

CI ([`build.yml`](.github/workflows/build.yml)) runs `tools/build.sh`, installs
the zip into a fresh Ghidra 12.1.3 and decodes a 48-byte synthetic image with
`C6000CorpusTest.java`, requiring no undecoded slots and no zero-width p-code
operands.

Beyond that, [docs/verification.md](docs/verification.md) describes:

- `C6000CorpusTest.java`, which linearly decodes any image you pass (path, base,
  offset, length) and reports instruction counts, placeholders and undecoded
  slots. No firmware is in this repository.
- `tools/oracle_compare.py` and the `audit_*_oracle.py` scripts, which compare
  listings against GNU `objdump -m tic6x` on firmware and on random 32-bit and
  compact encoding samples.
- `tests/fixtures/*.py` generators plus matching `ghidra_scripts/C6000*Test.java`
  scripts, which execute p-code in Ghidra's emulator against expected results
  in both endian modes.

## Contributing

Bug reports and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
For a wrong decode or wrong semantics, please use the
[issue template](https://github.com/geepot/ghidra-c6000/issues/new?template=wrong-decode.md)
and include the address, the bytes, and what you expected.

## Licence

Apache License 2.0; see [`LICENSE`](LICENSE) and [`NOTICE.md`](NOTICE.md).
Ghidra is a separate Apache-2.0 project of the NSA; this extension is not part
of it.
