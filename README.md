# ghidra-c6000

A free, open-source **Ghidra 12.x processor extension for the Texas Instruments
TMS320C6000 DSP family** (C64x, C64x+, C67x, C67x+ and C674x). It adds full32 and
compact 16-bit decoding, p-code semantics for the decompiler, the C6000 C calling
convention and C6000-specific analyzers. The implementation is based on TI's public
documentation (principally [SPRUFE8B](https://www.ti.com/lit/ug/sprufe8b/sprufe8b.pdf));
no disassembler source was copied, which is what allows the Apache-2.0 licence. See
[`NOTICE.md`](NOTICE.md) for provenance.

## Install

1. Download `ghidra_<version>_PUBLIC_<date>_C6000.zip` from
   [Releases](https://github.com/geepot/ghidra-c6000/releases), or
   [build it](#build).
2. In Ghidra: *File → Install Extensions*, **+**, pick the zip, restart Ghidra.

Each zip is tied to the Ghidra version it was built against. Releases include builds for
12.1.3, 12.1.4 and 12.2; select the matching zip, or rebuild for another 12.x release.

## Quick start

- **Little-endian ELF:** just import it. An ELF loader opinion maps
  `EM_TI_C6000` (e_machine 140) to `C6000:LE:32:default`.
- **Raw image or big-endian ELF:** in the import dialog choose the language
  yourself and, for a raw image, set the base address.

| Language id | Use |
|---|---|
| `C6000:LE:32:default` | little-endian C674x / C64x+ / C64x timing, shared superset decoder |
| `C6000:BE:32:default` | big-endian variant |
| `C6000:LE:32:analysis` / `C6000:BE:32:analysis` | simplified single-precision p-code for *reading* float-heavy code; flag values are not suitable for emulation |
| `C6000:LE:32:c67x` / `C6000:BE:32:c67x` | C67x / C67x+ cross-path timing with exact floating-point p-code |
| `C6000:LE:32:c67x-analysis` / `C6000:BE:32:c67x-analysis` | C67x / C67x+ cross-path timing with simplified floating-point p-code |

Select a `c67x` variant explicitly for C67x/C67x+ images, including ELF imports.
ELF auto-selection continues to use `default`. C67x variants omit the C64x/C674x
cross-path stall from opted-in exact schedules (SPRU198K 6.3.2.2). They share the
existing superset decoder; per-device instruction legality, including TSCL/TSCH
availability, is not filtered. See [processor timing](docs/pipeline-schedules.md#processor-timing-selection).

A raw binary also needs an entry point before auto-analysis finds code. In the GUI,
navigate to the address and use the native **C6000 → Set Entry Point Here** action
(or `C6000SetEntry.java` from Script Manager); in headless
Ghidra, use `-preScript C6000SetEntry.java <hexaddr>`. The script rejects headless
imports without an address or an address outside loaded memory. Compact packets decode
only after the packet analyzer has primed the decode context, which auto-analysis does
before disassembly.

When upgrading an existing program for v1.1.1, keep a packed backup first. The language
version is now 1.2: Ghidra's native language migration rebuilds instruction prototypes
after compact operand corrections. See the
[migration notes](docs/internals.md#language-prototype-migration), including annotation
and existing error-bookmark handling.

## Native CodeBrowser tools

Enable **C6000Plugin** through **File → Configure → Configure All Plugins**, then
open **Analysis → C6000 → Processor Tools**. The dockable panel shows the current
processor model, packet, function and schedule state. Native Listing/menu actions
set raw-image entry points and preview, enable, validate or disable exact schedules.
They use cancellable Ghidra tasks, source-bound reviews and Undo; no scripts or JSON
manifests are required. See the [native tools guide](docs/native-ui.md).

The processor languages, ABI, automatic analyzers and decompiler injection are
available independently of this optional GUI plugin.

## Features and limitations

| Area | State |
|---|---|
| 32-bit decode | broad SPRUFE8B §3.12 coverage, legacy `MVC`, C64x+ `LL`/`SL`/`CMTL`; unknown words stay undefined rather than guessed |
| Compact 16-bit fetch packets | supported forms decode using the fetch-packet header (appendices C.4, D.4, E.4, F.4, G.3, H.4) |
| Branches and calls | PCE1-relative targets; delayed `B` + `ADDKPC` calls and `B3` returns recovered by analyzers |
| P-code | integer ALU, multiplies, saturating and packed arithmetic, bit fields, linear and AMR circular addressing, loads/stores, single- and selected double-precision FP, compares, shifts, branches, `MVC`; no unimplemented-instruction placeholders remain |
| Software loops (`SPLOOP` family) | decoded and annotated with bookmarks; a separate cycle scheduler replays loop buffers (`C6000LoopReplay.java`) |
| Exact packet timing (explicit opt-in) | bounded per-function schedules for supported instruction phases, overlapping branches and normal software loops; complete reviewed traces with sequential leaf calls use normal decompiler injection; unsupported contracts are refused |
| Calling convention | TI C6000 C ABI (A4/B4/A6/B6… arguments, A4 return, B3 return address, B15 stack) |
| Function ID | `tools/gen_fid.py` generator only; no database shipped (TI licence) |

Main limitations:

- Default instruction lifting handles each instruction separately; packet
  parallelism and result latency require a supported, explicitly enabled
  [exact packet schedule](docs/pipeline-schedules.md) with a proved entry contract.
  Proven unconditional B/BNOP windows and CALLP packet companions use native
  delay p-code; see the documented mixed-width emulator limitation.
- Closed-call decompilation requires explicit plans and reviewed entry assumptions.
  It supports sequential leaf calls; nested calls and arbitrary indirect targets
  remain unsupported, and recovered C may inline helper effects.
- Constant propagation is bounded to 512-byte windows to avoid heap
  exhaustion on large images.
- Floating-point status flags are incomplete for some instructions, and
  reciprocal-estimate seeds are not proven bit-exact.
- Linked-word operations and `IDLE` lift to named events for an external
  monitor or scheduler.
- Instruction and timing coverage is bounded by the documented models and
  regression fixtures; it is not a complete hardware-emulation contract.
- C66x-specific instructions are a known gap. There is no C66x language variant
  or complete C66x ISA support; see [limitations](docs/limitations.md#processor-families).

More detail:

- [docs/limitations.md](docs/limitations.md): every known limitation, including the software-loop model.
- [docs/internals.md](docs/internals.md): compact packets, execute packets and delay slots, branch targets, analyzers, calling convention, source layout.
- [docs/verification.md](docs/verification.md): reproducible checks, retained results, and optional corpus/GNU-oracle comparisons.
- [docs/pipeline-schedules.md](docs/pipeline-schedules.md): exact timing contracts, supported phases and refusal boundaries.
- [docs/software-loop-conformance.md](docs/software-loop-conformance.md): the software-loop behaviour contract for an emulator.
- [docs/release.md](docs/release.md): release compatibility and publishing checklist.

## Build

Requirements: **Ghidra 12.x** and the JDK it declares in `Ghidra/application.properties`
(`application.java.min`): **JDK 21** for 12.0 and 12.1, **JDK 25** for 12.2. The build
script selects this version when `JAVA_HOME` is unset and rejects an explicitly
configured JDK that is too old.

```sh
tools/build.sh                             # compile SLEIGH, build dist/*_C6000.zip
tools/build.sh --install /path/to/ghidra   # ... and unzip it into <ghidra>/Ghidra/Extensions
```

Set `GHIDRA_INSTALL_DIR` and `JAVA_HOME` if Ghidra and that JDK are not in Homebrew's
default locations. The script exists because Gradle's `buildExtension` does **not**
compile SLEIGH: a zip built without the `.sla` files installs cleanly and then fails at
import with `Unsupported language`. `build.sh` compiles every `.slaspec` first and
checks archive integrity, all four compiled language variants, the loader opinion,
extension JAR and compatibility version. It also rejects local research, scratch and
cache files. The verified zip path is recorded in `$GHIDRA_WORK/archive-path.txt`
(`scratch/build/archive-path.txt` by default).

## Testing

```sh
python3 tools/verify.py --jobs 2            # build and run LE/BE release regressions
python3 tools/verify.py --with-ti --jobs 2  # also require TI-assembled fixtures
```

CI ([`build.yml`](.github/workflows/build.yml)) runs the same core suite on Ghidra
12.1.3, 12.1.4 and 12.2. It checks the packaged extension in a fresh scratch
installation, including decode, native flow, exact packet scheduling and floating-point
execution. Logs and a JSON summary are retained. The additional TI-assembled checks
require a local C6000 compiler/assembler.

Beyond that, [docs/verification.md](docs/verification.md) describes:

- `C6000CorpusTest.java`, which linearly decodes any image you pass (path, base,
  offset, length) and reports instruction counts, placeholders and undecoded
  slots.
- `tools/oracle_compare.py` and the `audit_*_oracle.py` scripts, which compare
  listings against GNU `objdump -m tic6x` on supplied images and generated
  full32 and compact encoding samples.
- `tests/fixtures/*.py` generators plus matching `ghidra_scripts/C6000*Test.java`
  scripts, which execute p-code in Ghidra's emulator against expected results
  in both endian modes.

## Contributing

Bug reports and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). For a
wrong decode or wrong semantics, please use the
[issue template](https://github.com/geepot/ghidra-c6000/issues/new?template=wrong-decode.md)
and include the address, the bytes, and what you expected.

## Licence

Apache License 2.0; see [`LICENSE`](LICENSE) and [`NOTICE.md`](NOTICE.md). Ghidra is a
separate Apache-2.0 project of the NSA; this extension is not part of it.
