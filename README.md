# ghidra-c6000

A free, open-source **Ghidra 12.x processor extension for the Texas Instruments
TMS320C6000 DSP family** — the C64x, C64x+, C67x, C67x+ and C674x. Ghidra has
no C6000 support ([NationalSecurityAgency/ghidra#1807](https://github.com/NationalSecurityAgency/ghidra/issues/1807));
this module adds it.

The encodings and semantics are written independently from TI's public
documentation, principally **SPRUFE8B**, the *TMS320C674x CPU and Instruction
Set Reference Guide*. Every constructor names the figure or table it comes
from. See [`NOTICE.md`](NOTICE.md) for the full provenance record — no
disassembler source was copied, which is what makes the Apache-2.0 licence
below possible.

## Status

This is a **working decoder with staged semantics**, and the README says
exactly where the line is drawn.

| Area | State |
|---|---|
| 32-bit instruction decode (mnemonic, unit, operands, length) | complete for every encoding documented in SPRUFE8B §3.12 |
| Instruction lengths and execute-packet framing | complete |
| Branch / call targets (`B`, `BNOP`, `CALLP`, `BDEC`, `BPOS`) | modelled, PCE1-relative per the manual |
| Compact 16-bit fetch packets | modelled via the packet-header context (see below) |
| P-code semantics | integer ALU, immediates, loads/stores, compares, shifts, branches/calls, `MVC` |
| Everything else | lifts to a named `c6000_unimpl_<mnemonic>` userop |
| Function ID | generation script shipped; database not shipped (TI licence) |
| Floating point, `.M` multiply, packed 8/16-bit arithmetic, Galois, SPLOOP buffer internals | decode only |

Unimplemented instructions are **explicit, greppable placeholders**, not
silently wrong data flow. `C6000CorpusTest.java` counts how often each is
reached, so the number in the table below is a measurement, not a claim.

## Measured coverage

Command used for every row (see [Testing](#testing)):

```
C6000CorpusTest.java stage1   # or stage2
```

| Corpus | Bytes decoded | Instructions | Undecoded words | Compact packets | Headers |
|---|---:|---:|---:|---:|---:|
| CDJ-2000NXS stage 1 (`0x11801da0`, first 55,120 bytes) | 10,712 | 2,678 | 394 | 172 | 97 |
| CDJ-2000NXS stage 2 (`0xC0000000`, first 131,072 bytes) | 123,180 | 30,795 | 1,973 | 4,234 | 1,309 |

The stage images are **not** in this repository. The test accepts an external
image path and base address, so private firmware can be measured without being
committed; regenerate the images with
`tools/cdj_dsp_image.py` from the CDJ-2000NXS research project and point
`C6000CorpusTest.java` at them.

Every remaining undecoded word in the two rows above is a **compact 16-bit
slot**, not an unknown 32-bit opcode: the 32-bit table decodes the full manual
with zero fallbacks. Closing that row is the active work item.

The generic, redistributable half of the corpus is generated at test time from
GNU binutils (`as -march=c674x` / `objdump -m tic6x`) and cross-checked against
this module by `tools/oracle_compare.py`; nothing built by TI or by binutils is
committed.

## Build

Requirements: **Ghidra 12.x** and **JDK 21** (Ghidra rejects newer JDKs).

```sh
tools/build.sh                      # compile SLEIGH, build the extension zip
tools/build.sh --install /path/to/ghidra   # ... and install it there
```

`build.sh` exists because **`buildExtension` does not compile SLEIGH**. A zip
built without it installs cleanly and then fails at import with
`Unsupported language`. The script compiles every `.slaspec` first, builds,
then verifies that the zip actually contains `c6000_le.sla` and `c6000_be.sla`.
`.sla` files are build artifacts and are gitignored.

The manual equivalent:

```sh
export GHIDRA_INSTALL_DIR=/opt/homebrew/opt/ghidra/libexec   # Homebrew
export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
export _JAVA_OPTIONS=-Duser.home=/tmp/c6000-home             # Ghidra writes under $HOME
export GRADLE_USER_HOME=/tmp/c6000-gradle
mkdir -p /tmp/c6000-home

"$GHIDRA_INSTALL_DIR/support/sleigh" data/languages/c6000_le.slaspec
"$GHIDRA_INSTALL_DIR/support/sleigh" data/languages/c6000_be.slaspec
"$GHIDRA_INSTALL_DIR/support/gradle/gradlew" -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" buildExtension
```

Ghidra discovers extensions in **`<ghidra install>/Ghidra/Extensions/`**, not in
the user settings directory. Use *File → Install Extensions*, or unzip
`dist/ghidra_*_C6000.zip` into that directory.

## Languages

| Language | Use |
|---|---|
| `C6000:LE:32:default` | little-endian C674x / C64x+ / C64x / C67x+ / C67x |
| `C6000:BE:32:default` | big-endian variant (C6000 supports both byte orders) |

An ELF loader opinion maps `EM_TI_C6000` (e_machine 140) to the language, so a
C6000 ELF picks it automatically. Raw binary import works too: choose the
language and set the base address.

C674x is the union of the C64x+ and C67x+ instruction sets (SPRUFE8B §1.1), so
one description serves the older parts, which are subsets.

## Compact 16-bit fetch packets

This is the part of C6000 that naive decoders get wrong, so it is worth
describing the model.

A fetch packet is eight 32-bit words (32 bytes). It is a **compact** packet
exactly when bits 31–28 of its eighth word are `1110`; that word is then a
*header* rather than an instruction, its layout field says which of the other
words hold two 16-bit instructions, and its expansion field supplies the
register set (`RS`), LD/ST data size (`DSZ`), saturation (`SAT`) and
branch-mode (`BR`) parameters that a 16-bit opcode cannot express (§3.10.2).

The header sits **after** the instructions it describes. SLEIGH fixes an
instruction's length from the tokens it matches, so a constructor that peeked
at word 7 would have to declare every compact instruction 32 bytes long. The
decode context is therefore primed out of band:

* `c6000.C6000PacketAnalyzer` runs before Ghidra's disassembly pass and writes
  the per-slot context (`c_is16`, `c_rs`, `c_dsz`, `c_sat`, `c_br`, `c_prot`)
  for every compact packet.
* `c6000.C6000PacketContext.prime(program, monitor)` is the same logic as a
  static helper, so scripts and headless runs can call it directly; the corpus
  test does exactly that.
* With no context primed, every word decodes as a normal 32-bit instruction — a
  graceful fallback rather than a hard failure.

The header word itself decodes as a 4-byte `CPKT` instruction. That is
unambiguous: `1110` in bits 31..28 is the reserved predication encoding
`creg=7, z=0` (Table 3-9), so no valid 32-bit instruction matches it.

## Execute packets, delay slots and parallel semantics

* Bit 0 of each word is the p-bit; `p=1` chains the next instruction into the
  same execute packet. Execute packets cannot cross a fetch packet.
* Instructions in an execute packet read pre-packet state and commit together.
  Ghidra has no notion of an execute packet, so each instruction is lifted on
  its own with its own reads and writes. This is the usual pragmatic model; it
  is *correct* for the common case of one writer per register per packet and can
  mis-order a packet that reads and writes the same register. It is documented
  rather than hidden.
* Delay slots are not modelled as p-code. Branches (`B`, `BNOP`, `CALLP`, ...)
  have five and loads four; Ghidra's flow analysis follows the branch and the
  fall-through, which is what matters for recovery. `CALLP` writes `inst_start
  + 24` to `B3`, matching the five delay slots.
* Branch targets are **PCE1-relative** — relative to the first instruction of
  the containing fetch packet, not to the branch itself. `B`/`CALLP`/`BNOP`/
  `BDEC`/`BPOS`/`ADDKPC` all use `inst_start & 0xFFFFFFE0`, exactly as the
  manual's Execution blocks specify.

## Calling convention

`data/languages/c6000.cspec` implements the C6000 C ABI:

| | |
|---|---|
| arguments | A4, B4, A6, B6, A8, B8, A10, B10, A12, B12, then the stack |
| 32-bit return | A4 |
| return address | B3 |
| stack pointer | B15 |
| frame pointer | A15 |
| data pointer | B14 |
| callee-saved | A10–A15, B10–B15 |

## Testing

The corpus test is a GhidraScript; it linearly decodes an image and reports
instruction counts, the mnemonic histogram, the placeholder rate and the
undecoded-word count, and can dump a listing for oracle comparison.

```sh
export GHIDRA_WORK=$PWD/scratch
export _JAVA_OPTIONS=-Duser.home=$GHIDRA_WORK/home
mkdir -p $GHIDRA_WORK/home $GHIDRA_WORK/proj

GHIDRA_INSTALL_DIR=/opt/homebrew/opt/ghidra/libexec

# Private images: pass a path, a base and an offset/length; nothing is committed.
C6000_LISTING=$GHIDRA_WORK/stage1.listing \
  "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" $GHIDRA_WORK/proj c6000-s1 \
  -import /path/to/dsp.stage1.payload.bin \
  -loader BinaryLoader -loader-baseAddr 0x11801da0 \
  -processor C6000:LE:32:default -cspec default -noanalysis \
  -scriptPath ghidra_scripts -postScript C6000CorpusTest.java stage1 -overwrite
```

`tools/oracle_compare.py` diffs that listing against `objdump -m tic6x` and is
what caught the three defects this module is built to avoid. Note that
`objdump -b binary -m tic6x` needs `--endian=little` and an input of at least
32 bytes.

### Known Ghidra 12.1.3 pitfall

If *every* Java script in a script directory suddenly fails with
`Failed to get OSGi bundle containing script`, look for a **compile error in a
sibling `.java` file**. Ghidra compiles a script directory as one OSGi bundle,
and `GhidraSourceBundle.tryBuild` dereferences a `javac` diagnostic whose source
is null (Ghidra 12.1.3, `GhidraSourceBundle.java:843`), so the whole build dies
with a `NullPointerException` that is reported as that misleading message, while
the console `PrintWriter` is never flushed. Keep independently-buildable scripts
in separate `-scriptPath` directories.

## Function ID

`tools/gen_fid.py` builds a Function ID database from a TI run-time library.
The **`.fidbf` is deliberately not shipped**: the TI code generation tools'
licence does not clearly permit redistributing a database derived from TI's RTS,
and the safe default is to ship the generator and let each user build it from
their own CGT install. Read the script's header before redistributing anything
it produces.

## Known limitations

* **Compact instructions decode via the header context**; a tool that
  disassembles without running `C6000PacketAnalyzer` (or calling
  `C6000PacketContext.prime`) will see compact packets as 32-bit code.
* **Execute packets are not modelled as units** — see above.
* **No delay-slot modelling** in p-code.
* **`.M` multiply, floating point, packed 8/16-bit and Galois semantics** are
  placeholders. Control-register reads/writes via `MVC` are decoded but the
  control register is not yet distinguished from a general-purpose register in
  every form.
* **`SPLOOP` buffer execution** is not modelled: the loop buffer is a
  microarchitectural structure with no program-counter effect, so the SPLOOP
  control instructions lift to placeholders rather than to a branch.
* **Predication** is decoded and displayed (`[B0] ADD.L1 ...`) but is not
  applied to the lifted p-code, so a predicated instruction's effects are not
  conditional in the decompiler.
* The generic corpus is assembled from GNU binutils, whose tic6x assembler
  covers less of the ISA than the manual; it is a regression oracle, not a
  completeness proof.

## Repository layout

```
build.gradle, settings.gradle, extension.properties, Module.manifest
data/languages/          c6000.sinc (framework), c6000_decode.sinc (generated),
                         c6000_manual.sinc, c6000_compact.sinc, c6000_semantics.sinc,
                         c6000_placeholders.sinc (generated), ldefs/pspec/cspec/opinion
ghidra_scripts/          C6000CorpusTest.java
src/main/java/c6000/     C6000PacketContext.java, C6000PacketAnalyzer.java
tools/                   build.sh, gen_decode.py, build_encodings.py,
                         oracle_compare.py, gen_fid.py
.github/workflows/       build.yml
```

`c6000_decode.sinc` and `c6000_placeholders.sinc` are generated by
`tools/gen_decode.py` from an encoding table parsed out of SPRUFE8B §3.12
(`tools/build_encodings.py`). They are committed so the extension builds
without the manual; do not edit them by hand.

## Licence

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE.md`](NOTICE.md).
