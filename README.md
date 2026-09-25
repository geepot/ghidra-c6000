# ghidra-c6000

A free, open-source **Ghidra 12.x processor extension for the Texas Instruments
TMS320C6000 DSP family** — the C64x, C64x+, C67x, C67x+ and C674x. Ghidra has
no C6000 support ([NationalSecurityAgency/ghidra#1807](https://github.com/NationalSecurityAgency/ghidra/issues/1807));
this module adds it.

The encodings and semantics are written independently from TI's public
documentation, principally **[SPRUFE8B](https://www.ti.com/lit/ug/sprufe8b/sprufe8b.pdf)**,
the *TMS320C674x CPU and Instruction Set Reference Guide*. The handwritten
definitions and generators identify their source figures and tables. See
[`NOTICE.md`](NOTICE.md) for the full provenance record — no
disassembler source was copied, which is what makes the Apache-2.0 licence
below possible.

## Status

This is a **working decoder with staged semantics**. The firmware measurements
below show both the decoded instructions and the remaining gaps.

| Area | State |
|---|---|
| 32-bit instruction decode (mnemonic, unit, operands, length) | broad SPRUFE8B §3.12 coverage, plus legacy `MVC`; some words remain undecoded |
| Instruction lengths and execute-packet framing | 2/4-byte lengths and compact layout context; execute packets are not atomic |
| Branch / call targets (`B`, `BNOP`, `CALLP`, `BDEC`, `BPOS`) | modelled, PCE1-relative per the manual |
| Compact 16-bit fetch packets | most observed slots decode, driven by packet-header context (see below) |
| P-code semantics | integer ALU and common multiplies, compact saturating arithmetic, immediates, bit-field operations, linear address arithmetic, scalar and doubleword loads/stores, single-precision arithmetic and conversions, selected double-precision arithmetic and conversions, compares, shifts, branches/calls, `MVC` |
| Other decoded instructions | 32-bit forms lift to explicit `c6000_unimpl_<mnemonic>` userops; every decoded compact form has p-code |
| Function ID | generation script shipped; database not shipped (TI licence) |
| Software loop controls | decoded and annotated; a separate cycle scheduler replays buffered packets and stage-boundary `ILC` changes, including predicate-driven `SPLOOPW` |
| Remaining double-precision floating point, advanced integer `.M` multiply, packed 8/16-bit arithmetic, Galois | decode only |

Unimplemented instructions are **explicit, greppable placeholders**, not
silently wrong data flow. `C6000CorpusTest.java` counts how often each is
reached, so the number in the table below is a measurement, not a claim.

## Measured coverage

Command used for every row (see [Testing](#testing)):

```
C6000CorpusTest.java stage1   # or stage2
```

| Corpus (first 12,288 / 131,072 bytes) | Bytes decoded | Instructions | Compact 16-bit | Headers | Unimplemented p-code | Undecoded slots | Byte coverage |
|---|---:|---:|---:|---:|---:|---:|---:|
| CDJ-2000NXS stage 1, base `0x11801da0` | 11,328 | 3,179 | 694 | 162 | 1 (<1%) | 240 | **92.2%** |
| CDJ-2000NXS stage 2, base `0xC0000000` | 131,052 | 36,600 | 7,674 | 2,214 | 9 (<1%) | 5 | **99.98%** |

Full-payload linear sweeps also completed with no zero-width p-code operands:

| Corpus | Payload bytes | Bytes decoded | Instructions | Unimplemented p-code | Undecoded slots | Byte coverage |
|---|---:|---:|---:|---:|---:|---:|
| Stage 1 | 55,120 | 40,328 | 10,452 | 838 (8%) | 3,698 | **73.2%** |
| Stage 2 | 361,248 | 335,972 | 91,483 | 23 (<1%) | 6,319 | **93.0%** |

The sweeps found 24 paired software loops and 43 buffer masks in stage 1,
and 224 paired loops and 470 buffer masks in stage 2. No detected loop
boundary was left unmatched. The loop schedule parsed and replayed all 24
stage 1 loops and all 224 stage 2 loops, with no body decode gaps.
The loop-control userops are counted separately from unimplemented instruction
placeholders.

`CPKT` headers now decode as named 4-byte rows. Undecoded slots remain: the
stage 1 window is mostly `0xffffffff` fill/data. The stage 2 window
has five 32-bit gaps; its compact halfwords now decode. Byte coverage is a
linear sweep of the stated windows or payloads, not a claim that every byte is
code. The full stage 1 image in particular contains substantial fill/data;
some repeating table bytes resemble compact instructions, so full-image
instruction counts are not a measure of executable-code coverage.
The full-payload sweeps used `-noanalysis`; normal Ghidra autoanalysis completed
on the stage 2 code window. Running autoanalysis after a full stage 2 linear
sweep exceeded the available Ghidra 12.1.3 heap, so the full-payload numbers
are decode and p-code checks rather than a whole-image decompiler test.

The stage images are **not** in this repository. The test accepts an external
image path and base address, so private firmware can be measured without being
committed; regenerate the images with
`tools/cdj_dsp_image.py` from the CDJ-2000NXS research project and point
`C6000CorpusTest.java` at them.

Compact decode is driven by the packet header through the `noflow` context
fields described below. The 32-bit table covers the documented opcode maps;
the compact table covers appendices C.4, D.4, E.4, F.4, G.3 and H.4, with
unresolved patterns still visible in the corpus. SPRUFE8B's figure D-6
(`Ltbd`) has blank field cells and no instruction description to resolve it.

The generic, redistributable half of the corpus is generated at test time from
GNU binutils (`as -march=c674x` / `objdump -m tic6x`) and cross-checked against
this module by `tools/oracle_compare.py`; nothing built by TI or by binutils is
committed.

Compact saturation regression fixtures are generated by
`tests/fixtures/compact-saturation.py <image.bin> <cases.tsv> [be]` and executed
with `C6000CompactSaturationTest.java <cases.tsv>` after importing the raw image
at `0x1000` with the matching C6000 language. The 23 cases per endian cover
SADD/SSUB overflow, four SMPY halfword selections, SSHL saturation and count
boundaries, compact forms whose SAT header bit is ignored, and S-unit formats
with the BR header bit set. The processor
spec declares a synthetic `PC` for Ghidra's emulator; architectural `PCE1`
remains a separate control register. P-code updates `CSR.SAT` as an instruction
effect; cycle-accurate placement of that write belongs to a pipeline model.

`tests/fixtures/long-arith.py <image.bin> [be]` and
`C6000LongArithmeticTest.java` check both endian variants of 32-bit `NORM`
and `SUBU`. The seven cases include the 40-bit register-pair forms, sign
boundaries, and a negative 40-bit subtraction result.

`tests/fixtures/fp-int.py <image.bin> <cases.tsv> [be]` and
`C6000FpConvertTest.java <cases.tsv>` check `SPINT` and `SPTRUNC` in both
endian modes. The 23 cases per mode cover all FADCR rounding modes, ties to
even, signed overflow, NaN, infinity, denormals, and the separate `.L1`/`.L2`
warning bits.

`tests/fixtures/dp-int.py <image.bin> <cases.tsv> [be]` and
`C6000DpConvertTest.java <cases.tsv>` check `DPINT` and `DPTRUNC` with
register-pair sources. The 17 original cases per mode cover rounding,
exceptions, warning bits, and the signed 32-bit result limits; six more cases
cover both pair encodings for `DPINT`, `DPTRUNC`, and `DPSP`. The odd/high
register in `src2` selects the 64-bit pair. TI's assembler sets `src1` to zero,
whereas older GNU tic6x assemblers encoded the even/low register there. The
decoder accepts both variants; see
[binutils gas/15094](https://lists.gnu.org/archive/html/bug-binutils/2013-02/msg00037.html).

`tests/fixtures/packed-arith.py <image.bin> <cases.tsv> [be]` and
`C6000PackedArithmeticTest.java <cases.tsv>` execute 24 packed arithmetic,
comparison, and min/max cases per endian mode, including cross-path `.S2`
sources and signed/unsigned lane boundaries.

The generated 32-bit decode table can be rebuilt from the public TI PDF:
run `pdftotext -layout sprufe8b.pdf /tmp/c6000ref/sprufe8b.txt`, then
`python3 tools/build_encodings.py /tmp/c6000ref/sprufe8b.txt` and
`python3 tools/gen_decode.py`. The intermediate `.research/` tables are
gitignored. `tools/build_encodings.py` expands the manual's grouped `LDB(U)`
and `LDH(U)` headings into distinct signed and unsigned opcodes; the generator
rejects unconstrained opcode fields so a malformed parse cannot create a
broad, false decode pattern.

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

* Bit 0 of each 32-bit opcode is its p-bit. A compact 16-bit instruction's
  p-bit comes from bits 13–0 of its fetch-packet header. In either case,
  `p=1` chains the next instruction into the same execute packet, including
  across a fetch-packet boundary.
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

* **Compact instructions decode via the header context**, which the Java
  analyzer primes before disassembly. The context fields are marked `noflow`
  so a compact slot reached by fall-through is not decoded with the previous
  instruction's parameters; the price is that a tool which disassembles
  without priming the context will not decode compact packets at all.
* **Some compact and 32-bit words remain undecoded.** The decoder leaves them
  undefined instead of guessing an instruction.
* **Execute packets are not modelled as units** — see above.
* **No delay-slot modelling** in p-code.
* **Circular AMR addressing is not modelled.** `.D` address arithmetic and
  load/store effective addresses use linear mode, with size scaling and
  pre/post register updates. Base writes occur after the memory transfer so a
  store using the same register for its source and base reads the old value.
* **Advanced integer `.M` multiply, remaining double-precision floating point,
  remaining packed 8/16-bit, and Galois semantics** are placeholders. Common 16-bit signed,
  unsigned and mixed-sign multiplies and `MPYLI` are modelled. Doubleword
  loads and stores transfer an overlapping 64-bit register pair. Selected
  double-precision arithmetic, comparisons and conversions use the same pair
  views; floating-point status register side effects remain unmodelled. `MVC` uses
  distinct control registers in its 32-bit forms; the compact `MVC` to `ILC`
  is also modelled.
* **Software loops:** `SPLOOP`, `SPLOOPD`, `SPLOOPW`, `SPKERNEL`,
  `SPKERNELR`, `SPMASK`, and `SPMASKR` lift to named p-code userops with their
  interval, encoded predicate selector, delay field, or unit mask. The selector
  preserves which register the buffer evaluates at later stage boundaries.
  The unconditional `SPLOOP`
  also performs its initial nonzero `ILC` decrement. Both 16-bit and 32-bit
  initiation intervals display their actual value (encoded value plus one).
  `C6000SoftwareLoopAnalyzer` matches each disassembled loop start with its
  kernel boundary and adds Info bookmarks at both addresses. The bookmarks
  resolve the six-bit `SPKERNEL` field to stage/cycle delay using the loop's
  initiation interval and show the source body, execute-packet count and
  dynamic length in cycles, including `NOP n` idle cycles;
  `SPMASK` bookmarks list the affected functional units. Source packets from
  different stages overlay the same buffer slots, so their count may exceed
  the buffer's 14-entry capacity. If an undecoded slot lies in the body, its
  byte count appears in the bookmark instead of an exact packet count.
  `C6000LoopBuffer` replays source and buffered instructions by cycle without
  adding a false PC branch. It handles initiation interval overlap, source
  `SPMASK` filtering, counted `SPLOOP`/`SPLOOPD` termination, the first-three-
  cycle `SPLOOPD` grace period, and the three-cycle delayed `SPLOOPW`
  predicate. `SPLOOPW` also decrements `ILC` at every stage boundary without
  using it to decide termination. The callback exposes each cycle's operations
  and `ILC` before and after stage boundaries. Zero- and one-iteration loops
  issue idle cycles through the last loading-stage boundary when the body ends
  partway through a stage. The detailed replay result gives the first cycle
  of post-body program-memory fetch; each overlapping epilog cycle marks its
  post-body fetch index. Given a caller-selected post-body execute packet,
  `overlayPostBody` applies its `SPMASK` to buffered operations in that cycle.
  For counted loops, a caller-supplied pending, unblocked interrupt signal can
  start draining at an eligible stage boundary; the result preserves `ILC` and
  keeps post-body fetch disabled. The result stops when the loop buffer finishes
  draining, before pending pipeline writes and handler entry. `SPLOOPW` keeps
  testing its delayed predicate during interrupt drain; if it ends the loop,
  the result identifies the first post-body instruction as the interrupt target.
  An `INTERRUPT_DRAINED` result yields an `InterruptHandoff` with the saved
  `SPLOOP` packet address, `ILC`, and `SPLX` state. After the caller restores
  architectural state, `replayCountedRestart` or `replayWhileRestart` pipes the
  loop back up: source `SPMASK` suppresses program operations, buffered masked
  operations execute, and `SPLOOPD` uses the `SPLOOP` initial test/decrement.
  In Ghidra's Script Manager, run
  `C6000LoopReplay.java` on a selected `SPLOOP`, or pass its address, initial
  `ILC` (for counted loops) or number of true predicate samples (for
  `SPLOOPW`), and a cycle limit as arguments. A fourth argument supplies the
  initial `ILC` for a `SPLOOPW` trace or the first pending-interrupt cycle for a
  counted trace. A fifth argument supplies the `SPLOOPW` pending-interrupt cycle.
  Append `restart` after the interrupt argument to trace return with saved
  `SPLX=1`.
  For example,
  `C6000LoopReplay.java 0xC00036A4 2 128` traces 48 cycles of the stage 2
  loop at that address. `C6000LoopModelTest.java` checks all decoded loop
  bodies in an imported image.

  The scheduler reports operation order and loop-control state; it does not
  execute each instruction's p-code or model instruction latency, pipeline
  writeback and handler entry, nested reload, or choose the post-body
  program-memory packet after branches. Restart of masked `BNOP`/`ADDKPC`
  idle-cycle operations is rejected until their special timing is modelled.
  [The loop conformance notes](docs/software-loop-conformance.md) specify
  the remaining emulator state. Native Ghidra decompilation still displays
  the loop-control userops, because the hardware buffer does not correspond
  to an ordinary control-flow edge.
* **Predication** is decoded, displayed and guards the modelled 32-bit p-code.
  Compact predication and packet-wide parallel effects need further work.
* The generic corpus is assembled from GNU binutils, whose tic6x assembler
  covers less of the ISA than the manual; it is a regression oracle, not a
  completeness proof.

## Repository layout

```
build.gradle, settings.gradle, extension.properties, Module.manifest
data/languages/          c6000.sinc (framework), c6000_decode.sinc (generated),
                         c6000_manual.sinc, c6000_compact.sinc, c6000_memory.sinc,
                         c6000_semantics.sinc,
                         c6000_placeholders.sinc (generated), ldefs/pspec/cspec/opinion
ghidra_scripts/          C6000CorpusTest.java, C6000SoftwareLoopTest.java,
                         C6000LoopReplay.java, C6000LoopModelTest.java
src/main/java/c6000/     C6000PacketContext.java, C6000PacketAnalyzer.java,
                         C6000SoftwareLoops.java, C6000SoftwareLoopAnalyzer.java,
                         C6000LoopBuffer.java
tools/                   build.sh, gen_decode.py, gen_memory.py, build_encodings.py,
                         oracle_compare.py, gen_fid.py
.github/workflows/       build.yml
```

`c6000_decode.sinc` and `c6000_placeholders.sinc` are generated by
`tools/gen_decode.py` from an encoding table parsed out of SPRUFE8B §3.12
(`tools/build_encodings.py`); `c6000_memory.sinc` comes from
`tools/gen_memory.py`. They are committed so the extension builds without the
manual; edit their generators rather than the generated files.

## Licence

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE.md`](NOTICE.md).
