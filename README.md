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
| 32-bit instruction decode (mnemonic, unit, operands, length) | broad SPRUFE8B §3.12 coverage, legacy `MVC`, and C64x+ linked-word `LL`/`SL`/`CMTL`; no nonfill gaps in the measured stage 2 payload or the stage 1 code region |
| Instruction lengths and execute-packet framing | 2/4-byte lengths and compact layout context; execute packets are not atomic |
| Branch / call targets (`B`, `BNOP`, `CALLP`, `BDEC`, `BPOS`) | modelled in the RAM address space, PCE1-relative per the manual; delayed `B` + `ADDKPC` calls and `B`/`BNOP` returns through B3 recovered by analyzers |
| Compact 16-bit fetch packets | most observed slots decode, driven by packet-header context (see below) |
| P-code semantics | integer ALU and common multiplies, compact saturating arithmetic, immediates, bit-field operations, linear and AMR circular address arithmetic, scalar and doubleword loads/stores, single-precision arithmetic and conversions, selected double-precision arithmetic and conversions, compares, shifts, branches/calls, `MVC` |
| Other decoded instructions | no generated `c6000_unimpl_<mnemonic>` calls remain; software-loop controls, `IDLE`, and C64x+ linked-word operations use named event userops; `DINT`/`RINT` update `TSR` and `CSR` interrupt-enable bits |
| Function ID | generation script shipped; database not shipped (TI licence) |
| Software loop controls | decoded and annotated; a separate cycle scheduler replays buffered packets and stage-boundary `ILC` changes, including predicate-driven `SPLOOPW` |
| Architecture-wide fidelity | not yet established by firmware coverage; packet timing, selected floating-point status, and exact reciprocal seeds need further verification |

The generator uses **explicit, greppable placeholders** if an instruction
lacks semantics. None remain in the generated table. `C6000CorpusTest.java`
counts placeholder occurrences in a firmware image; zero observed occurrences
alone would not establish architecture-wide fidelity.

`IDLE` emits a `c6000_idle` event for a cycle-aware scheduler to handle. Ghidra's
instruction emulator does not itself suspend until an interrupt. The
`interrupt-control.py` fixture and `C6000InterruptControlTest.java` verify the
`DINT`/`RINT` register transitions, nested sequence, and `IDLE` event in both
endian modes.

## Measured coverage

Command used for every row (see [Testing](#testing)):

```
C6000CorpusTest.java stage1   # or stage2
```

| Corpus (first 12,288 / 131,072 bytes) | Bytes decoded | Instructions | Compact 16-bit | Headers | Unimplemented p-code | Undecoded slots | Byte coverage |
|---|---:|---:|---:|---:|---:|---:|---:|
| CDJ-2000NXS stage 1, base `0x11801da0` | 11,328 | 3,179 | 694 | 162 | 0 | 240 | **92.2%** |
| CDJ-2000NXS stage 2, base `0xC0000000` | 131,072 | 36,605 | 7,674 | 2,214 | 0 | 0 | **100%** |

Full-payload linear sweeps also completed with no zero-width p-code operands:

| Corpus | Payload bytes | Bytes decoded | Instructions | Unimplemented p-code | Undecoded slots | Byte coverage |
|---|---:|---:|---:|---:|---:|---:|
| Stage 1 | 55,120 | 39,580 | 10,265 | 0 | 3,885 | **71.8%** |
| Stage 2 | 361,248 | 336,000 | 91,490 | 0 | 6,312 | **93.0%** |

The sweeps found 24 paired software loops and 43 buffer masks in stage 1,
and 224 paired loops and 470 buffer masks in stage 2. No detected loop
boundary was left unmatched. The loop schedule parsed and replayed all 24
stage 1 loops and all 224 stage 2 loops, with no body decode gaps.
The loop-control userops are counted separately from unimplemented instruction
placeholders.

`CPKT` headers decode as named 4-byte rows. The 328 undecoded slots in the
stage 1 code region (through `0x11805aff`) and all 6,312 in the full stage 2
payload are `0xffffffff` fill. The full stage 1 payload has 2,695 nonfill
undecoded 4-byte slots, first at `0x11805b04`, in its pointer and constant
tables. Forty-four of these had previously been mistaken for `CPKT` headers
outside the eighth word of a fetch packet. The corpus test reports nonfill
undecoded slots separately. Byte coverage is a
linear sweep of the stated windows or payloads, not a claim that every byte is
code. The full stage 1 image in particular contains substantial fill/data;
some repeating table bytes resemble compact instructions, so full-image
instruction counts are not a measure of executable-code coverage.
The full-payload sweeps first use `-noanalysis` for decode and p-code coverage.
With register-branch correction scheduled before decompiler-driven analysis,
autoanalysis after a full stage 2 sweep also completes: the formerly merged
function at `0xc001dd80` is 16 bytes in one range, and Ghidra's Stack analyzer
finishes. A linear sweep still attempts to decode data and fill as code; its
error bookmarks are not executable-code coverage failures.

The final full-payload operand audit compares the rendered operands of 770
stage 1 code instructions and 22,657 stage 2 instructions with GNU tic6x;
both have zero mismatches. It compares only forms with directly equivalent
spelling, excluding branch-target notation, memory syntax, known aliases, and
immediate-display conventions. The mnemonic/unit/length audit compares 3,835
stage 1 code instructions and 90,946 stage 2 instructions with zero unexplained
differences. These measurements show no undecoded instruction in the observed
firmware code, but they do not prove that every architectural encoding or
instruction behavior is correct.

`tests/fixtures/circular-addressing.py <image.bin> <cases.tsv> [be]` and
`C6000CircularAddressTest.java <cases.tsv>` execute 14 cases per endian mode.
They check BK0/BK1 wraparound, underflow, pre/post updates, noneligible base
registers, a full-width BK0 field, and byte/halfword store truncation. The register
forms of ADDAB/ADDAH/ADDAW/ADDAD and SUBAB/SUBAH/SUBAW use the local `.D`
source register, as the opcode map specifies.
`tests/fixtures/nonalign-circular.py <image.bin> <cases.tsv> [be]` and
`C6000NonalignedCircularTest.java <cases.tsv>` execute six cases per endian
mode. They verify that `LDNW`/`LDNDW` and `STNW`/`STNDW` wrap every transferred
byte across a circular-buffer edge and remain linear when AMR is disabled or
the base register cannot use circular addressing.

`tests/fixtures/float-dp-arithmetic.py <image.bin> <add.tsv> <mul.tsv> [be]`
generates exact-rational `ADDDP`/`SUBDP`/`MPYDP` results and FADCR/FMCR flags.
`C6000FloatAddTest.java <add.tsv>` and
`C6000FloatMultiplyTest.java <mul.tsv>` exercise 840 add/subtract and 640
multiply cases per endian mode, including `MPYSPDP`, all four rounding modes,
reversed `SUBDP` forms, special values, and widely separated operands.
`tests/fixtures/subdp-cross.py <image.bin> <cases.tsv> [be]` and
`C6000FloatAddTest.java <cases.tsv>` check the cross-path `SUBDP.L` operand
order and arithmetic on both register sides. `tests/fixtures/sshl.py
<image.bin> <cases.tsv> [be]` and `C6000SatArithmeticTest.java <cases.tsv>`
check register and immediate `SSHL.S`, including CSR.SAT, in both endian modes.

The stage images are **not** in this repository. The test accepts an external
image path and base address, so private firmware can be measured without being
committed; regenerate the images with
`tools/cdj_dsp_image.py` from the CDJ-2000NXS research project and point
`C6000CorpusTest.java` at them.

Compact decode is driven by the packet header through the `noflow` context
fields described below. The 32-bit table covers the documented opcode maps;
the compact table covers appendices C.4, D.4, E.4, F.4, G.3 and H.4. No
undecoded nonfill slots remain in the measured firmware code regions, although
architecture-wide compact encoding coverage is not established. SPRUFE8B's figure D-6
(`Ltbd`) has blank field cells and no instruction description to resolve it.

The generic, redistributable half of the corpus is generated at test time from
GNU binutils (`as -march=c674x` / `objdump -m tic6x`) and cross-checked against
this module by `tools/oracle_compare.py`; nothing built by TI or by binutils is
committed. An independent GNU disassembly of the firmware code regions agrees
with this decoder on 3,835 stage 1 code-region and 90,946 full-payload stage 2 instruction addresses,
lengths, mnemonics and functional units. There are no GNU-only instructions,
Ghidra-only non-NOP instructions, length mismatches or unexplained mnemonic/unit
differences. The comparison records 86 and 5,798 known naming differences,
respectively, and GNU elides some NOPs. It does not check operands or semantics.
That comparison exposed 1,582 stage 2 `MVKH` words previously displayed as
`MVK.L`; the decoder now constrains the high-half bit and uses the `.S` unit.

`tests/fixtures/mvkh.py <image.bin> <cases.tsv> [be]` and
`C6000MvkhTest.java <cases.tsv>` check the `.S1`/`.S2` encodings, high-half
writes, retained low half, predication and the contrasting `MVK` low constant
in both endian modes.

`tests/fixtures/sub-reverse.py <image.bin> <cases.tsv> [be]` and
`C6000ReverseSubTest.java <cases.tsv>` check six local and cross-path
reverse-operand `SUB.S1/S2` cases per endian, including predication. The
encoding's `x` bit selects either source register bank.
`tests/fixtures/long-shifts.py <image.bin> <cases.tsv> [be]` and
`C6000LongShiftTest.java <cases.tsv>` check twelve 40-bit `SHL`/`SHR`/`SHRU`
forms and three rejected pair encodings per endian. The pair shifts use the
low 40 bits, clear the high register's upper 24 bits, and sign-extend bit 39
for arithmetic right shifts.

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

`tests/fixtures/compact-header-collision.py <image.bin> [be]` and
`C6000CompactHeaderTest.java` verify that an E-prefixed word outside the header
position stays undefined, while a compact word containing an E-prefixed upper
halfword still decodes as two 16-bit instructions. Both endian variants pass.

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
`C6000PackedArithmeticTest.java <cases.tsv>` execute 140 packed arithmetic,
comparison, average, saturating multiply, min/max, byte merge, and pack cases
per endian mode. They cover cross-path sources, signed/unsigned lane boundaries,
the signed and mixed-sign high/low halfword multiplies, signed and unsigned
dot products (including rounded variants), saturating 8/16-bit lane arithmetic,
and
`SPACK2`/`SPACKU4` clamping without changing `CSR.SAT`.

`tests/fixtures/mpy2.py <image.bin> <cases.tsv> [be]` and
`C6000Mpy2Test.java <cases.tsv>` execute four signed packed multiplication
cases per endian mode. They verify that the two 32-bit products go to the
correct halves of a 64-bit destination pair. The same script executes four
`MPYHI` cases per endian mode from `tests/fixtures/mpyhi.py`, checking a
signed upper-halfword times signed 32-bit product in a register pair. Four
`DOTP2` pair cases from `tests/fixtures/dotp2-pair.py` cover the full-width
signed dot product, including the positive `0x80000000` boundary. Four
`SMPY2` cases from `tests/fixtures/smpy2.py` cover both 32-bit products in a
pair and `CSR.SAT` when either lane saturates.
Four `MPYSU4`/`MPYU4` cases from `tests/fixtures/packed-byte-mul.py` check all
four 16-bit products in a 64-bit pair, including signed byte boundaries.
Four `DDOTP4` cases from `tests/fixtures/ddotp4.py` check both signed
halfword-by-byte dot products and their placement in a 64-bit pair.
`tests/fixtures/ddot-pair.py <image.bin> <cases.tsv> [be]` and
`C6000PairAluTest.java <cases.tsv>` execute 12 `DDOTPH2`/`DDOTPL2` cases,
including the rounded `R` forms, per endian mode. They check source-pair
selection, cross-path input, saturation, and the `CSR.SAT`/`SSR.M1`/`SSR.M2`
effects against TI's worked examples.
Five `CMPY` cases from `tests/fixtures/cmpy.py` check the signed complex
products, pair result, and M-unit saturation flags in both endian modes.
Eight `CMPYR`/`CMPYR1` cases from `tests/fixtures/cmpyr.py` check rounding,
packing, and M-unit saturation against every TI worked example in both
endian modes.
Eight `MPYSPDP`/`MPYSP2DP` cases from
`tests/fixtures/mixed-float-mpy.py` check mixed-precision sources,
cross-path register pairs, and double-precision outputs in both endian modes.
Five `GMPY4` cases from `tests/fixtures/gmpy4.py` check TI's default
polynomial examples and changed `GFPGFR` polynomial/field-size settings in
both endian modes.

`tests/fixtures/paired-alu.py <image.bin> <cases.tsv> [be]` and
`C6000PairAluTest.java <cases.tsv>` execute 13 `ADDSUB`, `ADDSUB2`, `SADDSUB`,
`SADDSUB2`, `DMV`, and `UNPKLU4` cases per endian mode. They check pair
destination order, cross-path sources, signed and lane saturation, and
`CSR.SAT`/`SSR.L1`/`SSR.L2` effects.

`tests/fixtures/mpyid.py <image.bin> <cases.tsv> [be]` and
`C6000MpyidTest.java <cases.tsv>` check four signed 32-by-32 multiplication
cases per endian mode. They cover 64-bit register-pair results, a cross-path
source, and signed five-bit constants.
`tests/fixtures/rounded-mpy.py <image.bin> <cases.tsv> [be]` and
`C6000RoundedMultiplyTest.java <cases.tsv>` check eight `MPYHIR`/`MPYLIR`
cases per endian mode, including TI's worked examples, cross-path operands,
signed boundaries and the `0x4000` rounding bias.

`tests/fixtures/arithmetic-forms.py`, `compare-forms.py`, and
`mvc-control.py` with their matching `C6000*Test.java` scripts check signed
and unsigned 40-bit ADD/SUB/compare forms, operand ports, and the direction
and high address bits of 32-bit `MVC` control-register encodings in both
endian modes. The rounded multiply test displays the encoded `MPYLIR` name
and source order; `MPYILR` is its reversed-operand assembler pseudo-op.

`tests/fixtures/pair-unary.py` and `C6000PairUnaryTest.java` check scalar
`ABS` saturation and 40-bit `ABS`/`NEG`/`MV` operand pairs, upper-bit masking,
and invalid odd-pair or cross-path forms in both endian modes.
`tests/fixtures/linked-word.py` and `C6000LinkedWordTest.java` check the
C64x+ `LL`/`SL`/`CMTL` encodings and linked-memory event p-code.

`tests/fixtures/sat-arith.py <image.bin> <cases.tsv> [be]` and
`C6000SatArithmeticTest.java <cases.tsv>` execute 15 `SADD` and `SSUB` cases
per endian mode. They cover 32-bit and 40-bit saturation, signed constants,
register-pair results, and both `src1` and `src2` cross paths.

`tests/fixtures/packed-shifts.py <image.bin> <cases.tsv> [be]` and
`tests/fixtures/variable-shifts.py <image.bin> <cases.tsv> [be]` run through
`C6000PackedShiftTest.java <cases.tsv>`. The 12 `SHR2`/`SHRU2` and 14
`SSHVL`/`SSHVR` cases per endian mode check immediate and register counts,
cross-path sources, counts beyond 15/31, signed direction changes, saturation,
and `CSR.SAT`.
Seven `XPND2`/`XPND4` cases from `tests/fixtures/xpnd.py` use the same script
to check bit-to-halfword and bit-to-byte mask expansion.

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
  the per-slot context (`c_is16`, `c_isheader`, `c_rs`, `c_dsz`, `c_sat`, `c_br`, `c_prot`, `c_pfollow`)
  for every compact packet.
* `c6000.C6000PacketContext.prime(program, monitor)` is the same logic as a
  static helper, so scripts and headless runs can call it directly; the corpus
  test does exactly that.
* With no context primed, every word decodes as a normal 32-bit instruction — a
  graceful fallback rather than a hard failure.

Only the eighth word of a compact fetch packet decodes as a 4-byte `CPKT`
instruction. The `1110` prefix in bits 31..28 is the reserved predication
encoding `creg=7, z=0` (Table 3-9), so no valid 32-bit instruction matches it.

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
  manual's Execution blocks specify. Direct branch and call targets export in
  RAM, so Ghidra's flow references and disassembler follow the code address.
  The delayed-call analyzer recognizes a `B` followed by `ADDKPC` writing `B3`
  within five execute packets and classifies the branch as a call. A separate
  early analyzer classifies branches through the ABI return register `B3` as
  returns before Ghidra's switch analysis. Unpredicated `B`/`BNOP` register
  branches retain conservative fall-through during code discovery; an analyzer
  redecodes them as terminal branches or returns before Decompiler Switch
  Analysis so the decompiler sees their actual control flow.

The `branch-flow.py` fixture and `C6000FlowTargetTest.java` check seven direct
branch/call forms in both endian modes, including conditional versus
unconditional flow types. Ten stage 2 firmware branch/call sites, including
compact forms, also passed the RAM flow check. On a fresh stage 1 raw import
with entry `0x11801da0`, auto-analysis found functions at `0x11804280`,
`0x118048a0`, and `0x11804360`, with zero `const:` flow-error bookmarks. A raw
binary needs an entry point; `C6000SetEntry.java` supplies it for headless
tests. The packet-context analyzer runs before Ghidra's entry-point
disassembler so compact target slots get their width context in time. A fresh
stage 2 import also created a function at the checked `CALLP` target
`0xc0012720`. The return-flow regression checks 450 stage 2 `B3` branches,
including 24 predicated returns that retain their fall-through edge; no
unpredicated return retains a fall-through edge.

Ghidra's generic Basic Constant Reference Analyzer can exhaust the heap while
exploring the stage 2 control-flow graph. The C6000-specific analyzer bounds
each propagation walk to 512 bytes, still recovering nearby register-built
targets. A fresh stage 2 raw import with the default analyzers recovered 144
functions with zero `const:` flow-error bookmarks; a 60-second-per-function
audit decompiled all 144. In a separate full-payload sweep followed by
autoanalysis, Decompiler Switch Analysis took about 53 seconds and Stack took
about 4 seconds. The reported `0xc001dd80` merger did not recur.

### Floating-point decompilation

The default `C6000:LE:32:default` and `C6000:BE:32:default` languages retain
the detailed floating-point rounding and status-register model. For reading
float-heavy functions, explicitly select `C6000:LE:32:analysis` or
`C6000:BE:32:analysis` when importing a program. This variant uses native
single-precision p-code for `INTSP`, `INTSPU`, `MPYSP`, `ADDSP`, `SUBSP`, and
the SP comparisons. It represents status-register effects with the opaque
`c6000_fp_status` userop, so its flag values and special rounding cases are
not suitable for emulation. The same stage 2 function at `0xc0008c44`
decompiled to 36 lines with the analysis language versus 219 with the exact
language; the `fVar1 < 1.0` branch was visible in the shorter output.

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

`tools/oracle_compare.py` diffs that listing against `objdump -m tic6x` and
checks addresses, lengths, names and functional units. It caught the `MVKH`
decode bug described above. Note that
`objdump -b binary -m tic6x` needs `--endian=little` and an input of at least
32 bytes.

`tools/sample_encodings.py scratch/sample.bin` makes a reproducible sample of
32,768 unpredicated 32-bit words for the same comparison workflow. The sample
includes illegal encodings. It exposed the reverse `SUB.S`, long-shift,
ADD/SUB/compare port, `MVC` control-register, and long `ABS`/`NEG`/`MV`
operand-form bugs. `tools/audit_random_oracle.py IMAGE BASE LISTING` classifies
disagreements against TI's opcode and operand tables. In an additional
131,072-word sample, 378 GNU-only decodes violate those constraints; four
Ghidra-only words use an `x` bit exposed by TI's `MVK`/`NORM` diagrams, and
one `SPMASK` word violates its execute-packet placement rule. No disagreement
in that sample remains unexplained. These samples do not prove exhaustive ISA
coverage.

`tools/sample_encodings.py scratch/predicated.bin 32768 0xC674 --predicated`
samples valid conditional predicate encodings. Its GNU comparison had no
unexplained difference among 25,367 mutually decoded words. The compact
counterpart, `tools/sample_compact_encodings.py <image.bin> [header_expansion]`,
places every 16-bit value in a header-based packet. Sweeps across all eight
`DSZ` values with `BR=SAT=RS=0`, plus an all-ones expansion field, each had
91,552 mutually decoded rows and no mnemonic, functional-unit or length
mismatches. `tools/audit_compact_oracle.py IMAGE BASE LISTING` reports zero
unexplained disagreements for each sweep. GNU also decoded eight `MVC .S1`
forms whose `s=0` violates SPRUFE8B Figure F-31's `s=1` constraint; it left
64 `SPKERNEL` rows undefined in each synthetic image. The first compact sweep
exposed and verified the `CPKT` slot collision fixed above.

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
* **Some architecture encodings may remain uncovered.** The measured stage 2
  payload and stage 1 code region have no undecoded nonfill slots, but those
  images are not an exhaustive encoding test. The decoder leaves unknown words
  undefined instead of guessing an instruction.
* **Execute packets are not modelled as units** — see above.
* **C64x+ linked-word operations need a memory monitor.** `LL` and `SL`
  expose their CPU-visible load/store plus named link events. `CMTL` returns
  its monitor-provided success value through a userop. Ghidra's instruction
  emulator cannot decide another core's link state by itself.
* **No delay-slot modelling** in p-code.
* **Constant propagation is bounded to 512-byte windows.** This prevents the
  observed stage 2 heap exhaustion and recovers the three checked stage 1
  register-built call targets, but a value carried only across a longer span
  may not produce a computed reference automatically.
* **Misaligned aligned-word loads are outside the documented input domain.**
  SPRUFE8B requires `LDW` addresses to be word aligned. Its p-code clears
  the low two address bits so a propagated misaligned address cannot make
  Ghidra's decompiler construct an invalid four-byte RAM range. Emulator
  behavior for an actual misaligned `LDW` remains to be established.
* **AMR updates are instruction-level.** `.D` effective addresses and
  ADDA/SUBA results wrap for A4-A7/B4-B7, including BK0/BK1 selection and
  bytewise wrapping of nonaligned transfers. Base writes occur after the
  memory transfer so a store using the same register for its source and base
  reads the old value. Packet timing for writes to AMR still needs a
  cycle-aware execution model.
* **Floating-point fidelity remains incomplete.** Some arithmetic still lacks
  status-register side effects. `SPDP` and `DPSP` model their documented
  special values and status flags; `DPSP` also uses the FADCR rounding mode.
  `MPYSP2DP` handles signed special values and FMCR warning bits. `MPYSP`
  uses the same input handling and rounds its result using FMCR. `MPYSPDP`
  handles mixed-width special values and rounds its DP product using FMCR.
  `ADDSP` and
  `SUBSP` use FADCR rounding and warning bits, including the reversed `SUBSP`
  opcodes and both `.L` and `.S` unit forms. `ADDDP` and `SUBDP` use FADCR;
  `MPYDP` uses FMCR. Their finite arithmetic uses a quad-precision intermediate
  to preserve DP rounding, and their status flags include denormal, NaN,
  invalid, inexact, overflow, and underflow. `INTSP` and `INTSPU` also use
  FADCR rounding and set INEX for rounded integer conversions.
  The reciprocal estimate
  instructions implement TI's special cases and FAUCR flags, and return an
  eight-bit-accurate seed. TI does not publish the seed lookup table, so ordinary
  estimates are not yet proven bit-exact against hardware. `MVC` uses
  distinct control registers in its 32-bit forms; the compact `MVC` to `ILC`
  is also modelled.
* **SWE/SWENR exception transitions are instruction-level models.** For SWE,
  `NRP = inst_next` is exact when SWE ends its execute packet. A packet-aware
  executor is needed when SWE runs in parallel with NOP, and simultaneous
  exception priority is not represented in p-code.
* **RPACK2 documentation differs from its example:** the published execution
  rule and compiler guide specify a saturating left shift, which yields
  `0xFDB9` for the upper halfword of the sample `0xFEDCBA98`; the worked
  example prints `0xFDBA`. The implementation follows the stated operation.
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
