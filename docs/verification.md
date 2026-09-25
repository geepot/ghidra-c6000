# Verification and measured coverage

How the decoder and p-code are checked, and what the measurements do and do
not show. Firmware images are never committed; every firmware measurement
below was taken against privately extracted images passed in by path.

The generator uses **explicit, greppable placeholders** if an instruction
lacks semantics. None remain in the generated table. `C6000CorpusTest.java`
counts placeholder occurrences in a firmware image; zero observed occurrences
alone would not establish architecture-wide fidelity.

`IDLE` emits a `c6000_idle` event for a cycle-aware scheduler to handle. Ghidra's
instruction emulator does not itself suspend until an interrupt. The
`interrupt-control.py` fixture and `C6000InterruptControlTest.java` verify the
`DINT`/`RINT` register transitions, nested sequence, and `IDLE` event in both
endian modes.

## Importing the CDJ-2000NXS DSP payloads

Extract the two payloads from the decompressed MAIN image using your own
firmware tooling. Import each as a **Raw Binary** with the
`C6000:LE:32:default` language and `default` compiler specification. Use
these DSP execution addresses rather than the addresses of the payloads
inside MAIN or the stage-2 staging window:

| Payload | Load base | Analysis entry |
|---|---:|---:|
| stage 1 | `0x11801da0` | `0x11801da0` |
| stage 2 | `0xc0000000` | `0xc0000220` (after the vector table) |

Add the analysis entry before auto-analysis. In headless Ghidra, run
`-preScript C6000SetEntry.java <entry>`; in the GUI, navigate to the entry
address and run `C6000SetEntry.java` from Script Manager.

## Firmware coverage

Command used for every row (see [below](#running-the-corpus-test-and-oracles)):

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
committed; extract the code images from the firmware with your own tooling
and point `C6000CorpusTest.java` at them.

Compact decode is driven by the packet header through the `noflow` context
fields described in [internals](internals.md#compact-16-bit-fetch-packets). The 32-bit table covers the documented opcode maps;
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

## Running the corpus test and oracles

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
exposed the `CPKT` slot collision that `C6000CompactHeaderTest.java` now covers.
