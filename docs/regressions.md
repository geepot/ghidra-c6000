# Synthetic regression fixtures

Run the [release verification suite](verification.md#reproducing-release-verification)
for the curated checks, or use the generator and Ghidra script pairs below for focused
work. Unless stated otherwise, generate with `IMAGE CASES.tsv [be]`, import at `0x1000`
in the corresponding default C6000 language, and pass the manifest to the test script.
Run both endian modes. Counts describe each fixture's declared cases, not a new release
measurement.

For packet timing, see [exact schedules](pipeline-schedules.md),
[post-loop dispatch](post-loop-dispatch.md),
[closed direct-call traces](closed-call-traces.md) and
[caller continuations](caller-continuation-traces.md). Their refusal checks are part of
the contract.

## Flow references and ownership

`C6000SwitchOwnershipTest.java` runs after `C6000JumpTableTest.java` on the existing
`tests/fixtures/jump-table.py` image. Run both with little- and big-endian languages.
Six checks cover stable override label IDs on repeat analysis, lossless rehoming,
retention when a branch has no function owner, idempotence, preservation of mismatching
manual cases, and detached duplicates when the correct owner already has a table. The
test checks that repairs do not change instructions, flow or function bodies.

`tests/fixtures/constant-branch-target.py IMAGE CASES.tsv [be]` and
`C6000ConstantBranchTargetTest.java` check adjacent `MVK` /`MVKH` branch-target
references. Run the script before auto-analysis with `prepare CASES.tsv`, then after
analysis with `check CASES.tsv`. Four cases require exactly the constructed address;
four ensure that predicated high-half writes, same-execute-packet writes, alternate
entries and non-word-aligned target values do not get over-filtered. Run with both
`C6000:LE:32:default` and `C6000:BE:32:default`. Expected values come from SPRUFE8B's
MVK/MVKL and MVKH descriptions (pp. 381, 383-385) and branch pipeline Table 4-11, not
from observed disassembler output.

## Memory and arithmetic

`tests/fixtures/circular-addressing.py <image.bin> <cases.tsv> [be]` and
`C6000CircularAddressTest.java <cases.tsv>` execute 14 cases per endian mode. They check
BK0/BK1 wraparound, underflow, pre/post updates, noneligible base registers, a
full-width BK0 field, and byte/halfword store truncation. The register forms of
ADDAB/ADDAH/ADDAW/ADDAD and SUBAB/SUBAH/SUBAW use the local `.D` source register, as the
opcode map specifies. `tests/fixtures/nonalign-circular.py <image.bin> <cases.tsv> [be]`
and `C6000NonalignedCircularTest.java <cases.tsv>` execute six cases per endian mode.
They verify that `LDNW` /`LDNDW` and `STNW` /`STNDW` wrap every transferred byte across
a circular-buffer edge and remain linear when AMR is disabled or the base register
cannot use circular addressing.

`tests/fixtures/float-dp-arithmetic.py <image.bin> <add.tsv> <mul.tsv> [be]` generates
exact-rational `ADDDP` /`SUBDP`/`MPYDP` results and FADCR/FMCR flags.
`C6000FloatAddTest.java <add.tsv>` and `C6000FloatMultiplyTest.java <mul.tsv>` exercise
840 add/subtract and 640 multiply cases per endian mode, including `MPYSPDP`, all four
rounding modes, reversed `SUBDP` forms, special values, and widely separated operands.
`tests/fixtures/subdp-cross.py <image.bin> <cases.tsv> [be]` and
`C6000FloatAddTest.java <cases.tsv>` check the cross-path `SUBDP.L` operand order and
arithmetic on both register sides. tests/fixtures/sshl.py
<image.bin> <cases.tsv> [be]` and `C6000SatArithmeticTest.java <cases.tsv>`
check register and immediate `SSHL.S`, including CSR.SAT, in both endian modes.

## Scalar decode and compact operands

`tests/fixtures/mvkh.py <image.bin> <cases.tsv> [be]` and
`C6000MvkhTest.java <cases.tsv>` check the `.S1` /`.S2` encodings, high-half writes,
retained low half, predication and the contrasting `MVK` low constant in both endian
modes.

`tests/fixtures/sub-reverse.py <image.bin> <cases.tsv> [be]` and
`C6000ReverseSubTest.java <cases.tsv>` check six local and cross-path reverse-operand
`SUB.S1/S2` cases per endian, including predication. The encoding's `x` bit selects
either source register bank.
`tests/fixtures/long-shifts.py <image.bin> <cases.tsv> [be]` and
`C6000LongShiftTest.java <cases.tsv>` check twelve 40-bit `SHL` /`SHR`/`SHRU` forms and
three rejected pair encodings per endian. The pair shifts use the low 40 bits, clear the
high register's upper 24 bits, and sign-extend bit 39 for arithmetic right shifts.

`tests/fixtures/compact-move-memory.py IMAGE CASES.tsv [be]` and
`C6000CompactMoveMemoryTest.java CASES.tsv` check 1,792 cases per endian. They sweep
every explicit five-bit register value of LSDmvto/LSDmvfr across both RS values,
register sides, cross paths and .L/.S/.D units. Guarded aligned/nonaligned doubleword
cases distinguish unscaled offset/indirect addresses from scaled increment/decrement
updates (SPRUFE8B G-1/G-2 and C-9/C-11/C-13/C-15). All other registers and adjacent
memory bytes are checked.

`tests/fixtures/compact-operands.py IMAGE CASES.tsv [be]` and
`C6000CompactOperandsTest.java CASES.tsv` check 558 cases per endian mode. They cover
every compact Dstk offset with both data files, both register sets and loads/stores,
including operand order and guarded memory effects; post-increment
byte/halfword/word/doubleword accesses and pointer updates; guarded byte/halfword stores
through offset, indirect and predecrement forms; three-operand compact ADD/XOR displays;
and every signed five-bit .L/.D MVK constant with predication edge cases. Expected
fields and effects follow SPRUFE8B Figures C-8/C-10/C-12/C-13/C-14/C-16/G-4, MVK pp.
380-381, and the STB/STH descriptions. The fixture contains synthetic encodings only and
runs without firmware or an external assembler.

Compact saturation regression fixtures are generated by
`tests/fixtures/compact-saturation.py <image.bin> <cases.tsv> [be]` and executed with
`C6000CompactSaturationTest.java <cases.tsv>` after importing the raw image at `0x1000`
with the matching C6000 language. The 23 cases per endian cover SADD/SSUB overflow, four
SMPY halfword selections, SSHL saturation and count boundaries, compact forms whose SAT
header bit is ignored, and S-unit formats with the BR header bit set. The processor spec
declares a synthetic `PC` for Ghidra's emulator; architectural `PCE1` remains a separate
control register. P-code updates `CSR.SAT` as an instruction effect; cycle-accurate
placement of that write belongs to a pipeline model.

`tests/fixtures/compact-header-collision.py <image.bin> [be]` and
`C6000CompactHeaderTest.java` verify that an E-prefixed word outside the header position
stays undefined, while a compact word containing an E-prefixed upper halfword still
decodes as two 16-bit instructions. Run both endian variants.

## Integer and floating-point execution

`tests/fixtures/long-arith.py <image.bin> [be]` and `C6000LongArithmeticTest.java` check
both endian variants of 32-bit `NORM` and `SUBU`. The seven cases include the 40-bit
register-pair forms, sign boundaries, and a negative 40-bit subtraction result.

`tests/fixtures/exact-fp-selection.py <image.bin> <cases.tsv> [be]` and
`C6000ExactFloatSelectionTest.java <cases.tsv>` execute 14,688 default-language SP
arithmetic cases per endian mode. An exact-rational oracle checks ADDSP, SUBSP and
MPYSP, all four rounding modes, destination/source aliases and unconditional, true and
false predicates (including inverted predicates). Source registers, the other status
register and sticky status bits are checked. The script also rejects opaque arithmetic
userops and more than the single architectural predicate branch per instruction. Run
with `-noanalysis` after raw import at `0x1000` using the matching `C6000:LE:32:default`
or BE language. The `float-addsub-sp.py` / `C6000FloatAddTest.java`, `mpysp.py` and
`mpysp2dp.py` / `C6000FloatMultiplyTest.java`, and `dpsp.py` and `int-to-sp.py` /
`C6000ConvertStatusTest.java` suites cover the other consumers of these shared helpers,
including cross paths and register-pair results.

`tests/fixtures/fp-int.py <image.bin> <cases.tsv> [be]` and
`C6000FpConvertTest.java <cases.tsv>` check `SPINT` and `SPTRUNC` in both endian modes.
The 23 cases per mode cover all FADCR rounding modes, ties to even, signed overflow,
NaN, infinity, denormals, and the separate `.L1` /`.L2` warning bits.

`tests/fixtures/dp-int.py <image.bin> <cases.tsv> [be]` and
`C6000DpConvertTest.java <cases.tsv>` check `DPINT` and `DPTRUNC` with register-pair
sources. The 23 cases per mode cover rounding, exceptions, warning bits, signed 32-bit
result limits, and both pair encodings for `DPINT`, `DPTRUNC`, and `DPSP`. The odd/high
register in `src2` selects the 64-bit pair. TI's assembler sets `src1` to zero, whereas
older GNU tic6x assemblers encoded the even/low register there. The decoder accepts both
variants; see
[binutils gas/15094](https://lists.gnu.org/archive/html/bug-binutils/2013-02/msg00037.html).

`tests/fixtures/packed-arith.py <image.bin> <cases.tsv> [be]` and
`C6000PackedArithmeticTest.java <cases.tsv>` execute 140 packed arithmetic, comparison,
average, saturating multiply, min/max, byte merge, and pack cases per endian mode. They
cover cross-path sources, signed/unsigned lane boundaries, the signed and mixed-sign
high/low halfword multiplies, signed and unsigned dot products (including rounded
variants), saturating 8/16-bit lane arithmetic, and `SPACK2` /`SPACKU4` clamping without
changing `CSR.SAT`.

`tests/fixtures/mpy2.py <image.bin> <cases.tsv> [be]` and
`C6000Mpy2Test.java <cases.tsv>` execute four signed packed multiplication cases per
endian mode. They verify that the two 32-bit products go to the correct halves of a
64-bit destination pair. The same script executes four `MPYHI` cases per endian mode
from `tests/fixtures/mpyhi.py`, checking a signed upper-halfword times signed 32-bit
product in a register pair. Four `DOTP2` pair cases from `tests/fixtures/dotp2-pair.py`
cover the full-width signed dot product, including the positive `0x80000000` boundary.
Four `SMPY2` cases from `tests/fixtures/smpy2.py` cover both 32-bit products in a pair
and `CSR.SAT` when either lane saturates. Four `MPYSU4` /`MPYU4` cases from
`tests/fixtures/packed-byte-mul.py` check all four 16-bit products in a 64-bit pair,
including signed byte boundaries. Four `DDOTP4` cases from `tests/fixtures/ddotp4.py`
check both signed halfword-by-byte dot products and their placement in a 64-bit pair.
`tests/fixtures/ddot-pair.py <image.bin> <cases.tsv> [be]` and
`C6000PairAluTest.java <cases.tsv>` execute 12 `DDOTPH2` /`DDOTPL2` cases, including the
rounded `R` forms, per endian mode. They check source-pair selection, cross-path input,
saturation, and the `CSR.SAT` /`SSR.M1`/`SSR.M2` effects against TI's worked examples.
Five `CMPY` cases from `tests/fixtures/cmpy.py` check the signed complex products, pair
result, and M-unit saturation flags in both endian modes. Eight `CMPYR` /`CMPYR1` cases
from `tests/fixtures/cmpyr.py` check rounding, packing, and M-unit saturation against
every TI worked example in both endian modes. Eight `MPYSPDP` /`MPYSP2DP` cases from
`tests/fixtures/mixed-float-mpy.py` check mixed-precision sources, cross-path register
pairs, and double-precision outputs in both endian modes. Five `GMPY4` cases from
`tests/fixtures/gmpy4.py` check TI's default polynomial examples and changed `GFPGFR`
polynomial/field-size settings in both endian modes.

`tests/fixtures/paired-alu.py <image.bin> <cases.tsv> [be]` and
`C6000PairAluTest.java <cases.tsv>` execute 13 `ADDSUB`, `ADDSUB2`, `SADDSUB`,
`SADDSUB2`, `DMV`, and `UNPKLU4` cases per endian mode. They check pair destination
order, cross-path sources, signed and lane saturation, and `CSR.SAT` /`SSR.L1`/`SSR.L2`
effects.

`tests/fixtures/mpyid.py <image.bin> <cases.tsv> [be]` and
`C6000MpyidTest.java <cases.tsv>` check four signed 32-by-32 multiplication cases per
endian mode. They cover 64-bit register-pair results, a cross-path source, and signed
five-bit constants. `tests/fixtures/rounded-mpy.py <image.bin> <cases.tsv> [be]` and
`C6000RoundedMultiplyTest.java <cases.tsv>` check eight `MPYHIR` /`MPYLIR` cases per
endian mode, including TI's worked examples, cross-path operands, signed boundaries and
the `0x4000` rounding bias.

`tests/fixtures/arithmetic-forms.py`, `compare-forms.py`, and `mvc-control.py` with
their matching `C6000*Test.java` scripts check signed and unsigned 40-bit
ADD/SUB/compare forms, operand ports, and the direction and high address bits of 32-bit
`MVC` control-register encodings in both endian modes. The rounded multiply test
displays the encoded `MPYLIR` name and source order; `MPYILR` is its reversed-operand
assembler pseudo-op.

`tests/fixtures/pair-unary.py` and `C6000PairUnaryTest.java` check scalar `ABS`
saturation and 40-bit `ABS` /`NEG`/`MV` operand pairs, upper-bit masking, and invalid
odd-pair or cross-path forms in both endian modes. `tests/fixtures/linked-word.py` and
`C6000LinkedWordTest.java` check the C64x+ `LL` /`SL`/`CMTL` encodings and linked-memory
event p-code.

`tests/fixtures/sat-arith.py <image.bin> <cases.tsv> [be]` and
`C6000SatArithmeticTest.java <cases.tsv>` execute 15 `SADD` and `SSUB` cases per endian
mode. They cover 32-bit and 40-bit saturation, signed constants, register-pair results,
and both `src1` and `src2` cross paths.

`tests/fixtures/packed-shifts.py <image.bin> <cases.tsv> [be]` and
`tests/fixtures/variable-shifts.py <image.bin> <cases.tsv> [be]` run through
`C6000PackedShiftTest.java <cases.tsv>`. The 12 `SHR2` /`SHRU2` and 14 `SSHVL` /`SSHVR`
cases per endian mode check immediate and register counts, cross-path sources, counts
beyond 15/31, signed direction changes, saturation, and `CSR.SAT`. Seven `XPND2`
/`XPND4` cases from `tests/fixtures/xpnd.py` use the same script to check
bit-to-halfword and bit-to-byte mask expansion.

## Regenerating decode tables

The generated 32-bit decode table can be rebuilt from the public TI PDF: run
`pdftotext -layout sprufe8b.pdf /tmp/c6000ref/sprufe8b.txt`, then
`python3 tools/build_encodings.py /tmp/c6000ref/sprufe8b.txt` and
`python3 tools/gen_decode.py`. The intermediate `.research/` tables are gitignored.
`tools/build_encodings.py` expands the manual's grouped `LDB(U)` and `LDH(U)` headings
into distinct signed and unsigned opcodes; the generator rejects unconstrained opcode
fields so a malformed parse cannot create a broad, false decode pattern.

## Proven delay-window regression

`return-delay.py IMAGE CASES.tsv [be]` and `C6000ReturnDelayTest.java CASES.tsv` check
17 synthetic return/interrupt windows: parallel stores, scalar delay stores, multi-cycle
NOPs, BNOP counts, target sampling, RINT, mixed widths and crossed fetch headers and
PROT-load NOP cycles. Expected byte windows and guard stores are independent of
recovery. The native listing p-code is executed, tail effects must precede transfer, and
each recovered function must decompile within 15 seconds. Instruction stepping is also
checked for the uniform 32-bit cases. The test preserves all five comment classes, label
IDs and user references, including on initially undefined tail bytes, and requires
idempotence.

`C6000DelaySafetyTest.java` refuses nested control transfers, defined data and another
function's entry, and an oversized execute packet, predicated PROT loads, IDLE and
conflicting multicycle NOP generators (seven refusal cases).
`packet-call.py IMAGE CASES.tsv [be]` and `C6000PacketCallTest.java CASES.tsv` check six
CALLP cases across both link registers, including mixed-width companions that read the
old link. Run all three scripts in both endian modes. Reuse direct-flow,
predicated-register, delayed-call and switch-ownership fixtures as dependent checks. Raw
auto-analysis fixtures require `C6000SetEntry.java 1000` as a pre-script.

Regenerate `c6000_flow_delay.sinc` with `python3 tools/gen_flow_delay.py`;
`gen_decode.py` and `gen_compact.py` own their corresponding branch constructors. The
generated delay choices cover at most 254 bytes. Longer or unsupported windows remain
outside native delay recovery.

## Encoding identity and updating-load phases

`tests/fixtures/full32-encoding-info.py <image.bin> <cases.tsv> [be]` and
`C6000Full32EncodingInfoTest.java <cases.tsv>` check 110 synthetic cases per endian in
the default language, including 96 emulated scalar moves/zeros. They distinguish ADD/OR
move primitives and cross paths, exercise both predicate outcomes and inversion,
preserve all three status registers, retain equal-source SUB and 40-bit MV, and
distinguish identical-spelling address forms. Metadata checks cover ordinary/header
full32 branch scaling, including a header with zero layout and BR bits. Run after raw
import at 0x1000 with `-noanalysis`; the script primes packet context explicitly.

`pipeline-load-alias.py IMAGE CASES.json [be]` and
`C6000PipelineLoadAliasTest.java CASES.json` check 19 cases per endian: 16
native/scheduled executions and three simultaneous-write refusals. They cover pre/post
updates, aliased base/index/pair words, circular and nonaligned access, compact loads
and captured predicates.

`pipeline-caller-continuation.py` and `C6000CallerContinuationTest.java` cover 21 closed
trace contracts per endian, with six executions, 15 refusals and six wrong-entry-B3
refusals. See [trace contracts](caller-continuation-traces.md).

## Additional decoder accuracy checks

The release runner includes compact stack offsets (`compact-dstk`), unscaled
NDW offsets (`compact-ndw`), low comparison destinations (`compact-cmpdst`), and
NOP counts (`nop-count`). These retain independent checks for fixes already in
language 1.1. `compact-cross` verifies the `X` functional-unit suffix across the
compact D/L/M/S formats, while the existing move/memory and comparison sweeps
also check the corrected spellings.

`long-arith` executes both SUBU cross-operand forms. `gmpy4` assembles an
unconditional opcode and executes five polynomial/field-size examples.
`word-shifts` executes register counts 0, 1, 31, 32, 63, 64, 65 and
`0xffffffc1`, plus immediate controls, for SHL/SHR/SHRU. `dp-int` includes
DPSP INEX on rounding. All run in both byte orders.
