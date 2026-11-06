# Synthetic regression fixtures

Run the [release verification suite](verification.md#reproducing-release-verification)
for the curated checks, or use the generator and Ghidra script pairs below for focused
work. Unless stated otherwise, generate with `IMAGE CASES.tsv [be]`, import at `0x1000`
in the corresponding default C6000 language, and pass the manifest to the test script.
Run both endian modes. Counts describe each fixture's declared cases, not a new release
measurement.

For packet timing, see [exact schedules](pipeline-schedules.md),
[post-loop dispatch](post-loop-dispatch.md),
[closed-call traces](closed-call-traces.md) and
[caller continuations](caller-continuation-traces.md). Their refusal checks are part of
the contract.

## Flow references and ownership

`tests/fixtures/delayed-call-timing.py IMAGE CASES.json [be]` and
`C6000DelayedCallTimingTest.java prepare|check CASES.json` cover 235 independent
cases per language and byte order for issues #23, #24 and #30. The release runner
executes all four language variants through normal auto-analysis. Tests cover
E5 B3 clobbers after ADDKPC, preceding and same-packet loads, pair/base aliases,
all six predicate registers and both polarities, predicate writes across E5,
local/cross-path register targets, writer order, compact slots, fetch boundaries
and protected loads. `cl6x`-encoded `MPY32`, `ADDSP`, `MPYI`, `LL` and `CMTL` B3 writers
beside the B and one to four cycles before it check that each result lands after its
delay slots, including after the callee is entered; a not-taken `BNOP` beside a target
load, and one between a B3 load and the B with N = 0 to 5, check its idle cycles. A null row target
means the call is proved but its register target is not. Read-only recognition must agree with native call references
and function creation; false calls preserve return data, including untyped words.
Two additional analyzer passes check stable references and no spurious target
functions (SPRUFE8B 3.5, 3.6, 3.10.2.2, Tables 4-6/4-10/4-11).

`tests/fixtures/closed-call.py IMAGE CASES.json [be]` and
`C6000ClosedCallTraceTest.java CASES.json RESULTS.json` cover 48 contracts per endian
(14 executed schedules and 34 refusals). Split MVK/MVKH targets and links,
B5/B3/cross-path calls, target overwrites, callee branches and an internal counter loop
are checked alongside ownership, physical layout and late effects. Early correct links
now execute, including ADDKPC with four inserted NOPs; wrong link identities still
refuse.

`tests/fixtures/pipeline-calls.py IMAGE CASES.json [be]` and
`C6000PipelineCallsTest.java CASES.json RESULTS.json` cover 55 checks per endian
(35 executed schedules and 20 refusals). Execution covers full32/compact CALLP on both
S units, both RS settings, peers before/after CALLP, next-packet links across headers,
repeated and distinct callees, and saved return links in A0. Store observations check
captured pending effects and maturity before a second callee can mask the first store.
Unsafe unknown/conditional/late/clobbered links, nonlocal returns, simultaneous link
writers, pending branches and conflicting NOP generators remain refusals. The four
previously documented capability gaps now have execution checks. See the
[production round-trip](multi-call-roundtrip.md).

`tests/fixtures/pipeline-call-contracts.py IMAGE CASES.json [be]` and
`C6000PipelineCallContractTest.java CASES.json RESULTS.json` check six normal
closed-call activations and fourteen refusals per endian. The installed injection
library and stock native decompiler receive pending-store traces for both S units,
compact/header forms and repeated/distinct helpers. The fixture executes the injected
p-code, checks the returned C, preserves separate owners/references/comments, and
checks idempotence, persisted plan/hazard round trips and review/record/analyzer
activation. Stale source/plan/ownership/selector changes and alternate interior entries
refuse; incomplete, cancelled and unsafe activations leave no options or binding.

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

`tests/fixtures/elf-local-label.py IMAGE [be]` writes a TI-style ELF whose code labels
are local, size-0 `STT_FUNC` symbols, as `cl6x` emits them. Import it with `ElfLoader`
and auto-analysis (no base address or entry script), then run
`C6000ElfLocalLabelTest.java`. It checks that the jump to `$C$L1` keeps a plain jump
flow with no override, and that `$C$L1`, `$C$RL1` and `$C$RL2` keep their names inside
the containing function instead of starting functions. `$C$RL3`, which no flow reaches,
must still be decoded and must not start a function. Four local, size-0 `STT_FUNC` controls stay functions under their
names: the static function `h` (hidden, as `cl6x` emits it), the far-call trampoline
`$Tramp$S$$g` (as the TI linker emits it, SPRAB89 §5.3.2), and the near-miss names
`$C$L` and `$C$L1a`. The calls to `g` and to `$C$L2` keep their call references, and
the called label `$C$L2` is a function. Run with both languages.

`tests/fixtures/elf-compact.py IMAGE [be]` writes `cl6x` compact fetch packets into the
same kind of ELF, with a non-allocated `.TI.section.flags` section that Ghidra loads as
an `OTHER` overlay (issue #33). Import it with `ElfLoader` and auto-analysis, then run
`C6000ElfCompactTest.java`: every compact slot must decode in `dis6x` order with no
error bookmarks and `q1`, `f2` and `f3` must be functions, in both byte orders
(issue #31).

`tests/fixtures/upgrade-v1.py IMAGE [be]` copies a packed program of the same ELF saved
with the version 1 languages (`tests/fixtures/data/`). Import it with Ghidra's GZF loader
and run `C6000ElfCompactTest.java upgraded`: the big-endian program must migrate to
language version 2 through `C6000BeDefaultLanguageTranslator` and decode in `dis6x`
order; the little-endian one stays at version 1.

Hand-built fixtures list compact slots in execution order, one halfword per address.
`tests/fixtures/compact_order.py` rewrites their big-endian images so each compact
word's first slot is its 16 LSBs, as the hardware stores it.

`tests/fixtures/register-branch-tail.py IMAGE [be]` holds the `B B3`, `B B5` and
`BNOP B3,5` shapes of issue #32 with data after each delay window. Run
`C6000RegisterBranchTailTest.java prepare` as a pre-script (it marks the three entries
as functions) and `check` after auto-analysis: no function body holds anything past a
delay window, the delay slots are decoded, and neither later entry lies inside another
function.

`tests/fixtures/delay-window-forms.py IMAGE [be]` is the `cl6x` repro of issue #34: a
`B` call whose slots load its arguments and return link, and a predicated `B` whose
slots run on both paths. `C6000DelayWindowFormsTest.java prepare` marks the two entries;
`check` requires 20- and 12-byte `c_flow_delay` windows, the call's fallthrough at its
return point, and decompiled C that passes `2` to the callee and adds 5 on both paths.

## Memory and arithmetic

`tests/fixtures/pipeline-resources.py IMAGE CASES.json [be]` and
`C6000PipelineResourcesTest.java CASES.json` check 244 cases per language and
byte order: 148 executed schedules and 96 refusals. The release runner exercises
all four timing variants. Refusals cover all eight functional units, all six
predicate registers, complementary and proven-false guards, and LDW/STW transfer
path conflicts. Controls execute legal packets using separate units or T1/T2,
including complementary writes to one destination on different units. Compact
C674x memory forms exercise both RS selections; testing them under C67x timing
profiles does not establish C67x ISA legality. Every executed case checks all GPRs,
the return address and guarded memory words. Refused activations must leave context,
review metadata and the modification number unchanged (SPRUFE8B 3.6/3.8.1/3.8.5;
SPRU733A 3.6/3.7.1/3.7.4).

`tests/fixtures/pipeline-c67x.py IMAGE CASES.json [be]` and
`C6000PipelineCpuTest.java CASES.json` execute 15 cases per language and byte
order. The release runner imports the same bytes with `default`, `analysis`,
`c67x` and `c67x-analysis`. Hand-counted pipeline advances, stall edges and
register values cover both cross paths, enabled/disabled E1 writers, incoming
hazards, local reads, E1 updating-load bases, E5 load destinations, a pending load during a stall and
an E2 DP cross-port read. The AMR case retains its separate stall. A normal
injection, native decompilation, a review with the wrong language ID, and the
analysis-language conversion script exercise profile binding. Conversion preserves
the CPU family, is idempotent, and refuses to reuse the old language's review
(SPRU198K 6.3.2.2; SPRUFE8B 3.8.4).

`tests/fixtures/pipeline-bnop.py IMAGE CASES.json [be]` and
`C6000PipelineBnopTest.java CASES.json` check 118 schedules per endian.
The 28 fixed-five Sbu8/Sbu8c cases retain their literal display without a
scalar operand. Variable counts 0-5, both register sides, both RS selections,
both predicate polarities, zero/nonzero predicates, backward displacements,
BR-independent compact register targets and full-width register targets
provide controls. Displacement schedules take 15 hand-counted cycles; register
returns take seven. Each completes an
E5 load during the branch window, returns to B3 and checks that fallthrough
guards execute only for false predicates (SPRUFE8B 4.2.5-4.2.6 and Figures
F-17/F-18/F-20/F-21/F-32). The TI-assisted `caller-tail.py` /
`C6000CallerTailTest.java` fixture additionally checks fixed-five entry
evidence on both S units and rejects wrong idle counts and stale hazards.

`tests/fixtures/pipeline-andn.py IMAGE CASES.json [be]` and
`C6000PipelineAndnTest.java CASES.json` exercise 234 cases per endian mode:
228 native/scheduled checks and six functional-unit collision refusals.
All six `.L`/`.S`/`.D` units cover both cross paths, destination/source
aliases, both predicate polarities with zero/nonzero values, parallel source
and predicate writers, and consumers before and after E1 writeback. CSR and
AMR remain unchanged. Opcode fields, expected results and the single-cycle
contract follow SPRUFE8B pp. 145-146. This is a core release regression.

`tests/fixtures/compact-memory.py IMAGE CASES.json [be]` and
`C6000CompactMemoryTest.java CASES.json` execute 960 native instruction checks
and 960 exact-schedule checks per endian mode. They cover compact offset,
indirect, post-increment and pre-decrement loads/stores for byte, halfword,
word, doubleword and nonaligned word/doubleword transfers, including signed
and unsigned loads. Linear, BK0 and BK1 cases exercise all four eligible
pointers on both register sides, both data files and both RS selections.
The 192 overlapping cases include stores whose source is the updated pointer
and doubleword transfers whose even or odd data register is the pointer.
Scheduled observers check the E1 pointer before E5 load writeback and the data
after E5. All GPRs, AMR, CSR, the captured return target and guarded memory
bytes are checked. Nonaligned accesses wrap each byte independently across
the buffer edge (SPRUFE8B 2.8.3, 3.9.2, 4.2.5-4.2.6 and Figures C-8..C-15).
This fixture is part of the core release suite and requires no external image
or assembler.

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

`tests/fixtures/compact-predicated-mvk.py IMAGE CASES.json [be]` and
`C6000CompactPredicatedMvkTest.java CASES.json` cover all four Figure G-3 predicate
forms, both constants, .L/.S/.D units, both data register files and both header RS
values. The 120 synthetic encodings include writes to the predicate itself. Each
runs with predicate values zero, one and `0xffffffff`, checking 360 raw instruction
executions and 360 exact-schedule executions per endian mode. Disabled writes must
preserve the destination; enabled writes must install the constant, with unrelated
predicates, register-bank shadows and CSR preserved. Scheduled functions must return
to the captured B3 target. This fixture is part of the core release suite and needs
neither firmware nor TI's assembler.

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
sources. The 20 cases per mode cover rounding, exceptions, warning bits, signed 32-bit
result limits, and nonzero pairs for `DPINT`, `DPTRUNC`, and `DPSP`. TI `cl6x` 8.3.15
and GNU `as` 2.47 encode the pair's odd register in `src2` and its even/low register in
`src1`, the port that reads the low word; see
[binutils gas/15094](https://lists.gnu.org/archive/html/bug-binutils/2013-02/msg00037.html).

`tests/fixtures/dp-convert-src1.py <image.bin> <cases.tsv> [be]` and
`C6000DpConvertSourceTest.java <cases.tsv>` check that this form decodes and executes on
the named pair, and that every other `src1`, `x = 1` and an even `src2` stay undefined.
No assembler emits `src1 = 0` with another pair (as the opcode diagram shows) or an even
`src2`, and for those words `dis6x` names the pair from `src1` where GNU uses `src2`;
`dis6x` leaves any odd `src1` undefined.

`tests/fixtures/unary-dp-src1.py <image.bin> <cases.tsv> [be]` and
`C6000UnaryDpSourceTest.java <cases.tsv>` check `ABSDP`, `RCPDP` and `RSQRDP` source
pairs in both endian modes. TI `cl6x` 8.3.15 and GNU `as` 2.47 encode the pair's odd
register in `src2` and its low register in `src1`, the port that reads the low word, and
the decoder accepts that form. It also keeps the even-`src2`, `src1` = 0 form that main
already decoded as `src2`+1:`src2`, for compatibility only: no assembler emits it, the
Picarro image has none, and by the same port split it would read its low word from A0 or
B0. Every other `src1` and `x = 1` stay undefined. `dis6x` names the pair from `src2`
whatever `src1` holds and ignores `x`, but for an odd `src1` it shows `RCPDP` as `ADD`
and leaves `RSQRDP` undefined; GNU decodes any `src1` and rejects `x = 1`. Both halves
are read in E1 and a cross path carries one 32-bit operand per cycle (SPRUFE8B 2.4).
Each accepted form runs on the named pair and must match the even form's result and
FAUCR, plain, under `[A1]` and `[!A1]` (the skipped run must leave both untouched), and
with a flag-setting SNaN; reserved `creg` 7 stays undefined.

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

`tests/fixtures/mvc-tscl.py <image.bin> <cases.tsv> [be]` runs `C6000MvcControlTest.java`
on the `cl6x` 8.3.15 and GNU `as` 2.47 encodings of `MVC` to and from `TSCL`/`TSCH` in
both endian modes. The test interprets each plain, cross-path or predicated write and
read for both predicate values: its userop must run exactly when the predicate holds,
and no other register may be read or written. `.S1`, x=1 read, nonzero-crhi and `TSCH`
write forms stay undefined.

`tests/fixtures/pair-unary.py` and `C6000PairUnaryTest.java` check scalar `ABS`
saturation and 40-bit `ABS` /`NEG`/`MV` operand pairs, upper-bit masking, and invalid
odd-pair or cross-path forms in both endian modes. `tests/fixtures/linked-word.py` and
`C6000LinkedWordTest.java` check the C64x+ `LL` /`SL`/`CMTL` encodings and linked-memory
event p-code.

`tests/fixtures/reserved-predicate.py <image.bin> <cases.tsv> [be]` and
`C6000ReservedPredicateTest.java <cases.tsv>` decode 15 cases per endian mode in the
release suite. Unconditional-only `SMPY32` and `RPACK2` use the reserved `creg=0, z=1`
encoding (SPRUFE8B Table 3-9) and must not be shadowed by their predicated twins `MPY32US`
and `DMV`, which are decoded unpredicated and under several predicates. The shadowing only
shows with an even destination, which the twin's register pair can also encode, so the
cases use even and odd destinations. The seven `SMPY32`/`RPACK2` cases reuse values from
`remaining-arith.py` and also execute, checking the result, `CSR.SAT` and `SSR`.

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

## Delayed-call predicate facts

`delayed-call.py IMAGE [be]` and `C6000DelayedCallTest.java` (with
`C6000SetEntry.java 1000`) check ten sites in nine routines at 0x1d00-0x2100 for the compiler's
if/else-call predicate rewrite. `cl6x` 8.3.15 (`-mv6740 --abi=eabi -O2`) emits this
for one of our own tests (unrelated parallel instructions omitted):

```
   [!A0]   B       .S2     $C$L31
||         MV      .L1     A0,A1             ; guard predicate rewrite
   [ A0]   CALL    .S1     f1
|| [!A0]   CMPGT   .L1     A10,10,A0
   [ A1]   MVK     .L1     1,A0              ; nullify predicate
   [!A0]   BNOP            $C$L32,2
           ADDKPC  .S2     $C$RL134,B3,0
```

On the call path A0 is nonzero. The parallel `[!A0] CMPGT` reads its guard at E1 with
the call and does not run, and `[A1] MVK 1,A0` writes 1 or nothing, so A0 stays nonzero
whatever A1 holds. The `[!A0] BNOP` is never taken and `ADDKPC` sets B3 in the call's
last delay slot (SPRUFE8B 3.5, 3.6, 3.12 MVK/BNOP/ADDKPC, 4.2.6). Ghidra marks a
branch's parallel followers with the `_` delay-slot prefix; the predicate proof must
read their guard through it. 1d08 is this routine, 1f08 the same with the write under
A2, and 1d88 the `[!A0]` form, where `[!A1] ZERO A0` keeps A0 zero. 1e14 is the
opposite case: `[!A0] CALL || [A0] ZERO A0`, then `[!A1] ZERO A0` and `[A0] B`. Either
`ZERO` would clear A0, so on the `B`'s taken path neither ran and the `CALL` was not
taken; the two form an if/else pair and the near arm, 1e14, is the jump, not a call at
the `CALL`'s return. The controls 1e88 and 1f88 put `[A1] ZERO A0` and `[A2] ZERO A0`
under an `[A0]` call. Either can clear A0 on the call path, so the `BNOP` may be taken
and neither is a call.

`dis6x` also lists `SUB A0,A0,A0` as `ZERO A0` (SPRUFE8B 3.12 SUB, ZERO): 2008 is 1d88
with that form, a call, and 2088 the control with `SUB A0,A2,A0`, which can set A0 on
the call path. 210c checks the backward step: B3 is set under `[A0]` before an
unconditional `MVK 1,A0`, and A0 being true at the call says nothing about its value
when B3 was written, so 210c is not a call.

The independent `delayed-call-safety.py` / `C6000DelayedCallSafetyTest.java` fixture
also checks native `_[predicate]` followers through both the read-only recognizer
and the analyzer. Thirty-six cases vary all six predicate registers, both senses,
and matching/skipped/unknown guards on a parallel B3 low-half writer. Nine more
cover guarded ADDKPC links, high-half replacements and register-copy clobbers.
A skipped or unknown write cannot supply a return link; a skipped copy must retain
an already known link. Each case requires the actual native delay-slot prefix so a
plain instruction cannot accidentally stand in for the regression. Together with
its existing controls, this fixture checks 72 cases per endian (24 accepted and
48 refused). These follow SPRUFE8B 3.5, 3.6 and 4.2.6.

## Calls returning to earlier caller code (issue #41)

`idle-call.py IMAGE [be]` and `C6000IdleCallTest.java` (with `prepare` as a pre-script,
which declares the twelve functions) check twelve `B` sites in `cl6x` 8.3.15 words. A `B`
to another function's entry whose delay slots set B3 to earlier code of the same
function is a call that returns there, as in `for (;;) run(*tbl);`. 1004 (B3 is the
caller's entry), 1028 (a mid-function label) and 109c (B3 set in the slots of the jump
into it) must be calls with their whole window in the caller. B3 untouched (1044) or
still the previous call's link (10d4) stays a tail call, B3 naming another function
(1064) or a local target (1084, #11's shape) is not a call, and a predicated `B` (10e8)
keeps its not-taken path (SPRUFE8B 4.2.6, B).

A register `B` (1148) stays a jump with its native window: under a CALL override a
register branch gets no window, so a return to 1140 would skip the argument load at 114c.
With its target already a reference (1208; the test adds it, as a resolved computed
branch's would be) it is still not a call returning to 1200. CALLP (1164) and BNOP 5
(1180) leave no delay slots, so B3 written after them is fresh and 1168 and 118c are
calls (SPRUFE8B 3.12, BNOP and CALLP).

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

## ADDDP/SUBDP upper-word read timing (issue #20)

Both lower source words are sampled in E1 and both upper words in E2, before
that cycle's writes (SPRUFE8B Table 4-16; SPRU733A Table 4-12). This applies
to both displayed source operands, including reversed .S SUBDP encodings.
The correction leaves result write phases and raw arithmetic unchanged.

`pipeline-dp-read-timing.py` supplies independent cases for parallel E1 writers,
preceding E2 multiply writeback, preceding E5 load writeback, writes after the
read boundary, low-word snapshots, destination aliases, captured predicates,
and cross-path read stalls in both endian modes. `C6000PipelineDpTest.java`
executes the schedules, checks bit-exact arithmetic/status results and stall
counts, and decompiles selected reviewed schedules through the native engine.

## Packet context beside ELF overlays (issue #33)

The ELF loader adds initialized overlay blocks over OTHER for sections such as
`.TI.section.flags`. Rounding one of them out to a fetch packet left the overlay
space, so the packet analyzer gave up on the whole program and compact code in
`.text` stayed undecoded. Only loaded memory spaces are primed now.
`C6000PacketScopeTest.java` reuses the `compact-dstk` image, adds such an
overlay, runs the packet analyzer over every initialized byte as auto-analysis
does, and checks each compact slot decodes. It runs in both byte orders.
