# Internals

How the module models the parts of the C6000 that do not map directly onto SLEIGH:
compact fetch packets, execute packets, delay slots and branch targets, plus the ABI,
the analysis language variants and the source layout.

## Languages

| Language | Use |
|---|---|
| `C6000:LE:32:default` | little-endian C674x / C64x+ / C64x cross-path timing, shared superset decode |
| `C6000:BE:32:default` | big-endian variant (C6000 supports both byte orders) |
| `C6000:LE:32:analysis`, `C6000:BE:32:analysis` | same decode, simplified single-precision p-code for reading float-heavy code (see [below](#floating-point-decompilation)) |
| `C6000:LE:32:c67x`, `C6000:BE:32:c67x` | C67x / C67x+ cross-path timing with exact floating-point p-code |
| `C6000:LE:32:c67x-analysis`, `C6000:BE:32:c67x-analysis` | C67x / C67x+ cross-path timing with concise floating-point p-code |

An ELF loader opinion maps `EM_TI_C6000` (e_machine 140) to `C6000:LE:32:default`, so a
little-endian C6000 ELF picks it automatically. The opinion only matches little-endian
files; for a big-endian ELF or a raw binary, choose the language and (for raw images)
the base address yourself.

The TI assembler gives every label in a code section a size-0 `STT_FUNC` symbol,
local unless the label is declared global, so Ghidra's ELF loader starts a function at
each one. Shared-return analysis then marks every jump to such a label as a tail call,
although B and BNOP only load the PC (SPRUFE8B §3.12). `c6000.C6000_ElfExtension`
loads the compiler's branch and return labels (`$C$L<n>`, `$C$RL<n>`) as code labels.
Other labels have the same symbol type, size and binding as a C static function, so the
extension records them and `c6000.C6000LocalLabelAnalyzer` (`C6000 Local Code Labels`)
removes such a function once reached code falls into its entry or a conditional branch
reaches it, provided nothing calls it. Its name stays as a label and the function that
reaches it is refit. Entries nothing reaches (an address-taken static) and targets of only
an unconditional `B` (possibly a tail call) stay functions; see
[limitations](limitations.md#decode-and-analysis).

C674x is the union of the C64x+ and C67x+ instruction sets (SPRUFE8B §1.1), so one
description serves the older parts, which are subsets. C67x/C67x+ imports must
explicitly select a `c67x` variant to omit C64x cross-path stalls in opted-in exact
schedules. The eight language definitions share four compiled SLEIGH files; the
variants do not filter per-device instruction legality. See
[processor timing selection](pipeline-schedules.md#processor-timing-selection).

## Native CodeBrowser plugin

`C6000Plugin` is a released `ProgramPlugin` with native program-context actions and
a dockable `C6000Provider`. `C6000ScheduleDialog` previews explicit entry contracts;
`C6000ProgramActions` calls the shared compiler/review APIs, native disassembly and
function commands, and analysis workers. It does not invoke scripts. Program
listeners are detached on activation changes and disposal; queued tasks retain a
consumer for the target program until completion. See the [native tools guide](native-ui.md).

## Compact 16-bit fetch packets

A fetch packet is eight 32-bit words (32 bytes). It is a **compact** packet exactly when
bits 31–28 of its eighth word are `1110`; that word is then a *header* rather than an
instruction, its layout field says which of the other words hold two 16-bit
instructions, and its expansion field supplies the register set (`RS`), LD/ST data size
(`DSZ`), saturation (`SAT`) and branch-mode (`BR`) parameters that a 16-bit opcode
cannot express (§3.10.2).

The header sits **after** the instructions it describes. SLEIGH fixes an instruction's
length from the tokens it matches, so a constructor that peeked at word 7 would have to
declare every compact instruction 32 bytes long. The decode context is therefore primed
out of band:

* `c6000.C6000PacketAnalyzer` runs before Ghidra's disassembly pass and writes
  the per-slot context (`c_is16`, `c_isheader`, `c_rs`, `c_dsz`, `c_sat`, `c_br`, `c_prot`, `c_pfollow`)
  for every compact packet.
* `c6000.C6000PacketContext.prime(program, monitor)` is the same logic as a
  static helper, so scripts and headless runs can call it directly; the corpus
  test does exactly that.
* Tools that bypass auto-analysis must prime context before decoding compact
  slots; treating them as independent full32 words does not recover the header
  parameters.

A word's first compact instruction is its 16 LSBs in either byte order (SPRUFE8B
3.10.2.3, Table 3-16). In big-endian memory that halfword is at byte offset +2, and the
second instruction is before the slot that executes it, where SLEIGH cannot read. The
big-endian languages therefore widen `contextreg` to 64 bits and add `c_h16`, which the
primer sets to each compact slot's halfword. `tools/gen_compact_context.py` mirrors every
`insn16` field onto `c_h16`, and a 16-bit pad token keeps each compact instruction two
bytes long. Little-endian languages keep the `insn16` token (issue #31). Java readers use
`C6000PacketContext.halfword`.

Since language version 3 in both byte orders, `contextreg` is 128 bits and each field has
the same position in both. Bits 0-23 hold the decode and recovery fields and big-endian
bits 32-47 hold `c_h16`; bits 24-31 and 48-62 hold the packet staging fields and bits
63-122 the latched-branch fields (landing displacements are 20 bits). Bits 123-127 are unused: big-endian Ghidra fails to load
a language with a context field that reaches into them. New fields are `noflow` with a
`c_` prefix, unless they really must flow.

Only the eighth word of a compact fetch packet decodes as a 4-byte `CPKT` instruction.
The `1110` prefix in bits 31..28 is the reserved predication encoding `creg=7, z=0`
(Table 3-9), so no valid 32-bit instruction matches it.

## Execute packets, delay slots and parallel semantics

Bit 0 of a full32 opcode is its p-bit. Compact instructions take their p-bits from bits
13–0 of the fetch-packet header. A set p-bit chains the following instruction into the
same execute packet, including across fetch boundaries.

Default lifting handles instructions individually. A reader may therefore see a parallel
writer's value too early, and ordinary result latencies are not scheduled. Supported
functions can instead use an explicitly enabled
[exact packet schedule](pipeline-schedules.md), with a proved entry contract.

### Native delay windows

`C6000DelaySlots` proves finite `B` /`BNOP` windows, including IRP/NRP
forms. It accounts for execute cycles, implied BNOP cycles, multicycle NOP/ADDKPC,
protected loads and crossed compact headers. The physical byte count is stored in
`c_flow_delay`; `tools/gen_flow_delay.py` generates the constant `delayslot(n)` choices
because SLEIGH counts delay bytes, rather than instructions.

Targets and predicates are captured before delay work. Native parsing is checked before
listing changes; recovery preserves comments, symbols, references and
explicit fallthrough overrides. Re-decoding a window never polls the task monitor, so a
cancel lands between windows. A window whose rewrite fails part-way is put back as it was
(instructions, decode context, annotations) before the failure propagates. Recovery and
release never end their transactions uncommitted: in Ghidra an uncommitted nested
transaction aborts the enclosing auto-analysis transaction. Nested transfers, defined data and conflicting function
ownership prevent recovery. Predicated displacement `B`/`BNOP` and displacement and register `B`
calls, predicated or not, are recovered, and so is a `CALL_RETURN` tail call when nothing in
its packet or window writes B3 except a load and the delayed-call proof finds no return
address in B3; a call's fallthrough moves to the next execute packet after its window.
A jump whose target is only NOPs that fill the remaining delay cycles of a return
issued in the jump's window, taken whenever the jump is, is continued: a
`JUMP_OVERRIDE_UNCONDITIONAL` reference sends its branch to its own fall-through and the
edge to the NOPs is dropped, so no jump enters the delay slots of the return that owns them.
The jump is continued only once the return's window is proven to end where the jump lands
on every path and that window is laid, and an analysis override whose condition no longer
holds is removed. When issue #52's release takes the return's window, the jump gets its edge back.
Predicated register jumps and returns get their whole window too (issue #70); a return's
cut window that no continued jump supports any more is released if the whole window is
not proven. BDEC/BPOS retain conservative native treatment. Exact scheduling handles its own
supported branch phases.

CALLP supplies five implied idle cycles. Its parallel companions execute before the
side-specific A3/B3 link is written; the next execute packet is the return point.
Ghidra's generic delay-depth counter can apply the branch's compact context to its
followers, so the late pass corrects fallthrough using the proved physical window.
Mixed-width stock-emulator stepping remains limited; listing p-code and decompilation
use address-specific context.

Native p-code lifts an execute packet's members one after another, but every member reads
its operands before any member writes (SPRUFE8B 3.5). `C6000SamePacketHazardAnalyzer`
(`C6000 Same-Packet Hazards`) bookmarks each member that reads a register an earlier
member writes, and puts one `WARNING: C6000 same-packet hazard` line in the function's
header comment, replacing its own line on each pass. A branch reads only its target and
predicate; its p-code holds its window. Two members that both read-modify-write a control
register only OR in sticky flags (CSR SAT, FADCR/FAUCR/FMCR), which commute, so that pair
is not warned, and neither is a pair under opposite predicates on one register that the
writer leaves alone, since at most one of them executes. Functions with an active
reviewed schedule are skipped (issue #71).

### Branch targets

C6000 direct transfers are PCE1-relative: the base is the start of the containing
32-byte fetch packet, `inst_start & 0xFFFFFFE0`. This applies to B, CALLP, BNOP, BDEC,
BPOS and ADDKPC. Full32 BNOP displacement counts words in ordinary packets and halfwords
in header-based packets. The primed `c_hdrpkt` context selects that scale. Targets are
exported in RAM so Ghidra can follow them as code references.

### Latched branches

`C6000NestedLiftAnalyzer` takes each branch the nested-window comparison would warn about
and asks `Walker.liftPlan` for a lifting of its stretch: every transfer from where nothing
is in flight to the end of the windows issued there is latched, and lands behind the last
instruction that issues, in address order, before its sixth cycle. `Walker.liftMismatch`
runs the same hardware model as the warning against that lifting, for every consistent
outcome of the predicates; only a match is applied. `C6000DelaySlots.relift` decodes the
stretch again as straight-line code with the fields set: `c_inert_wrap`, `c_inert` and
`c_latch_t` on a branch select a form of the instruction that writes `C6000_LATCH_T<n>`
(and `C6000_LATCH_PC<n>` for a register target) and holds no transfer. Those forms are
generated from the ordinary `B` and `BNOP` constructors, 32-bit (`tools/gen_latched.py`)
and compact (`tools/gen_compact.py`); the ordinary ones require `c_inert_wrap=0`, because
SLEIGH does not prefer the more specific of two matching patterns. Eight latches are
reused as branches land; `c_land1`/`c_land2`
with a kind, a latch and a displacement on the landing instruction append a conditional
jump, call or return. A landing clears its latch, the latches are zero at every function
entry (`c6000.pspec`) and unaffected by calls (`c6000.cspec`), so an instruction can carry
a landing that only some paths use: `liftPlan` runs the hardware model for every outcome
and adds a landing wherever a branch lands outside its own stretch, in the code an earlier
taken branch went to. A transfer that lands with a constant written to `B3` since the last
call is a call returning there, in the hardware model and so in the plan. `c_landN_sure`
makes a landing unconditional where the plan's own runs always reach it with the latch
set and nothing outside the plan enters the code they run; only landings inside the
stretch qualify, because a run stops outside it once nothing is in flight. The listing is
then checked again and put back if it does not match.
A latched branch reports no flow to Ghidra, and its landing instruction does, so every
analysis that models the hardware asks `C6000PacketStagingAnalyzer.hardware`, `flow` and
`inert` instead of the listing. The constant-reference analyzer accepts a register
landing's target only when it is what the latched branch provably read.

Context fields must never be attached to register lists or share bits: Ghidra then treats
them as following flow whatever `noflow` says. `tools/gen_stage.py` generates tables
that pick the register from the field instead, and `C6000SamePacketHazardTest` checks that
no context field follows flow.

### Staged execute-packet writes

`C6000PacketStagingAnalyzer` takes each read of a register that an earlier member of the
same execute packet writes (`C6000SamePacketHazardAnalyzer.oldReads`, from p-code) and
sets context fields on two instructions. The writer gets `c_staged`, `c_defer` and
`c_defer_reg`: a wrapper constructor saves the register, builds the instruction, moves the
result to `C6000_NEW_<reg>` and restores the register. The last reader gets `c_cm1` or
`c_cm2` with the register: the wrapper copies `C6000_NEW_<reg>` into the register after
the instruction, or, for a branch, the `CFlowDelay` table does so right after the branch
has read its predicate and target. `C6000DelaySlots.recontext` decodes the instruction
unit again with the new fields and keeps its overrides, references and comments. The
analyzer then checks from p-code that the write is held and committed, and takes back
anything that is not. `C6000PacketStagingAnalyzer.hardware` gives the instruction without
staging; the call analyzer, the hazard analyzer, the low-half and jump-table analyzers
and the exact-schedule compiler and its hashes use it, so staging never changes what they
see.

### Call and return recovery

The call analyzer recognizes a B or BNOP transfer as a returning call when its delay
window establishes B3 as the return address. B3 is evaluated from each instruction's
p-code in hardware issue order, up to the cycle the branch lands, and must be where this
arm or its if/else partner stops issuing. A `BNOP n`
window is the 5 - n delay cycles after its NOPs (SPRUFE8B 3.12 BNOP). It can decode
undiscovered delay slots, apply a CALL override, add a register-built call-target
reference, and repair the caller's body. Predicated calls remain conditional; B/BNOP
through the ABI return register B3 remain returns.

B3 must match the end of its delay window, or the complete window of a proved
complementary call partner. A window holds at most 47 instructions: the rest of an
eight-instruction branch packet and five full packets (SPRUFE8B 3.5). Full-width windows may skip only a header exactly at
the boundary; a header elsewhere does not justify return-address slack. Incoming
jump propagation requires a complete delay window and no alternate entry into
the preceding slot sequence. Predicate constraints apply only while their register
is unchanged; uncertain conditional writes invalidate constants. Constant recovery
uses a packet E1 snapshot, then commits writes atomically. Load destinations are
invalidated in E5, including pair aliases; updating bases still change in E1.
Pending writes retire through multicycle NOP/ADDKPC and protected-load idle spans.
Predicate proofs account for the actual load write cycle, including loads issued
before the predicate query (SPRUFE8B 3.5, 3.6, 3.10.2.2, Tables 4-6/4-10/4-11).

Target recovery walks preceding straight-line code, follows MV and ADD/OR of zero, and
skips writes predicated opposite to the branch. Calls are revisited when preceding code
becomes available. The analyzer also handles complementary if/else call pairs: only the
call arm becomes a call when the other arm jumps to a local block. Terminal calls and
callees marked no-return retain their existing treatment.

The processor spec disables Ghidra's heuristic **Non-Returning Functions – Discovered**
analyzer. Its fallthrough heuristic can misclassify a returning call before C6000 delay
slots have been decoded. The name-based **Known** analyzer still runs.

An early pass classifies B3 returns before switch analysis. Register branches retain
conservative fallthrough during discovery, then are redecoded as terminal branches or
returns before Decompiler Switch Analysis. A late pass revisits code discovered while
switches are being recovered.

### Switch dispatch

`C6000JumpTableAnalyzer` recognizes a guarded table lookup: a CMPLTU/CMPGTU bound, an
MVK/MVKH table base, scaled index, predicated LDW and register B/BNOP. It reads at most
the guard's `K + 1` entries, stops at invalid targets, and creates computed-jump
references and a jump-table override. Without a proved guard it recovers no table.

New functions are considered as analysis discovers them. Unchanged overrides and bodies
are not rewritten, avoiding repeated analysis. Override ownership is checked separately
as described [below](#switch-override-ownership).

### Bounded propagation and regression checks

The C6000 constant-reference analyzer limits each propagation walk to 512 bytes to bound
memory use on large control-flow graphs. Values carried only across a longer span may
require manual references or additional evidence. Raw images also need an entry point;
`C6000SetEntry.java` supplies one before auto-analysis. Packet context is primed before
entry-point disassembly.

Ghidra's Scalar Operand References analyzer takes an MVK's sign-extended immediate for
an address. `C6000LowHalfReferenceAnalyzer` deletes that analysis reference when an
unpredicated MVKH completes the register to another value within five cycles, with
nothing reading or writing the register first and no branch landing in between
(SPRUFE8B pp. 380, 383). A branch lands six cycles after it issues (4.2.6, Table 4-11),
so only branches issued in the five cycles before the MVK can land inside that window.
A gap, a fetch-packet header, IDLE or a loop-buffer instruction keeps the reference.

The synthetic fixtures exercise these behaviors in both endian modes:

| Fixture | Checks |
|---|---|
| `branch-flow.py` | Direct targets, flow types and compact-header BNOP scaling. |
| `delayed-call.py` | ADDKPC and register-built calls, complementary predicates, caller bodies and call/jump distinction. |
| `call-packet-slots.py` | Delay slots and return point of a call with a parallel companion. |
| `tail-call-slots.py` | Tail-call delay slots in the caller, and B3-setting `B` and `BNOP` calls kept out of tail-call recovery. |
| `packet-window-fallthrough.py` | Fall-through and function body of conditional jumps whose windows mix 32-bit and compact instructions. |
| `jump-table.py` | A guarded three-case table, an adjacent valid address outside the bound, and native switch output. |
| `return-delay.py` / `packet-call.py` | Captured targets, tail effects, packet links and mixed-width windows. |

See [verification](verification.md) and the [fixture catalog](regressions.md) for
commands and test scripts.

### Floating-point decompilation

`C6000UseAnalysisLanguage.java` switches a comparison copy to the matching endian
and CPU family's concise language without running auto-analysis: `default` becomes
`analysis`, and `c67x` becomes `c67x-analysis`. Repeating it on either concise
variant is a no-op. The language change invalidates existing exact-schedule reviews,
which require renewed review. Keep the original exact-language
program: the concise language deliberately approximates floating-point status and
special rounding. Changing the language is a reading aid, not a fix to the exact
floating-point model.

The default `C6000:LE:32:default` and `C6000:BE:32:default` languages retain the
detailed floating-point rounding and status-register model. Its SP add/subtract,
multiply and DP-to-SP rounding helpers use mask selections instead of internal p-code
branches. All four rounding modes, signed zeros, NaNs, denormal handling, sticky status
bits and the lost-small-addend correction remain explicit; no opaque arithmetic userop
is introduced. This keeps repeated instructions from multiplying the decompiler block
graph. The inputs are captured before the destination is written, including aliases.
Pure speculative p-code arithmetic on special values is discarded before architectural
results or flags are selected (SPRUFE8B sections 2.10.1, 2.10.3 and 3.12
ADDSP/SUBSP/MPYSP/DPSP execution descriptions).

For reading float-heavy functions, explicitly select `C6000:LE:32:analysis` or
`C6000:BE:32:analysis` for C64x/C674x, or the corresponding `c67x-analysis`
variant for C67x/C67x+, when importing a program. These variants use native
single-precision p-code for `INTSP`, `INTSPU`, `MPYSP`, `ADDSP`, `SUBSP`, and the SP
comparisons. It represents status-register effects with the opaque `c6000_fp_status`
userop, so its flag values and special rounding cases are not suitable for emulation.
Use these languages to inspect control and data flow, then use the corresponding
exact language (`default` or `c67x`) for
detailed arithmetic and status checks.

## Switch override ownership

Ghidra stores switch metadata as `function::override::jmp_<branch>::switch` and
`case_<n>` labels. A body repair can leave those labels under the former function.
Passing the detached override to the native decompiler can crash it even when the
instruction listing is valid.

The jump-table and register-branch passes now verify ownership. Repair is limited to
canonical metadata whose ordered cases match the table recovered from the instructions
and bytes. A table moves to its current function owner; if no owner exists or that owner
already has a table, its namespace moves under `C6000_detached_switches`. Existing label
IDs, names and addresses stay intact. Unverified manual case choices stay unchanged. The
standalone `C6000RepairSwitchOverrides.java` script applies the same repair to a legacy
comparison copy.

## Calling convention

`data/languages/c6000.cspec` implements the C6000 C ABI:

| ABI role | Registers |
|---|---|
| arguments | A4, B4, A6, B6, A8, B8, A10, B10, A12, B12, then the stack |
| 32-bit return | A4 |
| return address | B3 |
| stack pointer | B15 |
| frame pointer | A15 |
| data pointer | B14 |
| callee-saved | A10–A15, B10–B15 |

## Function ID

`tools/gen_fid.py` builds a Function ID database from a TI run-time library. The
**`.fidbf` is deliberately not shipped**: the TI code generation tools' licence does not
clearly permit redistributing a database derived from TI's RTS, and the safe default is
to ship the generator and let each user build it from their own CGT install. Read the
script's header before redistributing anything it produces.

## Repository layout

```
build.gradle, settings.gradle, extension.properties, Module.manifest
data/languages/          c6000.sinc (framework), c6000_decode.sinc (generated),
                         c6000_manual.sinc, c6000_compact.sinc, c6000_memory.sinc,
                         c6000_nonalign.sinc (generated), c6000_semantics.sinc,
                         c6000_placeholders.sinc (generated), c6000_{le,be}[_analysis].slaspec,
                         ldefs/pspec/cspec/opinion
ghidra_scripts/          C6000*Test.java checks (one per fixture family), C6000CorpusTest.java,
                         C6000LoopReplay.java, analysis/decompiler audits
src/main/java/c6000/     packet context, packet/call/return/register-branch/software-loop
                         analyzers, software-loop model (C6000SoftwareLoops, C6000LoopBuffer),
                         exact pipeline compiler/injection, encoding metadata, TI ELF symbols
tests/fixtures/          generators for the fixture images and expected-result tables
tests/test_release_tools.py  archive and verification failure-detection checks
docs/                    verification, fixture catalog, release checklist, internals,
                         limitations, packet/trace and software-loop contracts
tools/                   build.sh, verify.py, check_archive.py, generators
                         (gen_*.py, build_encodings.py, parse_encodings.py), GNU-oracle audits
.github/                 workflows/build.yml, issue templates
```

`c6000_decode.sinc` and `c6000_placeholders.sinc` are generated by `tools/gen_decode.py`
from an encoding table parsed out of SPRUFE8B §3.12 (`tools/build_encodings.py`);
`c6000_memory.sinc` and `c6000_nonalign.sinc` come from `tools/gen_memory.py` and
`tools/gen_nonalign.py`. They are committed so the extension builds without the manual;
edit their generators rather than the generated files.

For specialized workflows, see [parallel-peer recovery](recover-parallel-peers.md),
[closed direct calls](closed-call-traces.md),
[caller continuations](caller-continuation-traces.md) and
[strict caller/store tails](caller-tail-traces.md).

## Lossless full32 encoding identity

SPRUFE8B section 3.12's scalar `MV` opcode maps cover distinct ADD-zero and OR-zero
encodings. The full32 decoder displays the actual primitive and an explicit zero
operand; cross-path variants of these constructors include X in the unit suffix. This is
a display change: their existing move p-code is retained. The separate 40-bit
register-pair move keeps its MV spelling, and an equal-source SUB is not collapsed into
an assembler-chosen ZERO alias.

TI-compatible text alone still cannot select every address form. In particular, small
B14/B15 offsets may use short5 or long15 forms with identical spelling. The public
`C6000EncodingInfo.describe(Instruction)` utility returns that form, encoded element
offset and scale, short-memory addressing mode, base/offset registers, predicate and p
fields, known scalar-move cross paths, and numeric packet layout/expansion/p bits.
C6000ExportEncodingInfo.java
<output.jsonl> [start end]` exports these alongside ordinary listing text.
It does not invent a TI suffix or emit raw opcode directives.

The packet description distinguishes unavailable header bytes from a known ordinary
packet. A full32 BNOP's displacement scale is two bytes in a header-based packet and
four in an ordinary packet; B, BDEC and BPOS remain four-byte scaled. An unknown BNOP
context has a null scale. These rules are from SPRUFE8B 3.10.2 and the section 3.12
opcode/execution descriptions; address-form fields follow 3.9.3 and the ADDAW/scalar
load/store opcode maps. Compact-specific form details are intentionally left to their
compact decoder.

`C6000EncodingInfo.registerCopySource(Instruction)` identifies conservative,
unconditional MV or integer ADD/OR-zero copies with zero in either operand position.
Constant-call recovery uses it so `ADD.Dx src,0,dst` retains the same known register
value as its former MV spelling. Unknown cross-path metadata is null; the API does not
assume every bit 12 is a cross selector.

### Language prototype migration

Big-endian languages are version 2.0 (issue #31). `data/languages/old/` describes the
version 1 `default` and `analysis` languages, and `C6000BeDefaultLanguageTranslator` /
`C6000BeAnalysisLanguageTranslator` carry each context field over by name. After
Ghidra's re-disassembly they prime `c_h16` and re-disassemble again, which keeps
references, overrides and comments. Re-run auto-analysis afterwards so delay windows and
calls are recovered from the corrected order. The big-endian C67x variants were never
released at version 1.

All eight languages are version 3.0: `contextreg` grew from 64 to 128 bits for latched
branches. `data/languages/old/` describes each version 2 language. Little-endian ones
have a `.trans` file, and Ghidra's default translator carries each field over by name.
Big-endian ones have a Java translator (`C6000Be*V2LanguageTranslator`) that also primes
`c_h16` again after Ghidra's re-decode, as the version 1 to 2 step does; with only a
`.trans` file a version 1 big-endian program came out with its compact code undecoded. The notes below on re-analysis and reviewed schedules apply to
this step too.

Little-endian languages became version 2.0 in v1.3.0: `contextreg` grew from 32 to 64 bits. The
old field positions are unchanged, but SLEIGH numbers context bits from the most
significant end, so every stored value moves. `data/languages/old/` describes all four
version 1 little-endian languages (1.0 to 1.2 differ only by added fields), and Ghidra's
default translator carries each field over by name; no Java translator is needed. A
reviewed exact schedule or parallel-peer plan hashes the context register's value, so
review an upgraded program's schedules again: until then an active schedule fails
loudly ("Exact C6000 schedule failed") instead of lifting.

Ghidra's upgrade re-disassembly can lose the instruction just after a native delay window
whose last slot is compact, or fail that window's branch with a Bad Instruction bookmark.
On the stock image this happened at three windows in about 30,000 instructions. The cause
is in Ghidra ([#10242](https://github.com/NationalSecurityAgency/ghidra/issues/10242)):
`SleighInstructionPrototype.getFallThroughOffset` and `getDelaySlotDepth` re-parse each
delay slot with the branch's own context, not the slot's, so a window that mixes 32-bit
and compact instructions is measured at the wrong length. `CodeManager.addInstructions`
uses that length for the range it reports as disassembled and for its conflict check.
Any whole-program re-disassembly does this, upgrade or not, and re-running auto-analysis
does not restore those instructions. Re-import when the listing must match a fresh
analysis exactly.

The same miscount gives a conditional jump with a window a wrong default fall-through,
and Ghidra's `FollowFlow` counts a window's slots with `getDelaySlotDepth` when it computes
function bodies. Delay-window recovery therefore sets every windowed conditional jump's
fall-through to the next execute packet after its native window, the packet primer's
parallel-peer windows included, and keeps the whole window in the function's body.

The 1.2 language minor version forces Ghidra's native re-disassembly upgrade. This is
necessary when a corrected compact operand partition distinguishes bits that an older
shared persisted prototype ignored. Updating the extension alone can leave old programs
with stale operand text and p-code. Preserve a packed backup and annotation inventory
before upgrade. Native migration can remove existing Bad Instruction error bookmarks;
retain/restore those from the backup if preserving every annotation is required. Audit
actual processor context and instruction extents as well as symbols, functions and
references.
