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

`C6000DelaySlots` proves finite unconditional `B` /`BNOP` windows, including IRP/NRP
forms. It accounts for execute cycles, implied BNOP cycles, multicycle NOP/ADDKPC,
protected loads and crossed compact headers. The physical byte count is stored in
`c_flow_delay`; `tools/gen_flow_delay.py` generates the constant `delayslot(n)` choices
because SLEIGH counts delay bytes, rather than instructions.

Targets and predicates are captured before delay work. Native parsing is checked before
listing changes; transactional recovery preserves comments, symbols, references and
explicit fallthrough overrides. Nested transfers, defined data and conflicting function
ownership prevent recovery. Predicated full windows, BDEC/BPOS and existing delayed-call
overrides retain conservative native treatment. Exact scheduling handles its own
supported branch phases.

CALLP supplies five implied idle cycles. Its parallel companions execute before the
side-specific A3/B3 link is written; the next execute packet is the return point.
Ghidra's generic delay-depth counter can apply the branch's compact context to its
followers, so the late pass corrects fallthrough using the proved physical window.
Mixed-width stock-emulator stepping remains limited; listing p-code and decompilation
use address-specific context.

### Branch targets

C6000 direct transfers are PCE1-relative: the base is the start of the containing
32-byte fetch packet, `inst_start & 0xFFFFFFE0`. This applies to B, CALLP, BNOP, BDEC,
BPOS and ADDKPC. Full32 BNOP displacement counts words in ordinary packets and halfwords
in header-based packets. The primed `c_hdrpkt` context selects that scale. Targets are
exported in RAM so Ghidra can follow them as code references.

### Call and return recovery

The call analyzer recognizes a B transfer as a returning call when its delay window
establishes B3 as the return address through ADDKPC or MVK/MVKH. It can decode
undiscovered delay slots, apply a CALL override, add a register-built call-target
reference, and repair the caller's body. Predicated calls remain conditional; B/BNOP
through the ABI return register B3 remain returns.

B3 must match the end of its delay window, or the complete window of a proved
complementary call partner. Full-width windows may skip only a header exactly at
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

The synthetic fixtures exercise these behaviors in both endian modes:

| Fixture | Checks |
|---|---|
| `branch-flow.py` | Direct targets, flow types and compact-header BNOP scaling. |
| `delayed-call.py` | ADDKPC and register-built calls, complementary predicates, caller bodies and call/jump distinction. |
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
                         exact pipeline compiler/injection and encoding metadata
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

The 1.2 language minor version forces Ghidra's native re-disassembly upgrade. This is
necessary when a corrected compact operand partition distinguishes bits that an older
shared persisted prototype ignored. Updating the extension alone can leave old programs
with stale operand text and p-code. Preserve a packed backup and annotation inventory
before upgrade. Native migration can remove existing Bad Instruction error bookmarks;
retain/restore those from the backup if preserving every annotation is required. Audit
actual processor context and instruction extents as well as symbols, functions and
references.
