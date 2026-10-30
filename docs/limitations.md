# Status and known limitations

The extension provides instruction decode, p-code and C6000-specific analysis. Its
models have different timing and execution guarantees. Use the
[verification guide](verification.md) to check the behaviors you depend on.

## Release 1.1.1: decompilation and round trips

Normal Ghidra decompilation can consume an explicitly reviewed complete closed-call
schedule through `enableClosedCalls`. This is an opt-in function-level capability.
Installing the extension, importing an image or migrating its language version does
not create entry proofs or activate schedules across the image. Default instruction
lifting can still expose a parallel result too early or omit its actual latency.

The call model accepts one to sixteen sequential nonrecursive leaf calls, including
repeated callees, proved register destinations, split return links and supported
callee branches/ordinary counter loops. Nested calls, arbitrary function pointers,
return links restored through memory, general caller branches and software loops
inside closed-call traces remain refused. Helpers retain separate database owners,
but the recovered C may inline their effects rather than preserve call expressions.
A callee cannot independently enable another schedule inside the root trace.

Normal activation requires a complete caller return, exact declared caller ownership,
no unowned spans and explicit drained-entry/incoming-hazard assumptions. Calls do not
flush the pipeline. Pending effects at the final return still need a supported
observation contract; closed-call and post-return store-tail contracts cannot be
combined. Changed source bytes, plans, ownership, context or references invalidate
the binding and require renewed review. Schedule limits are 4,096 states and one
million p-code operations; closed-call windows are bounded to 4 KiB each.

The `bitstream_flush` round trip matched 1,056 tested LE boundary/random/AMR cases
with TI compilation and compression enabled. It is evidence for that function and
corpus, not whole-image recovery, identical machine bytes, exhaustive semantic
equivalence or hardware validation. The emitted C still contains low-level AMR
expressions and signed arithmetic; matching the selected TI output does not establish
portable-C overflow safety. See the [experiment report](multi-call-roundtrip.md).

## Decode and analysis

**Coverage is not exhaustive.** Decode covers the documented full32 opcode maps and
supported compact formats, including legacy MVC and C64x+ LL/SL/CMTL. Unknown encodings
remain undefined. A successful sample or corpus run does not establish coverage of every
architectural encoding.

**Compact decode needs packet context.** The packet analyzer normally primes it before
disassembly. Tools that bypass auto-analysis must call `C6000PacketContext.prime` before
decoding compact slots. The `noflow` context fields prevent one instruction's header
parameters from leaking into another; see
[compact packet internals](internals.md#compact-16-bit-fetch-packets).

**Constant propagation is bounded.** Each walk is limited to 512 bytes to bound memory
use. A register-built target carried across a longer span, loaded from memory or
supplied by another routine may remain unresolved. Raw imports also need an explicit
entry before code discovery can begin.

## Packet timing and control flow

| Model | Supported behavior | Boundary |
|---|---|---|
| Default instruction p-code | Instruction effects and proved native B/BNOP/CALLP delay windows. | Parallel instructions are lifted individually; ordinary writeback latency is not scheduled. |
| [Exact packet schedules](pipeline-schedules.md) | Supported parallel reads, pending branches and register/memory/status phases through E10; normal software loops. | Reviewed drained entry and incoming E1 hazards; only unchanged recorded contracts activate automatically. Unsupported or stale contracts are refused. |
| [Loop replay](software-loop-conformance.md) | Buffer issue order, masks, loop counters and supported drain/restart behavior. | Does not execute instruction p-code, retire writes or enter interrupt handlers. |
| Closed-call schedules | Pending effects through explicitly proved caller/callee boundaries; normal decompiler injection for complete reviewed callers. | Sequential leaf calls and pinned ownership/entry assumptions; explicit activation only. |
| Read-only caller continuations | Pending effects through explicit immutable caller windows. | Bounded plans and entry proofs; not automatically installed as callee-only schedules. |

Native delay recovery remains conservative for nested transfers, predicated full
windows, BDEC/BPOS and existing delayed-call overrides. Ghidra's stock instruction-step
emulator can fail on mixed-width delay windows; direct listing p-code execution and
native decompilation have separate checks.

Trace and activation contracts are documented for
[closed calls](closed-call-traces.md),
[caller continuations](caller-continuation-traces.md) and
[strict caller/store tails](caller-tail-traces.md). A function boundary or ABI prototype
does not establish an empty incoming pipeline.

## Memory and addressing

**Aligned LDW requires a word-aligned address.** Its p-code clears the low two address
bits so a propagated misaligned value cannot form an invalid four-byte RAM range in the
decompiler. Actual hardware behavior outside the documented alignment requirement is not
established by this model.

**AMR effects are modeled at instruction level.** Eligible A4–A7/B4–B7 bases wrap
through BK0/BK1, including bytewise wrapping of nonaligned transfers. Stores capture
their source before a base update. Packet timing involving AMR writes is not generally
modeled. The exact compiler refuses unsupported control-register effects and buffered
missed-stall conditions.

**The time-stamp counter is not modeled.** `TSCL` writes and `TSCL`/`TSCH` reads lift
to `c6000_tsc_start`, `c6000_tscl_read` and `c6000_tsch_read`; the stock emulator needs a
userop handler to run them.

**Linked-word operations require an external memory monitor.** LL and SL expose the
CPU-visible transfer and named link events. CMTL receives success from a userop; the
stock instruction emulator cannot infer another core's link state.

## Floating point and arithmetic

Selected instructions model rounding modes, special values and status events, but
status-register coverage is not complete across the ISA. ADDSP/SUBSP and ADDDP/SUBDP use
FADCR; MPYSP, MPYSPDP and MPYDP use FMCR. Supported DP arithmetic uses a quad-precision
intermediate to retain DP rounding. See the
[fixture catalog](regressions.md#integer-and-floating-point-execution) for
instruction-specific execution checks.

Reciprocal estimates implement documented special cases and FAUCR flags with an
eight-bit-accurate seed. TI does not publish the seed lookup table, so ordinary results
are not proven bit-exact against hardware.

The `analysis` language variants simplify single-precision arithmetic and use an opaque
status userop. They are reading aids; use the default languages for emulation and exact
rounding/status checks.

The published RPACK2 execution rule and compiler guide specify a saturating left shift.
For the manual's `0xFEDCBA98` example this yields upper halfword `0xFDB9`, while the
worked example prints `0xFDBA`. The implementation follows the stated operation.

## Loops, interrupts and exceptions

Software-loop instructions lift to named userops and receive analyzer bookmarks. The
loop replay helper models buffer control separately from instruction execution. The
exact compiler supports normal counted/while loops, but nested reload and loop
interrupt/restart remain unsupported there. Detailed callback, reload and handoff
contracts are in the [loop-conformance guide](software-loop-conformance.md).

DINT/RINT update modeled TSR/CSR interrupt-enable fields. B IRP restores GIE and B NRP
sets NMIE; the remaining ITSR/NTSR-to-TSR restore is not modeled. IDLE emits a scheduler
event; the stock emulator does not suspend until an interrupt on its own.

SWE/SWENR transitions are instruction-level models. `NRP = inst_next` is exact when SWE
ends its execute packet. Parallel companions and simultaneous exception priority require
a packet-aware executor.

## Function ID

Only the [database generator](internals.md#function-id) is shipped. A database derived
from TI's run-time library is not distributed because its licensing must be assessed
separately.
