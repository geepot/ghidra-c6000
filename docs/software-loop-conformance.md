# C674x software-loop conformance

This is the transfer contract for a future emulator. The authoritative behavior is
[TI SPRUFE8B, chapter 7](https://www.ti.com/lit/ug/sprufe8b/sprufe8b.pdf),
especially §§7.7–7.13. `C6000LoopBuffer` is a cycle scheduler over Ghidra
instructions; it does not execute their p-code. Keep the scheduler's control
state separate from register, memory, branch, and pipeline state when porting it.

## Verified behavior

| Behavior | Current model | Check |
|---|---|---|
| Source execute packets, compact parallel bits, `NOP n` idle cycles | `fromProgram` extracts one scheduled iteration | 24/24 stage 1 and 224/224 stage 2 firmware bodies parsed |
| Initiation interval overlap and source `SPMASK` | `operationsAt` identifies program versus buffered operations and suppresses masked units | Firmware replay of all 248 paired loops |
| `SPLOOP` initial zero/nonzero `ILC` test and `SPLOOPD` first-three-cycle grace | `replayCountedDetailed` | Zero, one, and two-count runs over every counted firmware loop |
| Short final loading stage | Idle cycles continue through its stage boundary | Zero and one-count firmware replay assertions |
| `SPLOOPW` three-cycle delayed predicate and stage-boundary `ILC` decrement | `replayWhileDetailed` | Every detected firmware `SPLOOPW` replayed |
| Post-`SPKERNEL` fetch delay and epilog overlap | `ReplayResult.firstPostBodyCycle`, `Cycle.postBodyFetchEnabled` | Stage 2 loop at `0xC0003362`: delay 8 cycles, first fetch cycle 18, replay ends at cycle 23 |
| Post-body `SPMASK` suppression | `Cycle.overlayPostBody(packet)` filters buffered operations using the caller's selected program packet | 1 stage 1 and 45 stage 2 overlay cycles exercised with synthetic packets containing a `SPMASK` instruction drawn from firmware |

The replay result's cycle numbers begin at zero on the cycle **after** the
`SPLOOP` execute packet. `firstPostBodyCycle == cycles` means fetching resumes
on the next cycle after the reported loop trace. Operations in one cycle are
simultaneous even though the API returns a list for inspection.

## Remaining emulator state

1. **Program counter and execute packets.** The caller must choose the
   post-body packet, including branch delay slots and taken targets, then pass
   that packet to `overlayPostBody`. The scheduler reports fetch enable timing
   but does not guess the PC. Decode packet headers before constructing an
   execute packet.
2. **Instruction execution and pipeline.** Apply packet operands with
   simultaneous-read semantics and the instruction-specific write latencies
   from SPRUFE8B chapter 4. Loads, stores, branches, floating-point results,
   and control-register writes mature at different phases. The loop scheduler
   currently reports when an operation is issued, not when its result becomes
   visible.
3. **Interrupt drain and restart.** At an eligible stage boundary, interrupt
   draining must disable program-memory fetch, preserve the remaining `ILC`,
   finish pending register writes, save the `SPLOOP` packet address in `IRP` or
   `NRP`, and preserve `SPLX` in `ITSR` or `NTSR`. A restart suppresses parallel
   setup instructions and source `SPMASK` operations, executes buffered masked
   instructions, treats `BNOP` as idle cycles, and treats `SPLOOPD` as `SPLOOP`.
   Eligibility depends on pending/blocked interrupt state, loading/draining
   state, the first three cycles of `SPLOOPD/W`, and the loading-stage count.
4. **Nested reload.** A predicated `SPLOOP/D` with `SPKERNELR` or a later
   `SPMASKR` needs the outer predicate sampled four cycles before the final
   kernel boundary, `RILC` copied and decremented into `ILC`, and a second LBC
   while old stages drain and new stages reload. Branches can disable program
   fetch during reload. `replayCountedDetailed` rejects these loops instead of
   reporting an incomplete trace.
5. **Exceptions and architectural validation.** Exceptions abort the buffer
   without a normal epilog. The emulator must also enforce the documented
   resource, register-access, `SPMASKR`/`SPKERNELR`, and reload-overlap
   restrictions. Ghidra's static decoder does not enforce all of them.

For a full conformance run, supplement the firmware with small assembled
fixtures for zero/one iteration, every legal `ii`, each `SPKERNEL` delay,
source/post-body masks, `SPLOOPW` early termination, interrupt restart, and
both reload forms. Compare issue cycles, result-availability cycles, `ILC`,
`RILC`, `LBC`, `SPLX`, PC, and memory writes against a C674x hardware trace or
another independently validated reference. Firmware coverage verifies the
encodings it contains; it cannot establish behavior for interrupt or nested
reload paths that it does not exercise.
