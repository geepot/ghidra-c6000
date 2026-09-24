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
| Post-body `SPMASK` suppression | `Cycle.overlayPostBody(packet)` filters buffered operations using the caller's selected program packet | 1 stage 1 and 53 stage 2 overlay cycles exercised with synthetic packets containing a `SPMASK` instruction drawn from firmware |
| Counted-loop interrupt eligibility and buffer drain | `replayCountedDetailed` accepts a pending, unblocked interrupt signal, preserves `ILC`, disables post-body fetch, and returns `INTERRUPT_DRAINED` | Every counted firmware loop drained with a persistent pending signal and high `ILC`; short loops completed without accepting it |
| `SPLOOPW` interrupt drain and delayed-condition exit | `replayWhileDetailed` continues predicate tests while draining and distinguishes `INTERRUPT_DRAINED` from `INTERRUPT_AT_POST_BODY` | All detected firmware `SPLOOPW` loops drained with a true predicate; synthetic predicate changes ended 15 stage 1 and 39 stage 2 drains at the post-body instruction |
| Interrupt return packet and pipe-up | `InterruptHandoff` exposes the saved `SPLOOP` packet address, `ILC`, and `SPLX`; restart replay reverses source `SPMASK` behavior and makes `SPLOOPD` use `SPLOOP` initial control | All 248 detected firmware loops replayed on restart; 31 stage 1 and 584 stage 2 masked source operations were identified, and 2 stage 2 buffered operations ran through a source mask |
| Restart idle cycles for `BNOP`, masked `ADDKPC`, and protected loads | Source packet duration includes encoded delay counts and the compact header's `PROT` bit; restart issues an `Operation` with `idleOnly=true` for suppressed effects | Four assembled C674x loops cover displacement `BNOP`, masked register `BNOP`, masked `ADDKPC`, and a masked protected `LDW`. Firmware contains 6 stage 1 and 42 stage 2 protected source loads; all 248 loops replayed with the corrected durations |
| Immediate `SPKERNELR` reload | `replayImmediateReload` starts each buffered invocation after the final kernel boundary, copies and decrements the visible `RILC`, and overlaps its prolog with the previous epilog | Assembled buffer sequence from TI Example 7-15 replays two or three invocations in 20 or 27 cycles, including simultaneous old `STW` and new `MV` issues |

The replay result's cycle numbers begin at zero on the cycle **after** the
`SPLOOP` execute packet. `firstPostBodyCycle == cycles` means fetching resumes
on the next cycle after the reported loop trace. Operations in one cycle are
simultaneous even though the API returns a list for inspection. An emulator
must advance through an `idleOnly` operation's scheduled cycles without
executing that instruction's p-code.

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
3. **Interrupt completion and architectural return.** Counted-loop buffer draining now
   ends with preserved `ILC` and disabled program-memory fetch; `SPLOOPW`
   draining can instead hand the interrupt to the first post-body instruction.
   The emulator must finish pending register writes, write the saved packet
   address to `IRP` or `NRP`, preserve `SPLX` in `ITSR` or `NTSR`, and restore
   those registers on return. Restart replay handles source/buffer mask
   reversal and `SPLOOPD` initial control; the caller must suppress
   instructions parallel with the restarted `SPLOOP` packet. The scheduler
   handles `BNOP`, masked `ADDKPC`, and protected-load idle cycles.
   Architectural blocking and pending interrupt state are supplied by the
   caller for either loop kind. The model does not determine handler-entry
   timing or write the CPU control registers itself.
4. **Remaining nested reload cases.** The dedicated immediate reload entry
   point covers predicated `SPLOOP` with `SPKERNELR` when both the first and
   subsequent invocation counts finish the loading stage. It samples the
   caller's outer predicate four cycles before the last kernel boundary and
   reads the caller's visible `RILC` at the boundary. `SPLOOPD`, zero or short
   reload counts, delayed `SPMASKR` reload, and branch-based program-fetch
   disabling still need models. A delayed reload also needs a second LBC
   because the old drain and new prolog can have different offsets.
   `replayCountedDetailed` continues to reject reloadable loops.
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

The restart-delay and immediate-reload fixture is `tests/fixtures/loop-delay.s`. Assemble its
`.text` section as a raw binary with GNU `tic6x-unknown-elf-as -march=c674x`
and `tic6x-unknown-elf-objcopy -O binary -j .text`, then import it at
`0x1000` as `C6000:LE:32:default` and run `C6000LoopDelayTest.java` and
`C6000ImmediateReloadTest.java` headlessly. The scripts check issue effects and
idle-cycle positions. The protected-load case uses a 32-bit `LDW` in a compact
fetch packet with `PROT=1`. The same header rule also applies to 16-bit loads.
The immediate-reload fixture includes a 32-bit `NOP 4`, validating its four-bit
encoded count. These fixtures do not replace hardware timing validation.
