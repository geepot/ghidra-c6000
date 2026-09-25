# Status and known limitations

The short list is in the [README](../README.md#features-and-limitations); this
page has the detail. The module is a working decoder with staged semantics.

## Status by area

| Area | State |
|---|---|
| 32-bit instruction decode (mnemonic, unit, operands, length) | broad SPRUFE8B §3.12 coverage, legacy `MVC`, and C64x+ linked-word `LL`/`SL`/`CMTL`; no nonfill gaps in the measured stage 2 payload or the stage 1 code region |
| Instruction lengths and execute-packet framing | 2/4-byte lengths and compact layout context; execute packets are not atomic |
| Branch / call targets (`B`, `BNOP`, `CALLP`, `BDEC`, `BPOS`) | modelled in the RAM address space, PCE1-relative per the manual; delayed `B` + `ADDKPC` calls and `B`/`BNOP` returns through B3 recovered by analyzers |
| Compact 16-bit fetch packets | most observed slots decode, driven by packet-header context (see [internals](internals.md#compact-16-bit-fetch-packets)) |
| P-code semantics | integer ALU and common multiplies, compact saturating arithmetic, immediates, bit-field operations, linear and AMR circular address arithmetic, scalar and doubleword loads/stores, single-precision arithmetic and conversions, selected double-precision arithmetic and conversions, compares, shifts, branches/calls, `MVC` |
| Other decoded instructions | no generated `c6000_unimpl_<mnemonic>` calls remain; software-loop controls, `IDLE`, and C64x+ linked-word operations use named event userops; `DINT`/`RINT` update `TSR` and `CSR` interrupt-enable bits |
| Function ID | generation script shipped; database not shipped (TI licence) |
| Software loop controls | decoded and annotated; a separate cycle scheduler replays buffered packets and stage-boundary `ILC` changes, including predicate-driven `SPLOOPW` |
| Architecture-wide fidelity | not yet established by firmware coverage; packet timing, selected floating-point status, and exact reciprocal seeds need further verification |

## Limitations

* **Compact instructions decode via the header context**, which the Java
  analyzer primes before disassembly. The context fields are marked `noflow`
  so a compact slot reached by fall-through is not decoded with the previous
  instruction's parameters; the price is that a tool which disassembles
  without priming the context will not decode compact packets at all.
* **Some architecture encodings may remain uncovered.** The [measured](verification.md) stage 2
  payload and stage 1 code region have no undecoded nonfill slots, but those
  images are not an exhaustive encoding test. The decoder leaves unknown words
  undefined instead of guessing an instruction.
* **Execute packets are not modelled as units** — see
  [internals](internals.md#execute-packets-delay-slots-and-parallel-semantics).
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
  [The loop conformance notes](software-loop-conformance.md) specify
  the remaining emulator state. Native Ghidra decompilation still displays
  the loop-control userops, because the hardware buffer does not correspond
  to an ordinary control-flow edge.
* **Predication** is decoded, displayed and guards the modelled 32-bit p-code.
  Compact predication and packet-wide parallel effects need further work.
* The generic corpus is assembled from GNU binutils, whose tic6x assembler
  covers less of the ISA than the manual; it is a regression oracle, not a
  completeness proof.
