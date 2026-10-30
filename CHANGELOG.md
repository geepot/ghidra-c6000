# Changelog

## Unreleased

### Fixed

* Add LE/BE `c67x` and `c67x-analysis` language variants so opted-in exact
  schedules omit the C64x/C674x cross-path stall on C67x/C67x+ (SPRU198K
  6.3.2.2). Preserve existing default/analysis timing and language-bound review
  contracts. Cover both cross paths, predicates, incoming hazards, pending loads
  and late DP reads. Preserve the CPU family when switching a comparison copy to
  concise floating-point analysis, with native-decompiler and conversion checks.
  Decoder legality filtering remains a documented limitation;
  C66x-specific instruction support remains a known gap.
* Honor native parallel-follower predicate guards in all delayed-call path proofs,
  including B3 constant tracking. Refuse skipped or unproved guarded links, retain
  known links across skipped copies, and cover all six predicates in both senses
  and byte orders (SPRUFE8B 3.5, 3.6, 4.2.6).
* Keep a delayed call's predicate fact across a parallel follower's guard and
  across constant writes (`MVK`, `MVKL`, `SUB x,x,dst`) that cannot change it on
  the call path, so compiler predicate-nullify calls stay calls and a never-taken
  jump at another call's return is not one (SPRUFE8B 3.5, 3.6, 3.12 MVK/SUB/ZERO,
  4.2.6).

## 1.1.1 - 2026-10-29

### Upgrade notes

* All four language definitions are version 1.2 so Ghidra rebuilds persisted
  prototypes after the compact predicate and memory corrections. Keep a packed
  backup and annotation inventory before the native language upgrade.
* Native migration can clear existing Bad Instruction error bookmarks while rebuilding
  prototypes. Record them in the backup inventory and restore them when preservation
  is required; migration does not enable exact schedules automatically.

### Added

* Schedule `PACK2` (`.L`/`.S`) and `PACKL4` (`.L`) with E1 input capture and
  writeback (SPRUFE8B pp. 397-398, 407-408).
* Add an explicit, source-bound post-return store-tail observation contract.
  Capture individual byte/word/pair effects and mature only pending E3 stores
  during one or two declared idle advances. Keep ordinary pending-return
  refusals and real caller traces unchanged (SPRUFE8B 3.5, 4.2.3, 4.2.6).
* Support `ANDN` on `.L`, `.S` and `.D` in exact packet schedules, with
  E1 source capture and writeback, predication and register aliases
  (SPRUFE8B pp. 145-146).
* Integrate exact same-packet reads and delayed writeback into reviewed function
  analysis using the existing scheduling backend. Add read-only report/review/apply
  tooling, a contract-gated analyzer, and source-bound decompiler injection.
  Refuse stale bytes, context, ownership, entry assumptions and alternate entries
  instead of silently using sequential effects (SPRUFE8B 3.5, 3.8.3 and 4.2).
* Integrate explicitly reviewed, complete closed-call traces into normal decompilation
  through `enableClosedCalls`, persisted plans and the existing source-bound injection
  library. Preserve separate callee owners; reject stale plans, interior entries and
  bounded-only traces. Cover native decompilation and pending stores in both endians.
* Schedule sequential leaf calls, including repeated callees, with invocation-specific
  continuations and live pipeline effects. Accept proved early MVK/MVKH/ADDKPC links.
* Schedule full32/compact CALLP on both S units: E1 A3/B3 link, next execute-packet
  return address and five implicit NOP advances. Track saved return-link provenance
  for returns through registers such as A0, while rejecting unknown/clobbered links
  (SPRUFE8B 3.5, 3.7, 3.8.10, 4.2.6, CALLP p.172).
* Prove closed-call register destinations and MVK/MVKH return links from packet-old
  raw p-code; expose the captured call destination and ordered link writers. Permit
  validated direct branches and ordinary counter loops within the callee while
  retaining separate owners and pending effects across call/return boundaries.
  Cover target overwrites, cross-path/B3 calls, split-link refusals and internal
  branches in both endians (SPRUFE8B 3.5, 3.7, 3.12, 4.2.6).

### Fixed

* Capture both ADDDP/SUBDP upper source words in E2, preserving E1 lower
  words and issue predicates, including reversed operands and cross-path
  stalls (SPRUFE8B Table 4-16; SPRU733A Table 4-12; issue #20).
* Read the implicit five NOPs of compact `BNOP` Sbu8/Sbu8c from their
  encoding when no scalar operand exists (SPRUFE8B Figures F-18/F-21).
  Share the count reader across exact schedules, caller-entry evidence and
  loop-buffer timing; preserve variable-count and full-width forms.
* Apply AMR circular addressing to compact memory forms, including per-byte
  wrapping for nonaligned transfers, and preserve the incoming store source
  when predecrement updates an overlapping pointer (SPRUFE8B 3.9.2 and
  Figures C-8..C-15). Add native and exact-schedule regressions in both byte
  orders, including E1 pointer and E5 load observations.
* Correct the skip-condition polarity of compact predicated `MVK` for `[A0]`,
  `[!A0]`, `[B0]` and `[!B0]` (SPRUFE8B Figure G-3). Add raw and exact-schedule
  regression checks for enabled, disabled and predicate-aliasing writes in both
  byte orders.
* Refine delayed-call B3 ownership, restrict header adjustments to the actual
  window boundary, and require stable predicates and unique incoming paths
  before propagating return-address constants (SPRUFE8B 3.5, 3.12 B).
* Display compact cross-path functional units with `X`, including A-side
  `ADDAW` from B15 (SPRUFE8B 3.8.3 and Figures C-17/C-18, D-4/D-5/D-7,
  E-5, F-22/F-23/F-29, G-1/G-2).
* Route `SUBU` opfield `0111111` through cross-path src1, and decode
  unconditional `GMPY4` by treating compound-M bit 28 as predicate z
  (SPRUFE8B 3.12 SUBU and Figure E-1).
* Mask scalar `SHL`, `SHR` and `SHRU` register counts to six bits
  (SPRUFE8B 3.12 SHL/SHR/SHRU).
* Correct the `DPSP` fixture's INEX expectation when rounding, update compact
  unit expectations, and run the added accuracy regressions in both byte orders.
* Decode predicated full32 register `B.S2` in the exact scheduler's terminal
  context. Capture the predicate and target before delay work while retaining
  the existing discovery form and unresolved-target refusals. Cover both
  predicate polarities and all six predicate registers in both endian modes
  (SPRUFE8B pp. 153-154, section 4.2.6).

### Validation

* `bitstream_flush` recovered through stock `DecompInterface`, compiled with TI CGT
  C6000 8.3.15 and compression enabled, matches the original production schedule
  and independent oracle in all 1,056 boundary/random/AMR cases. No custom export
  payload is needed. Pre-activation C and an output mutant remain failing controls.
* Add CALLP, repeated-callee, saved-link and native decompiler execution regressions
  in both endians, including stale-contract and unsafe-entry refusals. Correct an
  older CALLP fixture's illegal NOP 2 peer.
* Release verification covers Ghidra 12.1.3, 12.1.4 and 12.2 in both byte orders,
  including TI-assisted checks and the additional parallel-peer recovery fixtures.
  See [release guidance](docs/release.md) for commands and coverage counts.

### Limitations

* Exact packet timing requires explicit reviewed entry assumptions and source-bound
  activation. Default instruction lifting still handles parallel instructions
  separately; installing or migrating does not make every function timing-correct.
* Closed-call schedules permit up to sixteen sequential nonrecursive leaf calls.
  Nested calls, arbitrary indirect targets, memory-restored return links and more
  general caller control flow remain unsupported. Recovered helper effects may be
  inlined rather than emitted as separate C calls.
* Round-trip results establish behavior on the tested corpus, not byte-identical
  recompilation, exhaustive correctness, portable-C overflow safety or silicon
  equivalence. Floating-point status, reciprocal estimates, interrupts and exceptional
  software-loop behavior retain the [documented limitations](docs/limitations.md).

## 1.1 - 2026-10-28

### Upgrade notes

* All four C6000 language definitions are now version 1.1. Ghidra's native
  migration rebuilds persisted instruction prototypes after the compact
  operand fixes. Back up existing programs and annotations before upgrading;
  see [migration notes](docs/internals.md#language-prototype-migration).
* Full32 scalar move aliases now display their actual ADD/OR-zero encoding;
  equal-source SUB and 40-bit MV retain their own identities. Identically
  spelled short/long memory forms are exposed by `C6000EncodingInfo` and
  `C6000ExportEncodingInfo.java` (SPRUFE8B 2.4, 3.9.3, 3.10.2).

### Added

* Complete proved full-width and compact execute-packet peers during ordinary
  analysis, sharing the reviewed recovery proof and preserving code/data, context
  and function bodies. Stop speculative compact fetch-tail decoding.
* Add opt-in physical parallel-peer reports and reviewed-hash recovery of undefined
  instructions while retaining existing code/data, context and annotations
  (SPRUFE8B 3.5, 3.10.2, 3.10.4).
* Add strict source-bound caller/store-tail traces with exact callee/caller byte
  ownership, native E3 store carry, and verified final caller E1 hazards
  (SPRUFE8B 3.5, 3.10, 4.2.3, 4.2.5, 4.2.6).
* Explicit per-function exact packet schedules preserve raw exact p-code,
  captured predicates and targets, old parallel reads, delayed sticky flags,
  X-path stalls and overlapping B/BNOP transfers. Supported phases extend
  through E10, including independent DP read ports and split writes.
  Enabling requires a documented drained entry and incoming E1 hazards,
  preserves annotations transactionally, and refuses unsupported contracts
  (SPRUFE8B 3.5, 3.8, 4.2). See [pipeline schedules](docs/pipeline-schedules.md).
* Normal SPLOOP/D/W loading, fetch and drain states in the exact compiler,
  including delayed ILC/RILC availability, SPMASK overlays, branch aborts and
  zero/one-iteration padding. Nested reload and interrupt/restart remain
  guarded there (SPRUFE8B 7.4, 7.7–7.10, 7.14).
* Read-only closed direct-call traces carry pending effects across explicit
  call/return windows, with byte hashes, ownership bounds and raw p-code link
  proof. Ordinary function schedules retain their call and pending-return
  guards (SPRUFE8B 3.5, 3.7, 3.10.2, 4.2).
* `tools/verify.py` builds and tests the packaged extension in an isolated
  Ghidra copy in both endian modes, retaining logs, completion markers and a
  JSON summary with the archive SHA-256. `--with-ti` requires the additional
  TI-assembled regressions. CI runs the core suite on all supported versions.
* Archive checks require all four compiled languages, loader opinion, extension
  JAR and compatibility metadata, and reject research, scratch and cache files.
  Builds record the exact Gradle output path for subsequent verification.

### Fixed

* Verification scripts use the PcodeExecutor constructor and PcodeProgram
  entry point shared by Ghidra 12.1.x and 12.2, so newer pipeline checks compile
  on the full support matrix.
* Recover proven unconditional B/BNOP delay windows, including IRP/NRP,
  parallel companions, multicycle NOPs, ADDKPC, PROT loads and compact
  headers. Targets and predicates are captured before delay work; tail stores
  and interrupt-enable restoration remain in the owning function. Unsafe
  windows are refused without changing annotations, references or explicit
  fallthrough overrides (SPRUFE8B 3.5, 3.10.2, 4.2.6).
* CALLP runs parallel companions before writing its A3/B3 link and links to
  the next execute packet. Mixed-width native instruction stepping retains
  a Ghidra delay-context limitation; listing p-code is tested directly.
* Correct compact stack offsets, signed five-bit MVK, narrow-store widths,
  operand display, absolute five-bit move registers, fixed low comparison
  destinations and unscaled NDW offset/indirect addresses
  (SPRUFE8B C-9/C-11/C-16, D-7/D-9/D-10, G-1/G-2/G-4, MVK/STB/STH).
* Updating loads capture addresses before base modification and preserve
  distinct E1 pointer and E5 data writes when registers alias
  (SPRUFE8B 4.2.5/Table 4-10). Constant-copy recovery follows the corrected
  full32 move primitives.
* Schedule ROTL result writes in E2 and MPYLI pair writes simultaneously in
  E4, with E1 operand capture, E1-only .M occupancy and conflicting write-port
  refusals (SPRUFE8B pp. 344–345, 414–415, 3.8.2).
* Schedule BDEC/BPOS from the raw predicate/counter decision through five
  delay cycles, with gated E1 decrement and cross-path hazards
  (SPRUFE8B pp. 159–160, 170–171).
* Prune only proved-impossible loading exits and predicate paths, retaining
  E1 snapshots, delayed counter visibility, unit checks and pending-return
  guards. Prove dominated constant suffixes across closed earlier control
  flow; reject invalid counted-loop ILC accesses (SPRUFE8B 3.5, 3.8.8,
  7.4.3, 7.9.7).
* Correct MVD E4 timing, SPLOOPW counter preservation and delayed predicate
  sampling, displacement-BNOP restart recognition and compact NOP counts
  (SPRUFE8B MVD pipeline, 7.7–7.10, 7.14, Appendix H).
* Resume normal post-loop dispatch at the SPKERNEL execution delay without
  an inferred six-cycle frontend refill. Refuse buffered missed X-path/AMR
  stalls while retaining program-memory stalls
  (SPRUFE8B p. 481, 7.9.4, 7.12, 7.15.2).
* Reject conflicting multicycle NOP generators before context priming or
  pipeline issue; preserve equal counts and whole execute-packet prefix timing
  (SPRUFE8B 3.5, 3.8.10, 3.8.11.5, 4.2.6).

## 1.0.4 - 2026-10-27

### Fixed
* Exact single-precision arithmetic and shared DP-to-SP rounding use equivalent
  mask selections instead of internal p-code branch trees. This preserves
  rounding modes, special values and sticky status flags while allowing large
  float-heavy functions to decompile within the same timeout. Add alias,
  predication and branch-count regressions, and repair affected fixture lookup
  for the predicated decoder constructors.
* Repair generated switch overrides left on a former function after body
  recovery. Code-verified cases are rehomed or retained outside function
  namespaces without deleting labels; detached duplicates no longer crash
  the decompiler. Correct override ownership checks also avoid rewriting
  unchanged tables on repeated analysis.
* Computed branch references no longer retain the intermediate signed `MVK`
  value when an adjacent, unconditional `MVKH` proves the final target.
  Predicated writes, same-execute-packet writes and alternate entries remain
  conservative. Synthetic reference tests cover both endian modes.
* Builds reject an explicitly configured JDK older than Ghidra's declared
  minimum, with a clear error before SLEIGH starts. JDK discovery reads
  `application.java.min` and handles missing JDKs without silently exiting.

### Added
* Read-only closed caller-continuation traces retain captured STW E3 effects
  through an immutable caller window and export the exit PC/E1 hazards.
  Ordinary function scheduling keeps its pending-return refusal.
* `C6000RepairSwitchOverrides.java` repairs legacy switch metadata on a copy.
  `C6000UseAnalysisLanguage.java` prepares a reading copy with concise float
  p-code, keeping the default language available for detailed semantic checks.

## 1.0.3 - 2026-10-27

### Added
* Ghidra 12.2 release and CI builds using JDK 25. The build script selects the
  JDK version required by the chosen Ghidra installation.

### Fixed
* Late branch analysis walks loaded, initialized memory instead of a min/max
  address range, avoiding exceptions when ELF metadata occupies another
  address space.
* A predicated register `B` (`src2`, `IRP`, `NRP`) or `BNOP`, and `SWE` /
  `SWENR`, no longer make the decompiler fail the whole function with "Bad
  relative branch" when it cannot resolve the indirect jump: they skip to
  `inst_next` instead of a label after `goto [x]`
  (`predicated-register-branch.py`, `C6000PredicatedBranchTest.java`).
* Predicated `B IRP` and `B NRP` decode; they decoded as `B` through `B6` / `B7`.
* `B IRP` restores GIE from PGIE and `B NRP` sets NMIE.

## 1.0.2 - 2026-10-13

### Added
* `C6000JumpTableAnalyzer` recovers the TI compiler's switch dispatch
  (guarded `LDW` from an `MVK`/`MVKH` table, then `B`/`BNOP` through the
  entry), recovering bounded case targets and their function ownership when
  Ghidra's decompiler cannot infer the table bounds.
* CI builds and smoke-tests the extension against Ghidra 12.1.4 as well as
  12.1.3, and uploads one zip per version.

### Fixed
* The CI artifact no longer contains the Ghidra release, JDK and scratch
  directories that the workflow unpacked into the workspace. It was about
  920 MB; the extension itself is about 1 MB.
* A 32-bit `BNOP` in a header-based (compact) fetch packet scaled its
  displacement by four instead of two, sending its CFG edge into the middle
  of an instruction.
* `B` calls whose delay slots set `B3` are modelled as returning calls: the
  register form (`B reg` after `MVKL`/`MVKH`), the `MVK`/`MVKH` return-address
  form, and unconditional immediate calls, which previously had no
  fall-through and left their delay slots and the code after the return
  point undecoded.
* Predicated `B` calls are recognised in the compiler's if/else call-pair
  form, with the other arm in the delay slots and `B3` set before the branch.
  Ambiguous overlapping-branch schedules remain conservative.
* In a "call Y if p, else jump to X" pair only the call arm is a call; the
  jump arm (a register arm is always the call; otherwise the nearer target)
  stays a conditional jump, so the local else-block is no longer made a
  function.
* Register calls get their `MVK`/`MVKH` target reference in far more cases:
  the look-back now decodes undecoded delay slots and pointer-typed code
  words, follows register moves, skips oppositely predicated writes, and is
  retried when preceding code is discovered. Targets loaded from memory or
  supplied by another routine may remain unresolved.
* Ghidra's heuristic non-returning-function discovery is disabled for the
  C6000 languages. It marked returning functions no-return because a call's
  delay slots and return point are not decoded until the call is
  recognised, then cleared code needed to establish their fall-through.

### Documentation
* The README is now a short overview (install, quick start, features and
  limitations, build, testing). Verification guidance and test fixtures moved to
  `docs/verification.md`, packet, delay-slot, branch and ABI internals to
  `docs/internals.md`, and the detailed limitations (including the
  software-loop model) to `docs/limitations.md`.
* Added `CONTRIBUTING.md` and a "wrong decode or semantics" issue template.
* The ELF loader opinion is documented as matching little-endian files only.

## 1.0.0 - 2026-09-25

First public release.

### Added
* `C6000:LE:32:default` and `C6000:BE:32:default` SLEIGH languages for the
  TMS320C674x DSP and, by subsetting, the C64x, C64x+, C67x and C67x+ parts.
* `C6000:LE:32:analysis` and `C6000:BE:32:analysis` variants with native
  single-precision p-code and an opaque status userop, for reading
  float-heavy code.
* Broad 32-bit instruction decode generated from the SPRUFE8B section 3.12
  opcode tables, with unresolved encodings left undefined for investigation.
* Compact 16-bit instruction decode driven by the fetch-packet header word,
  covering supported forms in SPRUFE8B appendices C.4, D.4, E.4, F.4,
  G.3 and H.4; unsupported halfwords remain undefined.
* The context fields are declared `noflow`. Without that attribute a compact
  slot reached by fall-through inherits the preceding instruction's decode
  parameters and is decoded as a 32-bit instruction.
* Modelled p-code semantics for the integer ALU, immediate construction,
  scalar loads and stores, single-precision floating point arithmetic and
  conversions, branches and calls; other decoded instructions lift to an
  explicit userop rather than to silently wrong data flow.
* `C6000PacketAnalyzer` and `C6000PacketContext`, which prime the decode
  context from compact fetch-packet headers before disassembly.
* ELF loader opinion mapping `EM_TI_C6000` (140) to the language.
* C6000 compiler spec implementing the TI C6000 calling convention.
* `C6000CorpusTest.java` corpus/regression script and a GNU-objdump oracle
  harness, plus GitHub Actions CI that builds against Ghidra 12.x and runs the
  tests.
* `tools/gen_fid.py`, which generates Function ID databases from a TI
  run-time library built with the TI C6000 code generation tools.

### Fixed
* `DPINT` and `DPTRUNC` now read a double-precision register pair and perform
  FADCR-aware integer conversion, including ties-to-even and warning bits.
* `SPINT` and `SPTRUNC` now use the `.L1`/`.L2` FADCR rounding mode and update
  conversion warning bits, including exceptional inputs. `SPINT` no longer
  lifts to an unimplemented-operation placeholder.
* `NORM` now distinguishes 32-bit and 40-bit sources, counts the 40-bit sign
  width correctly, and `SUBU` writes its signed 40-bit result to a register
  pair. Both have executable p-code instead of placeholders.
* Compact fetch-packet headers now decode as `CPKT` instead of selecting a
  conflicting 32-bit opcode before predicate validation.
* Signed immediates and `ADDKPC` operands use their documented fields; .L-unit
  five-bit constants use bits 22..18. Both directions of 32-bit `MVC` now move
  between general and named control registers, including `FADCR` and `FMCR`.
* Immediate exports carry a four-byte width, so Ghidra's constant-propagation
  analyzers no longer receive zero-width p-code operands.
* The register forms of `CLR`, `EXT`, `EXTU` and `SET` display their packed
  `src1` operand and lift the manual's bit-field operation; previously they
  showed two immediate fields from the sibling encoding.
* Packet-context priming is safe to repeat on a disassembled image, and the
  headless corpus test reports actual p-code placeholders and unknown slots,
  including Ghidra's one-byte `BAD-Instruction` rows.
* `.D` arithmetic units now use the `s` bit, while short load/store units use
  `y`; long load/store forms execute on `.D2`. Memory offsets are scaled by
  access size, and pre/post addressing modes update the base register after the
  transfer, preserving the old store source when it is also the base register.
* Scalar stores now read their data source from bits 27..23 instead of the
  base-register field at bits 22..18. Doubleword load/store operands display
  register pairs in 32-bit and compact formats; nonaligned doubleword address
  offsets follow their encoded scaled/nonscaled `sc` bit. Odd pair selectors
  in 32-bit aligned doubleword forms remain undefined.
* The TI manual's grouped `LDB(U)` and `LDH(U)` headings now produce separate
  signed and unsigned load encodings. The previous table parse attached their
  layouts to the preceding mnemonics and could display `LDW` words as `INTSPU`.
  Generation now rejects memory diagrams under nonmemory mnemonics and any
  unconstrained opcode-map field.
* CI's synthetic image test scans its actual 48-byte size and checks that all
  12 instructions decode.
* Doubleword loads and stores now lift 64-bit transfers through overlapping
  odd:even register pairs in both endian modes, including compact stack forms.
  The common 16-bit integer multiplies and 16-by-32 `MPYLI` also lift to
  p-code; immediate multiply operands are signed five-bit values.
* `BDEC` and `BPOS` now show their signed fetch-packet-relative target and
  lift conditional branch behavior. Compact register `BNOP` branches through
  its register; compact `MVC` to `ILC` and common `EXT`/`EXTU` forms lift to
  data-flow p-code.
* Selected double-precision conversions, addition, multiplication and
  comparisons now use pair operands and floating-point p-code. `MVD` lifts
  its register copy; pipeline timing and floating-point status side effects
  remain outside the p-code model.
* `SUBC`, `ROTL` and `LMBD` lift their documented integer operations.
  Nonaligned word loads and stores use word-scaled offsets; nonaligned
  doubleword transfers retain doubleword scaling.
* `MPYLHU` and `PACK2` now lift their unsigned halfword multiply and
  halfword packing operations.
* The reverse cross-path forms of `SUBDP` now display the architectural
  source order and lift 64-bit subtraction. `MPY32` and its mixed-sign and
  unsigned pair forms, `MPYHL`/`MPYLH` halfword forms, `MPYI`, and `PACKL4`
  now lift their documented integer operations.

### Notes
* `buildExtension` does not compile SLEIGH. `tools/build.sh` (and CI) run
  `support/sleigh` first and verify that the produced zip contains the `.sla`
  files; without them the zip installs cleanly and then fails at import with
  "Unsupported language".
* Ghidra 12.1.3 has a defect in `GhidraSourceBundle.tryBuild`: a `javac`
  diagnostic with a null source turns the whole script-directory build into a
  `NullPointerException`, which is reported as the misleading
  `Failed to get OSGi bundle containing script`. If every Java script in a
  script directory suddenly stops loading, look for a compile error in a
  sibling `.java` file.
