# Changelog

## Unreleased

### Fixed
* A 32-bit `BNOP` in a header-based (compact) fetch packet scaled its
  displacement by four instead of two, sending its CFG edge into the middle
  of an instruction.
* `B` calls whose delay slots set `B3` are modelled as returning calls: the
  register form (`B reg` after `MVKL`/`MVKH`), the `MVK`/`MVKH` return-address
  form, and unconditional immediate calls, which previously had no
  fall-through and left their delay slots and the code after the return
  point undecoded.
* Ghidra's heuristic non-returning-function discovery is disabled for the
  C6000 languages. It marked returning functions no-return because a call's
  delay slots and return point are not decoded until the call is
  recognised, then cleared that code; 203 calls on the CDJ-2000NXS DSP lost
  their fall-through this way.

### Documentation
* The README is now a short overview (install, quick start, features and
  limitations, build, testing). Measured coverage and test fixtures moved to
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
  covering most observed forms in SPRUFE8B appendices C.4, D.4, E.4, F.4,
  G.3 and H.4; unsupported halfwords remain undefined.
* The context fields are declared `noflow`. Without that attribute a compact
  slot reached by fall-through inherits the preceding instruction's decode
  parameters and is decoded as a 32-bit instruction; this was the single
  hardest bug in the port and is recorded here deliberately.
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
  between general and named control registers, including the firmware's
  `FADCR` and `FMCR` boot instructions.
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
