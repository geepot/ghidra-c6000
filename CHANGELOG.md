# Changelog

## 1.0.0 - unreleased

First public release.

### Added
* `C6000:LE:32:default` and `C6000:BE:32:default` SLEIGH languages for the
  TMS320C674x DSP and, by subsetting, the C64x, C64x+, C67x and C67x+ parts.
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
