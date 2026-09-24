# Changelog

## 1.0.0 - unreleased

First public release.

### Added
* `C6000:LE:32:default` and `C6000:BE:32:default` SLEIGH languages for the
  TMS320C674x DSP and, by subsetting, the C64x, C64x+, C67x and C67x+ parts.
* Complete 32-bit instruction decode generated from the SPRUFE8B section 3.12
  opcode tables: every documented opcode matches, with the correct mnemonic,
  functional-unit suffix, operand list and instruction length.
* Compact 16-bit instruction decode driven by the fetch-packet header word,
  including correct lengths and packet boundaries.
* Modelled p-code semantics for the integer ALU, immediate construction, loads
  and stores, branches and calls; every other instruction lifts to a named
  `c6000_unimpl_<mnemonic>` userop rather than to silently wrong data flow.
* `C6000PacketAnalyzer` and `C6000PacketContext`, which prime the decode
  context from compact fetch-packet headers before disassembly.
* ELF loader opinion mapping `EM_TI_C6000` (140) to the language.
* C6000 compiler spec implementing the TI C6000 calling convention.
* `C6000CorpusTest.java` corpus/regression script and a GNU-objdump oracle
  harness, plus GitHub Actions CI that builds against Ghidra 12.x and runs the
  tests.
* `tools/gen_fid.py`, which generates Function ID databases from a TI
  run-time library built with the TI C6000 code generation tools.

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
