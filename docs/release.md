# Release guidance

Release `v1.3.0` widens the little-endian context register to 64 bits (language version
2.0), recovers more calls and delay windows (calls with a parallel companion, wide
windows, tail calls marked `CALL_RETURN`), stops hand-written TI assembly labels from
starting functions, keeps the proven fall-through of conditional jumps whose windows mix
32-bit and compact instructions, extends exact schedules (entry branches, `SAT`,
complementary-predicate writers, self-guarded loop counters), and keeps earlier
auto-analysis work when analysis is cancelled. See the
[changelog](../CHANGELOG.md#130---2026-11-18),
[release limitations](limitations.md#release-111-decompilation-and-round-trips) and
[verification](verification.md).

## Release limitations

Exact timing remains opt-in and source-bound. Default instruction lifting is not a
complete packet-aware emulator. Closed-call scheduling supports up to sixteen
sequential nonrecursive leaf calls; nested calls, arbitrary indirect targets,
memory-restored links and more general caller control flow remain unsupported.
Recovered C can inline helper effects. The 1,056-case `bitstream_flush` result uses
LE emulator execution and TI compilation; it does not prove identical binaries,
portable-C safety, exhaustive correctness or silicon equivalence. Floating-point,
interrupt and exceptional-loop limitations are detailed in [limitations](limitations.md).

## Compatibility and migration

| Item | Value |
|---|---|
| Repository release | `v1.3.0` |
| Ghidra compatibility matrix | 12.1.4 / JDK 21; 12.2 / JDK 25 |
| Language version | 2.0 for all eight definitions (big-endian since issue #31; little-endian since v1.3.0, 64-bit context register) |
| Archive naming | `ghidra_<Ghidra version>_PUBLIC_<build date>_C6000.zip` |
| Extension-property version | Ghidra compatibility version, substituted from `@extversion@` during build |

Keep the `extension.properties` version token. That field identifies the
compatible Ghidra version, rather than the repository release. Each release
archive must match the Ghidra installation used to build it.

Big-endian version 1 programs migrate through `C6000BeDefaultLanguageTranslator` and
`C6000BeAnalysisLanguageTranslator`, which re-decode compact packets. Little-endian
version 1 programs migrate through `data/languages/old/c6000_le_*_v1.trans`, which carry
each context field into the 64-bit context register by name; review their exact
schedules again. Re-run auto-analysis afterwards. Both migrations re-disassemble existing
programs, which can drop an instruction after a delay window that mixes 32-bit and
compact instructions (Ghidra #10242).
Keep a packed backup and annotation inventory before upgrading; existing Bad
Instruction bookmarks may be removed. Preserve and, where required, restore their
recorded addresses, types, categories and comments before saving. See
[language prototype migration](internals.md#language-prototype-migration).

## Release verification

Build from a clean release commit and run the suite for every matrix row:

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
python3 tools/verify.py --ghidra /path/to/ghidra --with-ti --jobs 2
python3 tools/verify_gui.py --ghidra /path/to/ghidra --archive "$(cat build/release-archive-path.txt)"
```

The runner checks 99 core fixture/language imports (three through Ghidra's ELF loader and
one packed program) and seven TI-assembled fixture imports per endian: 212 per Ghidra
version, or 424
across the matrix. The core
count includes all four timing variants for the CPU, resource and delayed-call-timing fixtures. Native
decompiler checks retain their 15/30-second limits. Run the headed checks in a
desktop session, or prefix the GUI command with `xvfb-run -a` on Linux. CI runs the
core suite and headed checks for every matrix row without the proprietary TI
assembler.

Also run the focused checks for features outside the runner's registry:

| Feature | Fixture | Ghidra test |
|---|---|---|
| Reviewed parallel-peer recovery | `parallel-peers.py` | `C6000ParallelPeersTest.java` |
| Ordinary execute-packet completion | `parallel-peers.py` | `C6000ParallelPeerAnalyzerTest.java` |

Run each on a fresh import in both endian modes. The complete release check
therefore adds four focused imports per matrix row: 432 total imports across the
two-version matrix, plus eight Python release-tool tests and the separate headed
checks. Contracts and invocation
arguments are documented in [caller-tail traces](caller-tail-traces.md),
[reviewed peer recovery](recover-parallel-peers.md) and
[execute-packet completion](execute-packet-recovery.md).

Retain each `summary.json`, logs and the exact tested archive. Reports record
the commit and archive SHA-256. If source changes after verification, repeat
the affected checks and build release assets from the final commit.

## Checklist before tagging

- Confirm the release scope, date its changelog entry and commit the changes.
- Complete the unit tests, full compatibility matrix and focused checks above.
- For target-specific changes, run the optional corpus/oracle checks on
  representative inputs and record the load base, window and tool versions.
- Require a clean working tree and passing CI for the release commit.
- Retain the verified archive for each Ghidra version and generate `SHA256SUMS`.
- Create the annotated release tag at that same commit and push it with the
  release branch.
- Publish the GitHub release with the two matching archives, checksums,
  upgrade notes and links to the changelog and verification results.

## Checking release assets

To validate an archive without installing it:

```sh
python3 tools/check_archive.py dist/ghidra_12.2_PUBLIC_YYYYMMDD_C6000.zip --ghidra-version 12.2
```

The build records its exact Gradle task output in
`$GHIDRA_WORK/archive-path.txt`; verification preserves a copy and records its
SHA-256. Select that output rather than another zip left in `dist/`. Check
the uploaded asset names, sizes and SHA-256 digests against the local files
before considering publication complete.
