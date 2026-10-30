# Verification

Use the release suite to check the current source and packaged extension.
[Release guidance](release.md) records the supported matrix and publishing checks. Individual tests are described in the [fixture catalog](regressions.md).

## Reproducing release verification

Run commands from the repository root. You need Python 3, Ghidra 12.x and its
[required JDK](../README.md#build). Ghidra must also have a native decompiler for your
host; on macOS, follow **Building Native Components** in its `GettingStarted.md` if
necessary. The runner checks this prerequisite.

```sh
# Build and run the core suite in both endian modes.
python3 tools/verify.py --jobs 2

# Include the three additional fixtures that require TI's assembler.
python3 tools/verify.py --with-ti --jobs 2
```

CI runs the core suite on Ghidra 12.1.3, 12.1.4 and 12.2. The additional `--with-ti`
checks cover predicate facts, caller continuations and post-loop dispatch. A requested
run fails if a required tool is missing.

### Tool configuration

| Setting | Purpose |
|---|---|
| `GHIDRA_INSTALL_DIR` or `--ghidra PATH` | Select the Ghidra installation; defaults to Homebrew's installation. |
| `JAVA_HOME` | Select the JDK; otherwise the runner looks for the version required by Ghidra. |
| `TI_C6000_BIN` | Select a C6000 compiler bin directory or `cl6x` executable for `--with-ti`. |
| `GRADLE_USER_HOME` | Select a Gradle cache; defaults to `scratch/build/gradle`. |

The first build needs network access to download Gradle unless its wrapper distribution
is cached. The default TI path is `/Applications/ti/ti-cgt-c6000_8.3.15/bin`.

### Focused checks

```sh
python3 tools/verify.py --list
python3 tools/verify.py --only pipeline-loop --jobs 2
python3 tools/verify.py --only pipeline-loop --endian le
```

Repeat `--only` to select more fixtures. Add `--with-ti` when selecting a TI-assembled
fixture. A focused run verifies only the selected scope.

`--timeout SECONDS` limits each build, generator and headless invocation (default: 600
seconds). Individual native decompiler checks retain their 15- or 30-second limits. Use
`--help` for all options.

## What the suite checks

| Area | Checks |
|---|---|
| Decode and operands | Smoke decode, compact headers and operands, memory forms, comparison destinations and full32 encoding identity. |
| Native flow | Return delays and refusal safety, CALLP companions, direct and predicated branches, delayed calls, target references and switch ownership. |
| Exact packet schedules | Parallel input capture, pending branches, SP/DP writeback and flags, software loops, counters, ROTL, MPYLI, load aliases, closed calls and source-bound native decompilation across separate owners. |
| Floating point | Exact SP selection and rational SP/DP arithmetic expectations, including aliases, predication and rounding modes. |
| Additional TI fixtures | Predicate proofs, caller-continuation contracts, post-loop dispatch and missed-stall refusals. |

Every run builds all four SLEIGH variants and checks the archive's integrity, required
runtime files and Ghidra compatibility metadata. Research, scratch and cache files are
rejected. The runner then installs a copy of that archive into a fresh scratch Ghidra
installation, leaving the configured installation unchanged.

LE and BE have separate user homes and projects. Each fixture is imported at `0x1000`;
flow fixtures use auto-analysis, while semantic fixtures prime packet context explicitly
under `-noanalysis`.

The suite covers release dependencies, rather than every fixture in the repository.
Execution checks generally use the default languages. The `pipeline-c67x` fixture
runs `default`, `analysis`, `c67x` and `c67x-analysis` in both byte orders. It checks
cycle/stall counts and values for both cross paths, predicated writers, incoming
hazards, loads and late DP reads, retains the separate AMR hazard, and exercises
schedule injection, native decompilation, CPU-preserving analysis-language conversion
and rejection of reviews for another language. Eight language
definitions share four compiled SLEIGH files. Additional instruction checks are listed in the
[fixture catalog](regressions.md).

## Headed framework integration

After building, run `python3 tools/verify_gui.py --archive /absolute/path/to/C6000.zip`
in a desktop session, or under `xvfb-run -a` on Linux. This adds a real CodeBrowser
and native-plugin lifecycle check to the headless suite. It opens only generated
fixtures in an isolated project and requires a clean framework error log.
The [native tools guide](native-ui.md#framework-integration-and-verification) describes
the covered workflows and retained screenshots. CI runs this as a separate virtual
display step on every supported Ghidra version; the default local `verify.py` command
remains headless.

## Reading the results

A passing fixture requires a successful process **and** every expected script completion
marker. Ghidra can report a script failure while returning exit status zero, so process
status alone is insufficient. The smoke test also requires zero undecoded slots and no
zero-width p-code operands.

The runner prints `PASS` or `FAIL` for each fixture. Once the checks finish, it prints
`VERIFIED` or `FAILED` and the summary path. Setup and build failures stop earlier with
an error message. Each invocation creates a new `scratch/verify-*` directory containing:

| Evidence | Contents |
|---|---|
| `summary.json` | Commit, worktree status, Ghidra version, commands, results and archive SHA-256. |
| Verified archive | The exact zip tested, retained separately from mutable `dist/` outputs. |
| Build and fixture files | Build logs, generated inputs and manifests, generator/headless logs, and decompiler output where produced. |

For a failure, start with the log named in the summary. Check the requested scope and
endian modes before treating a passing summary as a release check. The
[release checklist](release.md#checklist-before-tagging) defines the full matrix
required before tagging.

## Running the corpus test and oracles

These optional checks use external images or generated encoding samples. Firmware is
never committed, and the release suite does not run it.

### Decode an external image

Use a Ghidra installation containing the extension. To install a build, run
`tools/build.sh --install /path/to/ghidra`. Adjust the image, load base and window
length in this example:

```sh
export GHIDRA_INSTALL_DIR=/path/to/ghidra
export GHIDRA_WORK="$PWD/scratch/corpus"
export _JAVA_OPTIONS="-Duser.home=$GHIDRA_WORK/home"
mkdir -p "$GHIDRA_WORK/home" "$GHIDRA_WORK/proj"

IMAGE=/path/to/image.bin
BASE=0x1000
LENGTH=0x3000

C6000_LISTING="$GHIDRA_WORK/image.listing" \
  "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$GHIDRA_WORK/proj" c6000-corpus \
  -import "$IMAGE" -loader BinaryLoader -loader-baseAddr "$BASE" \
  -processor C6000:LE:32:default -cspec default -noanalysis \
  -scriptPath ghidra_scripts \
  -postScript C6000CorpusTest.java image "$IMAGE" "$BASE" 0 "$LENGTH" \
  -deleteProject
```

The script reports decoded bytes and instructions, compact/header counts, placeholders,
and undecoded slots, including nonfill slots. Set the offset and length to the intended
window; the script rejects a window outside loaded memory. A linear sweep can decode
data and fill as instructions, so its byte coverage is not a measure of executable-code
coverage.

For auto-analysis, use the executable's entry point and load addresses from its file
format or platform documentation. Add `-preScript C6000SetEntry.java ENTRY` before
analysis, or run that script at the entry in the GUI. File offsets are not necessarily
execution addresses.

### Compare with GNU tic6x

For the little-endian image and listing above:

```sh
python3 tools/oracle_compare.py "$IMAGE" "$BASE" "$GHIDRA_WORK/image.listing"
```

This tool requires a GNU `objdump` with tic6x support. It compares addresses, lengths,
mnemonics and functional units; operands and execution semantics require separate
checks. The tool currently invokes GNU in little-endian mode. When running `objdump`
directly, pass `--endian=little` and provide at least one 32-byte fetch packet.

For encoding probes, use `tools/sample_encodings.py` for full32 words (including
`--predicated`) or `tools/sample_compact_encodings.py` for compact halfwords and header
expansions. Decode each generated image with the corpus script, then compare its
listing. `tools/audit_random_oracle.py` and `tools/audit_compact_oracle.py` classify
disagreements against TI's encoding constraints. Illegal encodings are expected in these
samples.

## Interpreting the evidence

Synthetic execution checks, image decode coverage and GNU comparisons measure different
properties. Zero placeholders or unexplained disagreements in a sample does not
establish complete ISA coverage or C674x hardware equivalence. Event userops such as
`c6000_idle` also require an external scheduler; their presence is distinct from
unimplemented-instruction placeholders. See [known limitations](limitations.md) for
model boundaries.
