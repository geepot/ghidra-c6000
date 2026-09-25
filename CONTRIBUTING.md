# Contributing

Issues and pull requests are welcome.

## Reporting a wrong decode or wrong semantics

Use the [wrong decode / semantics](https://github.com/geepot/ghidra-c6000/issues/new?template=wrong-decode.md)
issue template. The most useful report has:

- the Ghidra version, extension version and language id (`C6000:LE:32:default`, ...);
- the address and the raw bytes of the whole 32-byte fetch packet (for compact
  code the header word decides how the other words decode);
- what Ghidra shows (listing text, or the p-code / decompiler output) and what
  you expected, with the SPRUFE8B figure, table or section that says so;
- if you have it, the same bytes through GNU `objdump -m tic6x`
  (`objdump -D -b binary -m tic6x --endian=little --adjust-vma=<base> packet.bin`;
  the input must be at least 32 bytes).

Only post bytes you are allowed to share. A single fetch packet is usually
enough; never attach whole firmware images.

## Changing the module

- Cite the SPRUFE8B (or SPRU732J) figure, table or section behind every
  encoding or semantic change, in the code comment and the commit message.
  Never copy code from another disassembler (see [`NOTICE.md`](NOTICE.md));
  binutils and Capstone are oracles only.
- Edit the generators (`tools/gen_*.py`, `tools/build_encodings.py`), not the
  generated `.sinc` files, which say so in their first line.
- Add a fixture under `tests/fixtures/` and a `ghidra_scripts/C6000*Test.java`
  check for new semantics, covering both endian modes.
- Run `tools/build.sh` before opening a PR, and say in the PR which checks you
  ran. [docs/verification.md](docs/verification.md) shows how to run the corpus
  test and the GNU oracle comparisons.
- Add a line to [`CHANGELOG.md`](CHANGELOG.md) under *Unreleased*.
- Do not commit firmware, TI manuals or text extracted from them.

The source layout is described in [docs/internals.md](docs/internals.md#repository-layout).

## Ghidra 12.1.3 script pitfall

If *every* Java script in a script directory suddenly fails with
`Failed to get OSGi bundle containing script`, look for a **compile error in a
sibling `.java` file**. Ghidra compiles a script directory as one OSGi bundle,
and `GhidraSourceBundle.tryBuild` dereferences a `javac` diagnostic whose source
is null (Ghidra 12.1.3, `GhidraSourceBundle.java:843`), so the whole build dies
with a `NullPointerException` that is reported as that misleading message, while
the console `PrintWriter` is never flushed. Keep independently-buildable scripts
in separate `-scriptPath` directories.
