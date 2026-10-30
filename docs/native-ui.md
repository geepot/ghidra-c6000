# Native CodeBrowser tools

The extension has two layers. Processor languages, the ABI, analyzers and dynamic
p-code injection are native Ghidra extension components and work without the GUI
plugin. `C6000Plugin` adds CodeBrowser actions and a dockable inspector; it calls
those Java APIs directly and does not execute scripts or load JSON manifests.

## Enable the tools

Install the extension and restart Ghidra. In CodeBrowser, use **File → Configure →
Configure All Plugins**, find **C6000Plugin** / **C6000 processor tools**, and enable
it. Save the tool configuration to retain that choice. Open **Analysis → C6000 →
Processor Tools**. Ghidra manages the provider's docking layout and action key bindings.

The panel follows the active program and cursor. It shows the language, cross-path
stall selection, floating-point model, current instruction, fetch packet, function
and exact-schedule state. Actions are unavailable for non-C6000 programs and invalid
locations. The entry and scheduling actions also appear in the Listing and
Decompiler context menus. Immutable program views allow inspection, preview and
validation; entry setup, activation and disable require an editable program.

Language selection remains part of the standard import workflow. Use `c67x` or
`c67x-analysis` for C67x/C67x+ timing; `default` and `analysis` retain C64x/C674x
cross-path stalls. The concise variants approximate floating-point flags and special
rounding. The decoder remains a shared superset, and C66x-specific instructions
remain a [known gap](limitations.md#processor-families).

Internal decoder context and scheduler registers are hidden through the processor
specification, rather than changing the user's Listing options. Ghidra's **Display
Hidden Registers** setting can expose them for debugging. Architectural registers
remain available normally.

## Start a raw image

1. Import with the correct language, byte order and base address.
2. Place the Listing cursor at an executable entry instruction.
3. Choose **C6000 → Set Entry Point Here**.

The cancellable background command primes packet context, disassembles, creates an
entry function and registers the entry point. It uses the normal analyzer pipeline.
It refuses defined data, packet headers, delay-slot interiors and another function's
interior instead of clearing existing code or stealing ownership. Cancellation and
failure roll back; successful setup supports Undo.

The compact-packet byte analyzer processes the changed fetch packets supplied by
Ghidra, rather than rescanning the whole program on every byte event. A change to a
header or slot covers that whole fetch packet. Truncated imports with no complete
header still receive ordinary-instruction context. Adjacent or sparse imported
memory blocks can share a packet, including a header split across blocks. Context
is written only at initialized addresses.

## Review and enable exact scheduling

Select a function, then choose **Review Exact Schedule...**. Provide:

- Evidence that all incoming instruction effects and transfers have completed.
  A function boundary or ABI alone is insufficient.
- Any GPRs written in the preceding E1 cycle, separated by spaces or commas.
  Empty means none.
- The initialized source-byte range supporting that evidence. Addresses are
  hexadecimal and the end is inclusive. Cover whole 32-byte fetch packets, up to
  64 KiB. The default is the entry's fetch packet; select setup or caller bytes instead when they support the assumption.

**Preview schedule** is read-only. It checks the supported phases, declared function
ownership and the pinned entry evidence. For incomplete ownership, finish normal
analysis/disassembly and inspect the function body before previewing again. The GUI
never silently adopts another function's instructions or guesses an entry contract.
Preview refuses physical functional-unit and memory-transfer-path conflicts,
even when the instructions have mutually exclusive predicates.
Compilation is cancellable between scheduler states. Editing any input invalidates
the preview; Cancel closes the dialog without recording a review. Existing review
inputs are restored when reopening the form, but still require a fresh preview.
Reviews with multiple evidence ranges must be renewed through their API/batch
workflow so every source assumption is preserved.

After checking the preview, choose **Enable reviewed schedule**. A native analysis
worker suspends auto-analysis, revalidates the exact preview and commits its review
and activation in one undoable transaction. Byte edits, language changes, context,
ownership or reference changes can invalidate a preview. Refusal leaves no partial
activation. The contract persists in the program database and is checked by the
normal decompiler injection library.

**Validate Exact Schedule** checks an enabled review without changing the program.
A stale binding is also refused during decompilation. Re-preview and explicitly
enable a fresh review after relevant changes. The panel clears operation results
when the current function or program changes, or the program is edited. A background
validation result is displayed only for the function and program version it checked.

**Disable Exact Schedule...** explicitly restores ordinary instruction lifting and
removes that function's review and observation/call contracts. It preserves function
ownership, comments and references, and supports Undo. Ordinary lifting does not
model the same packet parallelism or delayed effects. A stale review is never
automatically disabled.

## Framework integration and verification

| Component | Ghidra integration |
| --- | --- |
| Processor definitions | `.ldefs`, `.pspec`, `.cspec`, ELF opinion and compiled SLEIGH |
| Automatic recovery | Discovered `AbstractAnalyzer` implementations with native analysis priorities |
| Native tools | Released `ProgramPlugin`, `ProgramContextAction`, dockable `ComponentProviderAdapter` |
| Long operations | Native cancellable tasks, background commands and `AnalysisWorker` |
| Program changes | Transactions, source-bound reviews, native Undo/Redo and database persistence |
| Lifecycle | Program activation/location events, debounced domain listeners and disposal cleanup |
| Help | Packaged JavaHelp topic, table of contents and action help locations |

Run the [normal regression suite](verification.md), then test the exact archive in
an isolated, headed CodeBrowser:

```sh
python3 tools/verify_gui.py --archive /absolute/path/to/C6000.zip
# Linux without a desktop:
xvfb-run -a python3 tools/verify_gui.py --archive /absolute/path/to/C6000.zip
```

The GUI runner creates a temporary Ghidra installation, user home, tool and project
containing generated LE/BE fixtures. It does not open the user's projects. It checks
class discovery, analyzer-driven entry setup, real dialog preview/activation, stale
source refusal, cancelled/edited previews, renewal inputs, disable confirmations,
native Undo/Redo, immutable database views, program database reopening,
tool configuration restore, program switching and plugin disposal. It also checks
ordinary, activated and disabled schedules through the real Decompiler provider,
including actions from its context. It requires a
clean framework error log as well as completion assertions. Screenshots and logs are
retained under `scratch/verify-gui-*`.

Scripts remain available for headless/batch workflows, fixture execution and research
traces. Closed-call scope construction and post-return observation contracts remain
advanced APIs; this GUI does not infer those contracts or replace their review rules.
Ordinary GUI preview refuses functions carrying those advanced contracts, rather than
renewing assumptions that the form cannot display. Their existing activation can
still be validated or explicitly disabled from the native panel.

Fixture-only `*Test.java` scripts and the `tests/` tree stay in the repository and
are excluded from release archives, keeping Script Manager focused on user tools.
The public `C6000CorpusTest.java` audit remains shipped. Verification uses the
repository's explicit script path.
