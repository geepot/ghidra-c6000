<!-- SPDX-License-Identifier: Apache-2.0 -->
# Proved execute-packet completion

Ordinary analysis now completes physically parallel peers in both full-width and
compact code. The analyzer retains the historical `C6000 Compact Packet Tails`
option name, its default enablement and its analysis priority, so saved options
still apply. A known instruction with p=1 proves that the following physical slot
belongs to the same execute packet. A branch alone does not prove every later slot
in its fetch packet is code. The old speculative compact-tail walk is removed.

`C6000ParallelPeers` is the shared read-only proof used by the analyzer and
`C6000RecoverParallelPeers.java`. The reviewed script retains its source/manifest/
report hashes, explicit apply mode and annotation audit. The analyzer uses a
bounded physical window, validates the complete chain before insertion, and
creates only undefined instruction units. Each execute packet is all or nothing:
every peer is checked again before the first write, and a mismatch after a write
clears only that packet's new peers and is logged. The analyzer never ends its
transaction uncommitted, which would abort the enclosing auto-analysis transaction.
Cancellation propagates instead of becoming an unresolved proof.

The proof checks physical widths, p bits, header fields, complete instruction
ownership, the eight-instruction limit and multicycle-NOP restrictions. Both
stored-context and physically seeded fresh parses must agree in text, width and
canonical native p-code for new instructions. Existing peers can bridge a chain
only with complete, compatible ownership. A partial-owned anchor also refuses.
A later conflict invalidates the entire candidate chain; it cannot leave an
earlier peer partially recovered.

Existing instruction/data overlaps, foreign owners, function entries, stale
context, unsupported p-code and new control-transfer peers refuse. Neither path
clears existing units, changes decode context or expands function bodies. Headers are
skipped, not created. Uniform fill, unproved alternate entries, delay-window
obligations and pointer-data reclassification require separate evidence.
Decodable bytes alone do not justify replacing defined data with instructions.

The pipeline compiler, caller-tail contract, register-write/store phases and
SLEIGH semantics are unchanged. Ordinary callee-only pending-return refusals
remain. Caller-scoped traces continue to carry stores into the actual caller.

## Focused checks

Generate the synthetic fixture with:

```
python3 tests/fixtures/parallel-peers.py IMAGE CASES.json [be]
```

Import at `0x1000` with the matching default C6000 endian language and no automatic
analysis. Run the following independently on fresh imports:

* `C6000ParallelPeersTest.java CASES.json REPORT_DIRECTORY C6000RecoverParallelPeers.java`
* `C6000ParallelPeerAnalyzerTest.java CASES.json OUTPUT_DIRECTORY`

Each covers 24 cases. The reviewed script creates six instructions and verifies
report/review/source guards. The analyzer creates seven, since the script-only
reviewed-bound cut is not an architectural restriction. Both refuse an unrelated
compact p=0 tail, a new control-transfer peer, partial ownership and a data
conflict late in the chain. The analyzer also checks unchanged original
instructions/references, comments, labels, function metadata/bodies and decode
context, idempotence and cancellation. A separate overlay-space case verifies that
the default-space proof never inserts instructions into an overlay. No
follow-through instruction is created.

The release runner's `peer-cancel.py` / `C6000PeerCancelTest.java` cancels the
analyzer at each of its cancellation checks in turn, inside a transaction that
stands in for auto-analysis, and requires that transaction to keep its earlier work.

These checks target listing discovery, not a new ISA or silicon qualification.
TI architecture basis: SPRUFE8B sections 3.5 and 3.10.2/3.10.4.
