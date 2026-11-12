// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check jumps preempted by a return or call in a tests/fixtures/preempted-jump.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class C6000PreemptedJumpTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x1080L, 0x1000L, 0x10a0L, 0x1100L, 0x1140L,
		0x1180L, 0x11c0L, 0x1200L, 0x1220L, 0x1280L, 0x1298L };
	private static final String[] NAMES = { "callee", "padret", "padtail", "padcode",
		"padother", "padwritten", "padshort", "padleak", "padcall", "padentry", "padinside" };
	private int checks;

	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x1000L));
			C6000PacketContext.prime(currentProgram, monitor);
			for (int i = 0; i < ENTRIES.length; i++) {
				disassemble(toAddr(ENTRIES[i]));
				createFunction(toAddr(ENTRIES[i]), NAMES[i]);
			}
			// A stale analysis override (its preemption never held) and a user override.
			override(0x1104L, SourceType.ANALYSIS);
			override(0x11c4L, SourceType.USER_DEFINED);
			return;
		}
		// The jump continues into its window; the return's window ends where the jump lands.
		continues(0x1004L, 0x1008L, 0x1030L);
		window(0x100cL, 4, FlowOverride.RETURN);
		// The fall-through return now owns the NOPs the jump targeted.
		window(0x1024L, 3, FlowOverride.RETURN);
		returns(0x1000L, "0x111", "0x333");
		// No fall-through: the window is decoded once the jump continues.
		continues(0x10a0L, 0x10a4L, 0x10bcL);
		window(0x10a8L, 3, FlowOverride.RETURN);
		returns(0x10a0L, "0x333");
		// Known-bads: the jump keeps its target.
		for (long at : new long[] { 0x1104L, 0x1148L, 0x1184L, 0x1204L, 0x1228L }) keeps(at);
		// padentry: a function entry in the return's window leaves the cut unproven, so nothing changes.
		keeps(0x1284L);
		// A user's override stands.
		Instruction user = getInstructionAt(toAddr(0x11c4L));
		if (java.util.Arrays.stream(user.getReferencesFrom()).noneMatch(r -> r.isPrimary() &&
				r.getReferenceType() == RefType.JUMP_OVERRIDE_UNCONDITIONAL && r.getSource() == SourceType.USER_DEFINED)) {
			throw new AssertionError("user override at " + user.getAddress() + " removed");
		}
		checks++;
		// padleak's return keeps its straight-line window: cut at the landing it would drop ADDK 0x22.
		window(0x120cL, 3, FlowOverride.RETURN);
		// A call does not continue the jump: one fall-through cannot hold its return past the landing and its not-taken path.
		Instruction call2 = getInstructionAt(toAddr(0x1230L));
		if (call2 == null || call2.getFlowType().isCall()) throw new AssertionError("predicated preempting call: " + call2);
		checks++;
		println("C6000_PREEMPTED_JUMP_OK checks=" + checks);
	}

	/** Override the jump's branch to its own fall-through and drop its edge to the target. */
	private void override(long at, SourceType source) throws Exception {
		Instruction jump = getInstructionAt(toAddr(at));
		Address next = jump.getMaxAddress().next().add(jump.getPrototype().getDelaySlotByteCount());
		var references = currentProgram.getReferenceManager();
		for (Reference r : jump.getReferencesFrom()) {
			if (r.getReferenceType().isFlow() && r.getToAddress().equals(jump.getDefaultFlows()[0])) references.delete(r);
		}
		references.setPrimary(references.addMemoryReference(jump.getAddress(), next,
			RefType.JUMP_OVERRIDE_UNCONDITIONAL, source, 0), true);
	}

	/** The jump's branch is overridden to its own fall-through, with no edge to its target. */
	private void continues(long at, long next, long target) {
		Instruction jump = getInstructionAt(toAddr(at));
		if (jump == null || getInstructionAt(toAddr(next)) == null) throw new AssertionError("undecoded at " + toAddr(at));
		Address override = null;
		for (Reference r : jump.getReferencesFrom()) {
			if (r.getReferenceType() == RefType.JUMP_OVERRIDE_UNCONDITIONAL && r.isPrimary()) override = r.getToAddress();
			else if (r.getReferenceType().isFlow() && r.getToAddress().equals(toAddr(target))) {
				throw new AssertionError("jump at " + toAddr(at) + " still flows to " + toAddr(target) + ": " +
					java.util.Arrays.toString(jump.getReferencesFrom()));
			}
		}
		if (!toAddr(next).equals(override)) throw new AssertionError("jump at " + toAddr(at) + " overridden to " + override);
		checks++;
	}

	private void keeps(long at) {
		Instruction jump = getInstructionAt(toAddr(at));
		for (Reference r : jump.getReferencesFrom()) {
			if (r.getReferenceType().isOverride()) throw new AssertionError("known-bad jump at " + toAddr(at) + " overridden");
		}
		if (jump.getFlows().length != 1 || !jump.getFlows()[0].equals(jump.getDefaultFlows()[0])) {
			throw new AssertionError("known-bad jump at " + toAddr(at) + " lost its target");
		}
		checks++;
	}

	private void window(long at, int depth, FlowOverride override) {
		Instruction b = getInstructionAt(toAddr(at));
		if (b == null || b.getDelaySlotDepth() != depth || b.getFlowOverride() != override) {
			throw new AssertionError("window at " + toAddr(at) + ": " + (b == null ? "null" : b + " depth " +
				b.getDelaySlotDepth() + " override " + b.getFlowOverride()));
		}
		checks++;
	}

	private void returns(long entry, String... expected) throws Exception {
		Function f = getFunctionAt(toAddr(entry));
		String name = f.getName();
		var decompiler = new DecompInterface();
		try {
			decompiler.openProgram(currentProgram);
			var result = decompiler.decompileFunction(f, 60, monitor);
			if (result == null || result.getDecompiledFunction() == null) {
				throw new AssertionError("decompile failed: " + (result == null ? "null" : result.getErrorMessage()));
			}
			String c = result.getDecompiledFunction().getC();
			for (String e : expected) if (!c.contains(e)) throw new AssertionError(name + " lacks " + e + ":\n" + c);
			checks++;
		}
		finally {
			decompiler.dispose();
		}
	}
}
