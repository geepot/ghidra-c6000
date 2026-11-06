// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check B calls returning to earlier caller code in a tests/fixtures/idle-call.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class C6000IdleCallTest extends GhidraScript {
	private static final long RUN = 0x1100L;
	private static final long[] ENTRIES = { RUN, 0x1000L, 0x1020L, 0x1040L, 0x1060L, 0x1080L, 0x10c0L, 0x10e0L,
		0x1140L, 0x1160L, 0x1180L, 0x1200L };
	private static final String[] NAMES = { "run", "idle", "loopmid", "tail", "other", "jlocal", "stale", "pred",
		"regcall", "callp", "bnop", "regref" };

	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x1000L));
			C6000PacketContext.prime(currentProgram, monitor);
			for (int i = 0; i < ENTRIES.length; i++) {
				disassemble(toAddr(ENTRIES[i]));
				createFunction(toAddr(ENTRIES[i]), NAMES[i]);
			}
			// regref's B with its target known, as a resolved computed branch's would be.
			currentProgram.getReferenceManager().addMemoryReference(toAddr(0x1208L), toAddr(RUN),
				RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0);
			return;
		}
		// Known-bads: B3 untouched, B3 an earlier call's link, B3 another function, a local target, a predicated B.
		notCall(0x1044L, true);
		notCall(0x10d4L, true);
		notCall(0x1064L, false);
		notCall(0x1084L, false);
		Instruction pred = getInstructionAt(toAddr(0x10e8L));
		if (pred == null || toAddr(0x10e4L).equals(pred.getFallThrough())) {
			throw new AssertionError("predicated B at 0x10e8 loses its not-taken path: " + describe(pred));
		}
		// A register B has no native window under a CALL override: lifted with its slots, never past them.
		Instruction arg = getInstructionAt(toAddr(0x114cL));
		if (arg == null || !arg.isInDelaySlot()) {
			throw new AssertionError("register B at 0x1148 bypasses its slots: " + describe(getInstructionAt(toAddr(0x1148L))));
		}
		// With its target known, still no call returning to regref.
		Instruction known = getInstructionAt(toAddr(0x1208L));
		if (known == null || toAddr(0x1200L).equals(known.getFallThrough())) {
			throw new AssertionError("register B at 0x1208 returns to 0x1200: " + describe(known));
		}
		// Known-good: B3 set to earlier caller code is a call with its full window, returning there.
		call(0x1004L, 0x1000L, 0x1000L, 0x101cL, 0x100cL);
		call(0x1028L, 0x1024L, 0x1020L, 0x1038L, 0x1030L);
		call(0x109cL, 0x1080L, 0x1080L, 0x10a4L, 0x10a0L);
		// CALLP and BNOP 5 leave no delay slots, so the B3 writes after them are fresh.
		call(0x1168L, 0x1164L, 0x1160L, 0x1178L, 0x116cL);
		call(0x118cL, 0x1180L, 0x1180L, 0x1194L, 0x1190L);
		println("C6000_IDLE_CALL_OK checks=12");
	}

	/** A returning call to run whose fall-through is ret and whose window, owned by the caller, ends before end. */
	private void call(long at, long ret, long caller, long end, long slot) {
		Instruction b = getInstructionAt(toAddr(at));
		if (b == null || !b.getFlowType().isCall() || b.getFlowType().isTerminal() ||
			!toAddr(ret).equals(b.getFallThrough()) || !callsRun(b)) {
			throw new AssertionError("call at " + toAddr(at) + ": " + describe(b));
		}
		Instruction last = getInstructionContaining(toAddr(end - 1));
		Instruction s = getInstructionAt(toAddr(slot));
		Function f = getFunctionContaining(toAddr(slot));
		if (last == null || !last.isInDelaySlot() || s == null || !s.isInDelaySlot() ||
			f == null || !f.getEntryPoint().equals(toAddr(caller))) {
			throw new AssertionError("window of " + toAddr(at) + " to " + toAddr(end) + ": slot " + s +
				" function " + f + ", last " + last + "; " + describe(b));
		}
	}

	/** Not a returning call; a tail call keeps no fall-through and calls run. */
	private void notCall(long at, boolean tail) {
		Instruction b = getInstructionAt(toAddr(at));
		if (b == null || (b.getFlowType().isCall() && !b.getFlowType().isTerminal()) ||
			(tail && (b.getFallThrough() != null || !callsRun(b)))) {
			throw new AssertionError((tail ? "tail call" : "jump") + " at " + toAddr(at) + ": " + describe(b));
		}
	}

	private boolean callsRun(Instruction b) {
		for (Reference r : b.getReferencesFrom()) {
			if (r.getReferenceType().isCall() && r.getToAddress().equals(toAddr(RUN))) return true;
		}
		return false;
	}

	private static String describe(Instruction i) {
		if (i == null) return "null";
		StringBuilder refs = new StringBuilder();
		for (Reference r : i.getReferencesFrom()) refs.append(' ').append(r.getReferenceType()).append(':').append(r.getToAddress());
		return i + " flow=" + i.getFlowType() + " override=" + i.getFlowOverride() + " fallthrough=" +
			i.getFallThrough() + " depth=" + i.getDelaySlotDepth() + " refs=" + refs;
	}
}
