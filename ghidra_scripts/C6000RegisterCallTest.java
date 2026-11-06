// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check register-target B calls in a tests/fixtures/register-call.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;

public class C6000RegisterCallTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x1000L, 0x1040L, 0x1080L, 0x10a0L, 0x10e0L };
	private static final String[] NAMES = { "rcall", "rknown", "rtail", "rpred", "sink" };

	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x1000L));
			C6000PacketContext.prime(currentProgram, monitor);
			for (int i = 0; i < ENTRIES.length; i++) {
				disassemble(toAddr(ENTRIES[i]));
				createFunction(toAddr(ENTRIES[i]), NAMES[i]);
			}
			return;
		}
		// Known-good: the call reads its target at E1 and transfers after its window, so the
		// argument and B3 writes in the slots precede the CALLIND (SPRUFE8B 4.2.6, B).
		call(0x1004L, 0x1000L, 0x101cL, null, new String[] { "A4", "B4", "B3" });
		call(0x104cL, 0x1040L, 0x1058L, 0x10e0L, new String[] { "A4", "B3" });
		// Predicated: the not-taken path also continues at 0x10c4, after the slots.
		call(0x10b0L, 0x10a0L, 0x10c4L, 0x10e0L, new String[] { "A4", "B3" });
		if (!skipsTo(getInstructionAt(toAddr(0x10b0L)), 0x10c4L)) {
			throw new AssertionError("not-taken path of 0x10b0: " + describe(getInstructionAt(toAddr(0x10b0L))));
		}
		// Known-bad: B3 untouched is not a returning call.
		Instruction tail = getInstructionAt(toAddr(0x1088L));
		if (tail == null || (tail.getFlowType().isCall() && !tail.getFlowType().isTerminal()) ||
			tail.getFallThrough() != null) {
			throw new AssertionError("tail transfer at 0x1088: " + describe(tail));
		}
		println("C6000_REGISTER_CALL_OK checks=5");
	}

	/** A returning call after its window, owned by caller, whose CALLIND follows every write to slotWrites. */
	private void call(long at, long caller, long ret, Long callee, String[] slotWrites) {
		Instruction b = getInstructionAt(toAddr(at));
		if (b == null || !b.getFlowType().isCall() || b.getFlowType().isTerminal() ||
			!toAddr(ret).equals(b.getFallThrough()) || (callee != null && !calls(b, callee))) {
			throw new AssertionError("call at " + toAddr(at) + ": " + describe(b));
		}
		for (Address slot = b.getMaxAddress().next(); slot.compareTo(toAddr(ret)) < 0; slot = slot.add(4)) {
			Instruction s = getInstructionAt(slot);
			Function f = getFunctionContaining(slot);
			if (s == null || !s.isInDelaySlot() || f == null || !f.getEntryPoint().equals(toAddr(caller))) {
				throw new AssertionError("slot " + slot + " of " + toAddr(at) + ": " + s + " in " + f + "; " + describe(b));
			}
		}
		PcodeOp[] ops = b.getPcode(true);
		int callAt = -1;
		for (int i = 0; i < ops.length; i++) if (ops[i].getOpcode() == PcodeOp.CALLIND) callAt = i;
		for (String name : slotWrites) {
			var register = currentProgram.getRegister(name);
			boolean written = false;
			for (int i = 0; i < ops.length; i++) {
				Varnode out = ops[i].getOutput();
				if (out == null || !out.isRegister() || out.getOffset() != register.getOffset()) continue;
				written = true;
				if (callAt < 0 || i > callAt) {
					throw new AssertionError(name + " written after the call at " + toAddr(at) + ": " + describe(b));
				}
			}
			if (!written) throw new AssertionError(name + " not written before the call at " + toAddr(at) + ": " + describe(b));
		}
	}

	/** A CBRANCH to ret before the CALLIND: the not-taken path. */
	private boolean skipsTo(Instruction b, long ret) {
		for (PcodeOp op : b.getPcode(true)) {
			if (op.getOpcode() == PcodeOp.CALLIND) return false;
			if (op.getOpcode() == PcodeOp.CBRANCH && op.getInput(0).isAddress() &&
				op.getInput(0).getOffset() == ret) return true;
		}
		return false;
	}

	private boolean calls(Instruction b, long target) {
		for (Reference r : b.getReferencesFrom()) {
			if (r.getReferenceType().isCall() && r.getToAddress().equals(toAddr(target))) return true;
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
