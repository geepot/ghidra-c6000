// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check tail-call delay slots and B3-setting calls in a tests/fixtures/tail-call-slots.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class C6000TailCallSlotsTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x1000L));
			C6000PacketContext.prime(currentProgram, monitor);
			disassemble(toAddr(0x11c0L));
			// A known no-return callee, as an ELF exit() is.
			createFunction(toAddr(0x11c0L), "exit").setNoReturn(true);
			disassemble(toAddr(0x1300L));
			createFunction(toAddr(0x1300L), "bnop_call");
			return;
		}
		// Tail calls: the delay slots run before the callee and belong to the caller.
		slots(0x1100L, new long[] { 0x1104L, 0x1108L, 0x110cL });
		slots(0x1140L, new long[] { 0x1144L });
		// A register call whose window sets B3 stays a returning call.
		long[][] calls = { { 0x1024L, 0x102cL } };
		for (long[] c : calls) {
			Instruction call = getInstructionAt(toAddr(c[0]));
			if (call == null || !call.getFlowType().isCall() || call.getFlowType().isTerminal() ||
				call.getFallThrough() == null || getInstructionAt(toAddr(c[1])) == null) {
				throw new AssertionError("call at " + toAddr(c[0]) + ": " + describe(call));
			}
		}
		// A B whose window sets B3, even past the window end, is a call, not a tail call.
		Instruction past = getInstructionAt(toAddr(0x1248L));
		if (past != null && past.isInDelaySlot()) {
			throw new AssertionError("0x1248 recovered as a tail-call slot of " + describe(getInstructionAt(toAddr(0x1244L))));
		}
		// A BNOP whose B3 already holds its return address is a call, not a tail call.
		Instruction arg = getInstructionAt(toAddr(0x130cL));
		if (arg != null && arg.isInDelaySlot()) {
			throw new AssertionError("0x130c recovered as a tail-call slot of " + describe(getInstructionAt(toAddr(0x1308L))));
		}
		println("C6000_TAIL_CALL_SLOTS_OK");
	}

	private void slots(long entry, long[] slots) {
		Instruction branch = getInstructionAt(toAddr(entry));
		if (branch == null || branch.getFallThrough() != null) {
			throw new AssertionError("tail call at " + toAddr(entry) + ": " + describe(branch));
		}
		for (long slot : slots) {
			Instruction i = getInstructionAt(toAddr(slot));
			Function f = getFunctionContaining(toAddr(slot));
			if (i == null || !i.isInDelaySlot() || f == null || !f.getEntryPoint().equals(toAddr(entry))) {
				throw new AssertionError(toAddr(slot) + ": instruction=" + i + " function=" + f +
					", expected a delay slot of " + toAddr(entry) + "; branch " + describe(branch));
			}
		}
	}

	private static String describe(Instruction i) {
		return i == null ? "null" : i + " flow=" + i.getFlowType() + " override=" + i.getFlowOverride() +
			" fallthrough=" + i.getFallThrough();
	}
}
