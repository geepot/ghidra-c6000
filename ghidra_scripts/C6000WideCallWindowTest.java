// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check B calls with 47 and 40 instructions in their windows in a tests/fixtures/wide-call-window.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;

public class C6000WideCallWindowTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x1000L));
			C6000PacketContext.prime(currentProgram, monitor);
			for (long at : new long[] { 0x1000L, 0x10e0L, 0x1100L }) disassemble(toAddr(at));
			createFunction(toAddr(0x1000L), "wide");
			createFunction(toAddr(0x10e0L), "callee");
			createFunction(toAddr(0x1100L), "wide40");
			return;
		}
		// The rest of the branch's packet plus five full packets: 47 slots (SPRUFE8B 3.5, 4.2.6).
		call(0x1000L, 0x10bcL, 0x10c0L);
		// The branch alone in its packet: 40 slots, and the return in the caller is classified.
		call(0x1104L, 0x11a4L, 0x11a8L);
		Instruction ret = getInstructionAt(toAddr(0x11b0L));
		if (ret == null || !ret.getFlowType().isTerminal() || getFunctionContaining(toAddr(0x11b0L)) == null ||
			!getFunctionContaining(toAddr(0x11b0L)).getEntryPoint().equals(toAddr(0x1100L))) {
			throw new AssertionError("return at 0x11b0: " + describe(ret));
		}
		println("C6000_WIDE_CALL_WINDOW_OK checks=3");
	}

	private void call(long at, long lastSlot, long returnTo) {
		Instruction b = getInstructionAt(toAddr(at));
		Instruction last = getInstructionAt(toAddr(lastSlot));
		if (b == null || !b.getFlowType().isCall() || b.getFlowType().isTerminal() ||
			!toAddr(returnTo).equals(b.getFallThrough()) || last == null || !last.isInDelaySlot()) {
			throw new AssertionError("call at " + toAddr(at) + ": " + describe(b) + "; last slot " + last);
		}
	}

	private static String describe(Instruction i) {
		return i == null ? "null" : i + " flow=" + i.getFlowType() + " override=" + i.getFlowOverride() +
			" fallthrough=" + i.getFallThrough() + " depth=" + i.getDelaySlotDepth();
	}
}
