// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check delay slots and return points of B calls in a tests/fixtures/call-packet-slots.py image.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class C6000CallPacketSlotsTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		// Returning calls, with or without a parallel companion, and the code after each return point.
		long[][] calls = { { 0x1000L, 0x1200L }, { 0x1008L, 0x1100L }, { 0x1010L, 0x1140L }, { 0x1018L, 0x1200L }, { 0x102cL, 0x1200L } };
		for (long[] c : calls) {
			Instruction call = getInstructionAt(toAddr(c[0]));
			if (call == null || !call.getFlowType().isCall() || call.getFlowType().isTerminal() || !calls(call, c[1])) {
				throw new AssertionError("call at " + toAddr(c[0]) + ": " + call +
					(call == null ? "" : " flow=" + call.getFlowType() + " fallthrough=" + call.getFallThrough()));
			}
		}
		owned(0x1000L, new long[] { 0x1004L, 0x1008L, 0x100cL, 0x1010L, 0x1014L, 0x1018L, 0x101cL,
			0x1020L, 0x1024L, 0x1028L, 0x102cL, 0x1030L, 0x1034L, 0x1038L, 0x103cL });
		println("C6000_CALL_PACKET_SLOTS_OK");
	}

	private void owned(long entry, long[] slots) {
		for (long slot : slots) {
			Function f = getFunctionContaining(toAddr(slot));
			if (getInstructionAt(toAddr(slot)) == null || f == null || !f.getEntryPoint().equals(toAddr(entry))) {
				throw new AssertionError(toAddr(slot) + ": instruction=" + getInstructionAt(toAddr(slot)) +
					" function=" + f + ", expected in " + toAddr(entry) + "; branch " + branch(entry));
			}
		}
	}

	private String branch(long entry) {
		Instruction b = getInstructionAt(toAddr(entry));
		return b == null ? "null" : b + " flow=" + b.getFlowType() + " override=" + b.getFlowOverride();
	}

	private static boolean calls(Instruction insn, long target) {
		for (Reference r : insn.getReferencesFrom()) {
			if (r.getReferenceType().isCall() && r.getToAddress().getOffset() == target) return true;
		}
		return false;
	}
}
