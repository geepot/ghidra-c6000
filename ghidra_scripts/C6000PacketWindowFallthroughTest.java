// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check the fall-through of windowed conditional jumps in a tests/fixtures/packet-window-fallthrough.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;

public class C6000PacketWindowFallthroughTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			C6000PacketContext.prime(currentProgram, monitor);
			for (long at : new long[] { 0x1000L, 0x1020L }) {
				currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(at));
				disassemble(toAddr(at));
				createFunction(toAddr(at), at == 0x1000L ? "peer" : "mixed");
			}
			return;
		}
		// The packet primer's two-byte window: the ADD in the jump's own execute packet.
		jump(0x1000L, 2, 0x1006L);
		// The proved 10-byte window: MVK, ADD (32-bit) and NOP 3 (compact).
		jump(0x1020L, 10, 0x102eL);
		println("C6000_PACKET_WINDOW_FALLTHROUGH_OK checks=4");
	}

	private void jump(long at, int window, long next) {
		Instruction b = getInstructionAt(toAddr(at));
		if (b == null || !b.getFlowType().isConditional() || !b.getFlowType().isJump() ||
			b.getPrototype().getDelaySlotByteCount() != window || !toAddr(next).equals(b.getFallThrough())) {
			throw new AssertionError("jump at " + toAddr(at) + ": " + (b == null ? "null" : b + " flow=" +
				b.getFlowType() + " window=" + b.getPrototype().getDelaySlotByteCount() + " fallthrough=" +
				b.getFallThrough() + " expected " + toAddr(next)));
		}
		// The function keeps every slot of the window, though the fall-through now skips them.
		var owner = getFunctionContaining(toAddr(at));
		if (owner == null || !owner.getBody().contains(toAddr(at), toAddr(next - 1))) {
			throw new AssertionError("window " + toAddr(at) + "-" + toAddr(next - 1) + " outside its function: " +
				(owner == null ? "none" : owner.getBody()));
		}
	}
}
