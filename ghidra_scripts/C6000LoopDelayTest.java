// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Import the assembled tests/fixtures/loop-delay.s as a raw binary at 0x1000.

import java.util.ArrayList;
import java.util.List;

import c6000.C6000LoopBuffer;
import c6000.C6000PacketContext;
import c6000.C6000LoopBuffer.Cycle;
import c6000.C6000LoopBuffer.Operation;
import c6000.C6000LoopBuffer.Origin;
import c6000.C6000LoopBuffer.ReplayResult;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class C6000LoopDelayTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		Address base = currentProgram.getAddressFactory().getDefaultAddressSpace()
			.getAddress(0x1000);
		C6000PacketContext.prime(currentProgram, monitor);
		for (int offset = 0; offset < 0x80; offset += 4) {
			disassemble(base.add(offset));
		}
		check(base, 0, 0x0c, "BNOP", 3);
		check(base, 0x14, 0x24, "ADDKPC", 3);
		check(base, 0x2c, 0x3c, "BNOP", 3);
		check(base, 0x60, 0x70, "LDW", 4);
		for (int count = 1; count <= 9; count++) {
			Address at = base.add(0xa0 + (count - 1) * 4);
			disassemble(at);
			Instruction nop = getInstructionAt(at);
			if (nop == null || !nop.getMnemonicString().equals("NOP") ||
				nop.getScalar(0) == null ||
				nop.getScalar(0).getUnsignedValue() != count - 1) {
				throw new AssertionError("wrong NOP count at " + at);
			}
		}
		println("C6000_LOOP_DELAY PASS loops=4 nopCounts=1..9 delayCycles=3/4");
	}

	private void check(Address base, int startOffset, int kernelOffset,
			String delayedMnemonic, int idleCycles) throws Exception {
		Instruction start = getInstructionAt(base.add(startOffset));
		Instruction kernel = getInstructionAt(base.add(kernelOffset));
		if (start == null || kernel == null ||
			!start.getMnemonicString().contains("SPLOOP") ||
			!kernel.getMnemonicString().contains("SPKERNEL")) {
			throw new AssertionError("fixture did not decode at " + base.add(startOffset));
		}
		C6000LoopBuffer loop = C6000LoopBuffer.fromProgram(currentProgram,
			start, kernel);
		if (loop.initiationInterval() != 2 ||
			loop.dynamicLength() != idleCycles + 3 ||
			loop.protectedLoadCount() != (delayedMnemonic.equals("LDW") ? 1 : 0) ||
			loop.sourcePackets() != 3) {
			throw new AssertionError("wrong source timing at " + start.getMinAddress());
		}
		List<Cycle> normal = new ArrayList<>();
		ReplayResult first = loop.replayCountedDetailed(2, 16, normal::add);
		List<Cycle> restarted = new ArrayList<>();
		ReplayResult second = loop.replayCountedRestart(2, 16, restarted::add,
			cycle -> false);
		if (first.cycles != idleCycles + 5 ||
			second.cycles != idleCycles + 5 ||
			normal.size() != idleCycles + 5 ||
			restarted.size() != idleCycles + 5) {
			throw new AssertionError("wrong replay duration at " + start.getMinAddress());
		}
		assertIssue(normal.get(0), delayedMnemonic, false);
		assertIssue(restarted.get(0), delayedMnemonic, true);
		for (int cycle = 1; cycle <= idleCycles; cycle++) {
			if (!normal.get(cycle).operations.isEmpty() ||
				!restarted.get(cycle).operations.isEmpty()) {
				throw new AssertionError("delay NOP missing at cycle " + cycle);
			}
		}
		for (List<Cycle> trace : List.of(normal, restarted)) {
			int nextSourceCycle = idleCycles + 1;
			if (trace.get(nextSourceCycle).operations.size() != 1 ||
				trace.get(nextSourceCycle).operations.get(0).sourceCycle !=
					nextSourceCycle ||
				trace.get(nextSourceCycle).operations.get(0).origin != Origin.PROGRAM ||
				trace.get(nextSourceCycle + 2).operations.size() != 1 ||
				trace.get(nextSourceCycle + 2).operations.get(0).sourceCycle !=
					nextSourceCycle ||
				trace.get(nextSourceCycle + 2).operations.get(0).origin != Origin.BUFFER) {
				throw new AssertionError("buffer issue shifted by delay");
			}
		}
	}

	private static void assertIssue(Cycle cycle, String name, boolean idleOnly) {
		if (cycle.operations.size() != 1) {
			throw new AssertionError("wrong delay source issue count");
		}
		Operation op = cycle.operations.get(0);
		if (!op.instruction.getMnemonicString().contains(name) ||
			op.origin != Origin.PROGRAM || op.idleOnly != idleOnly) {
			throw new AssertionError("wrong restart effect for " + name);
		}
	}
}
