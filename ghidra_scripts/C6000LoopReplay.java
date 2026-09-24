// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Trace the loop containing the cursor, or pass its SPLOOP address as arg 1.
// For counted loops arg 2 is the initial ILC value (default 2). For SPLOOPW,
// arg 2 is the number of predicate samples that remain true (default 2).
// Arg 3 is the maximum number of cycles (default 512).

import java.util.concurrent.atomic.AtomicInteger;

import c6000.C6000LoopBuffer;
import c6000.C6000LoopBuffer.Cycle;
import c6000.C6000LoopBuffer.Operation;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class C6000LoopReplay extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		Address address = args.length > 0 ? toAddr(Long.decode(args[0])) : currentAddress;
		if (address == null) throw new IllegalArgumentException("select a SPLOOP instruction");
		Instruction start = currentProgram.getListing().getInstructionAt(address);
		if (start == null || !start.getMnemonicString().contains("SPLOOP")) {
			throw new IllegalArgumentException("not a SPLOOP instruction: " + address);
		}
		Instruction kernel = currentProgram.getListing().getInstructionAfter(address);
		while (kernel != null && kernel.getMinAddress().subtract(address) <= 1024 &&
				!kernel.getMnemonicString().contains("SPKERNEL")) {
			kernel = currentProgram.getListing().getInstructionAfter(kernel.getMinAddress());
		}
		if (kernel == null || kernel.getMinAddress().subtract(address) > 1024) {
			throw new IllegalArgumentException("no SPKERNEL found for " + address);
		}
		C6000LoopBuffer buffer = C6000LoopBuffer.fromProgram(currentProgram, start, kernel);
		int count = args.length > 1 ? Integer.decode(args[1]) : 2;
		int limit = args.length > 2 ? Integer.decode(args[2]) : 512;
		println("C6000_REPLAY " + address + " " + buffer.kind() + " ii=" +
			buffer.initiationInterval() + " dynlen=" + buffer.dynamicLength() +
			" packets=" + buffer.sourcePackets());
		if (buffer.kind() == C6000LoopBuffer.Kind.SPLOOPW) {
			AtomicInteger samples = new AtomicInteger();
			buffer.replayWhile(limit, this::showCycle,
				() -> samples.getAndIncrement() < count);
		}
		else {
			buffer.replayCounted(Integer.toUnsignedLong(count), limit, this::showCycle);
		}
	}

	private void showCycle(Cycle cycle) {
		StringBuilder line = new StringBuilder("C6000_CYCLE ").append(cycle.number)
			.append(" LBC=").append(cycle.lbc).append(" ILC=")
			.append(cycle.ilcBefore).append("->").append(cycle.ilcAfter);
		if (cycle.stageBoundary) line.append(" boundary");
		if (cycle.terminatingBoundary) line.append(" terminate");
		for (Operation op : cycle.operations) {
			line.append(" | ").append(op.origin).append("#")
				.append(op.iteration).append("@")
				.append(op.instruction.getMinAddress()).append(":")
				.append(op.instruction.getMnemonicString());
		}
		println(line.toString());
	}
}
