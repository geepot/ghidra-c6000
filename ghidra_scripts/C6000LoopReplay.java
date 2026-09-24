// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Trace the loop containing the cursor, or pass its SPLOOP address as arg 1.
// For counted loops arg 2 is the initial ILC value (default 2). For SPLOOPW,
// arg 2 is the number of predicate samples that remain true (default 2).
// Arg 3 is the maximum number of cycles (default 512). For SPLOOPW, arg 4
// is the initial ILC value (default 0), which is traced but does not govern exit.
// For counted loops, arg 4 is the first cycle with a pending unblocked interrupt.

import java.util.concurrent.atomic.AtomicInteger;

import c6000.C6000LoopBuffer;
import c6000.C6000LoopBuffer.Cycle;
import c6000.C6000LoopBuffer.Operation;
import c6000.C6000LoopBuffer.ReplayResult;
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
		ReplayResult result;
		if (buffer.kind() == C6000LoopBuffer.Kind.SPLOOPW) {
			AtomicInteger samples = new AtomicInteger();
			long initialIlc = args.length > 3 ? Long.decode(args[3]) : 0;
			result = buffer.replayWhileDetailed(initialIlc, limit, this::showCycle,
				() -> samples.getAndIncrement() < count);
		}
		else {
			int interruptAt = args.length > 3 ? Integer.decode(args[3]) :
				Integer.MAX_VALUE;
			result = buffer.replayCountedDetailed(Integer.toUnsignedLong(count),
				limit, this::showCycle, cycle -> cycle >= interruptAt);
		}
		println("C6000_REPLAY_END cycles=" + result.cycles +
			" outcome=" + result.outcome + " ILC=" + result.remainingIlc +
			" postBodyFetch=" + result.firstPostBodyCycle);
	}

	private void showCycle(Cycle cycle) {
		StringBuilder line = new StringBuilder("C6000_CYCLE ").append(cycle.number)
			.append(" LBC=").append(cycle.lbc).append(" ILC=")
			.append(cycle.ilcBefore).append("->").append(cycle.ilcAfter);
		if (cycle.stageBoundary) line.append(" boundary");
		if (cycle.terminatingBoundary) line.append(" terminate");
		if (cycle.interruptBoundary) line.append(" interrupt-drain");
		if (cycle.postBodyFetchEnabled) {
			line.append(" postFetch#").append(cycle.postBodyCycle);
		}
		for (Operation op : cycle.operations) {
			line.append(" | ").append(op.origin).append("#")
				.append(op.iteration).append("@")
				.append(op.instruction.getMinAddress()).append(":")
				.append(op.instruction.getMnemonicString());
		}
		println(line.toString());
	}
}
