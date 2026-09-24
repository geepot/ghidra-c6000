// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Validate loop source extraction and cycle scheduling over an imported image.

import java.util.concurrent.atomic.AtomicInteger;
import java.util.HexFormat;

import c6000.C6000LoopBuffer;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class C6000LoopModelTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		int parsed = 0;
		int skipped = 0;
		int unsupported = 0;
		int replayed = 0;
		InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction start = instructions.next();
			if (!start.getMnemonicString().contains("SPLOOP")) continue;
			Instruction kernel = currentProgram.getListing().getInstructionAfter(start.getMinAddress());
			while (kernel != null &&
					kernel.getMinAddress().subtract(start.getMinAddress()) <= 1024 &&
					!kernel.getMnemonicString().contains("SPKERNEL")) {
				kernel = currentProgram.getListing().getInstructionAfter(kernel.getMinAddress());
			}
			if (kernel == null || kernel.getMinAddress().subtract(start.getMinAddress()) > 1024) {
				throw new AssertionError("unpaired loop at " + start.getMinAddress());
			}
			try {
				C6000LoopBuffer buffer = C6000LoopBuffer.fromProgram(
					currentProgram, start, kernel);
				parsed++;
				int ii = buffer.initiationInterval();
				int dynlen = buffer.dynamicLength();
				if (buffer.kind() == C6000LoopBuffer.Kind.SPLOOPW) {
					AtomicInteger samples = new AtomicInteger();
					int cycles = buffer.replayWhile(5, 512, cycle -> {
						long expectedBefore = (5L - cycle.number / ii) & 0xffffffffL;
						long expectedAfter = (expectedBefore - (cycle.stageBoundary ? 1 : 0)) &
							0xffffffffL;
						if (cycle.lbc != cycle.number % ii ||
							cycle.ilcBefore != expectedBefore || cycle.ilcAfter != expectedAfter) {
							throw new AssertionError("bad SPLOOPW cycle at " + start.getMinAddress());
						}
					}, () -> samples.getAndIncrement() < 2 * ii);
					if (cycles < ii) throw new AssertionError("SPLOOPW exited too early");
				}
				else {
					int first = buffer.kind() == C6000LoopBuffer.Kind.SPLOOP ? 2 :
						2 + (3 / ii) + 1;
					// If SPKERNEL precedes a stage boundary, the buffer
					// emits NOP cycles through that boundary before exit.
					int expected = Math.max(dynlen, ii) + (first - 1) * ii;
					int cycles = buffer.replayCounted(2, 512, cycle -> {
						if (cycle.lbc != cycle.number % ii || cycle.ilcAfter > cycle.ilcBefore) {
							throw new AssertionError("bad ILC/LBC at " + start.getMinAddress());
						}
					});
					if (cycles != expected) {
						throw new AssertionError("bad duration at " + start.getMinAddress() +
							": " + cycles + " != " + expected);
					}
					int zeroExpected = buffer.kind() == C6000LoopBuffer.Kind.SPLOOP ?
						dynlen : Math.max(dynlen, ii) + (3 / ii) * ii;
					int zeroCycles = buffer.replayCounted(0, 512, cycle -> {
						if (buffer.kind() == C6000LoopBuffer.Kind.SPLOOP) {
							for (C6000LoopBuffer.Operation op : cycle.operations) {
								if (op.origin == C6000LoopBuffer.Origin.BUFFER) {
									throw new AssertionError("zero ILC replayed buffer at " +
										start.getMinAddress());
								}
							}
						}
					});
					if (zeroCycles != zeroExpected) {
						throw new AssertionError("bad zero-ILC duration at " +
							start.getMinAddress() + ": " + zeroCycles + " != " + zeroExpected);
					}
				}
				replayed++;
			}
			catch (IllegalArgumentException e) {
				// The listing can contain a partially decoded source packet.
				if (skipped++ < 32) println("C6000_MODEL_SKIP " + start.getMinAddress() +
					" " + e.getMessage() + gapDetail(e.getMessage()));
			}
			catch (UnsupportedOperationException e) {
				if (unsupported++ < 8) println("C6000_MODEL_UNSUPPORTED " +
					start.getMinAddress() + " " + e.getMessage());
			}
		}
		println("C6000_MODEL parsed=" + parsed + " replayed=" + replayed +
			" skipped=" + skipped + " unsupported=" + unsupported);
	}

	private String gapDetail(String message) throws Exception {
		String prefix = "undecoded bytes after ";
		if (!message.startsWith(prefix)) return "";
		Instruction previous = currentProgram.getListing().getInstructionAt(
			currentProgram.getAddressFactory().getAddress(message.substring(prefix.length())));
		if (previous == null) return "";
		Instruction next = currentProgram.getListing().getInstructionAfter(previous.getMinAddress());
		if (next == null) return "";
		int gap = (int) next.getMinAddress().subtract(previous.getMaxAddress()) - 1;
		byte[] bytes = new byte[Math.min(gap, 16)];
		if (bytes.length > 0) currentProgram.getMemory().getBytes(
			previous.getMaxAddress().next(), bytes);
		return " gap=" + gap + " bytes=" + HexFormat.of().formatHex(bytes) +
			" next=" + next;
	}
}
