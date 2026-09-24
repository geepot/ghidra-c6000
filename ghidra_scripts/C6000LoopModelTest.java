// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Validate loop source extraction and cycle scheduling over an imported image.

import java.util.concurrent.atomic.AtomicInteger;
import java.util.HexFormat;
import java.util.List;

import c6000.C6000LoopBuffer;
import c6000.C6000LoopBuffer.ReplayResult;
import c6000.C6000LoopBuffer.Outcome;
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
		int whileInterruptExits = 0;
		Instruction maskProbe = null;
		InstructionIterator maskInstructions = currentProgram.getListing().getInstructions(true);
		while (maskInstructions.hasNext()) {
			Instruction candidate = maskInstructions.next();
			if (candidate.getMnemonicString().equals("SPMASK") &&
				candidate.getScalar(0) != null &&
				candidate.getScalar(0).getUnsignedValue() != 0) {
				maskProbe = candidate;
				break;
			}
		}
		final Instruction overlayMask = maskProbe;
		AtomicInteger maskedOverlays = new AtomicInteger();
		AtomicInteger maskedSourceOps = new AtomicInteger();
		AtomicInteger restartBufferOpsThroughMask = new AtomicInteger();
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
				if (!buffer.interruptReturnPacket().equals(start.getMinAddress())) {
					throw new AssertionError("wrong interrupt return packet");
				}
				parsed++;
				int ii = buffer.initiationInterval();
				int dynlen = buffer.dynamicLength();
				if (buffer.kind() == C6000LoopBuffer.Kind.SPLOOPW) {
					AtomicInteger samples = new AtomicInteger();
					ReplayResult result = buffer.replayWhileDetailed(5, 512, cycle -> {
						for (C6000LoopBuffer.Operation op : cycle.operations) {
							if (op.origin == C6000LoopBuffer.Origin.PROGRAM &&
								(unitBit(op.instruction.getMnemonicString()) &
									buffer.sourceMaskAt(op.sourceCycle)) != 0) {
								maskedSourceOps.incrementAndGet();
							}
						}
						long expectedBefore = (5L - cycle.number / ii) & 0xffffffffL;
						long expectedAfter = (expectedBefore - (cycle.stageBoundary ? 1 : 0)) &
							0xffffffffL;
						if (cycle.postBodyFetchEnabled ||
							cycle.lbc != cycle.number % ii ||
							cycle.ilcBefore != expectedBefore || cycle.ilcAfter != expectedAfter) {
							throw new AssertionError("bad SPLOOPW cycle at " + start.getMinAddress());
						}
					}, () -> samples.getAndIncrement() < 2 * ii);
					if (result.outcome != Outcome.COMPLETE || result.cycles < ii ||
						result.firstPostBodyCycle != result.cycles) {
						throw new AssertionError("bad SPLOOPW exit");
					}
					AtomicInteger interruptAt = new AtomicInteger(-1);
					ReplayResult drained = buffer.replayWhileDetailed(5, 512, cycle -> {
						if (cycle.interruptBoundary) {
							if (!interruptAt.compareAndSet(-1, cycle.number) ||
								!cycle.stageBoundary || cycle.number < 3 ||
								cycle.number < ((dynlen + ii - 1) / ii) * ii - 1) {
								throw new AssertionError("bad SPLOOPW interrupt boundary");
							}
						}
						if (cycle.postBodyFetchEnabled || cycle.terminatingBoundary) {
							throw new AssertionError("bad SPLOOPW interrupt drain");
						}
					}, () -> true, cycle -> true);
					if (drained.outcome != Outcome.INTERRUPT_DRAINED ||
						interruptAt.get() < 0 || drained.firstPostBodyCycle != -1) {
						throw new AssertionError("bad SPLOOPW interrupt result");
					}
					C6000LoopBuffer.InterruptHandoff whileHandoff =
						buffer.interruptHandoff(drained);
					if (!whileHandoff.returnPacket.equals(start.getMinAddress()) ||
						whileHandoff.ilc != drained.remainingIlc ||
						!whileHandoff.savedSplx) {
						throw new AssertionError("bad SPLOOPW interrupt handoff");
					}
					AtomicInteger earlyInterrupt = new AtomicInteger(-1);
					ReplayResult exitedDuringDrain = buffer.replayWhileDetailed(5, 512,
						cycle -> {
							if (cycle.interruptBoundary) earlyInterrupt.set(cycle.number);
						}, () -> earlyInterrupt.get() < 0, cycle -> true);
					if (exitedDuringDrain.outcome == Outcome.INTERRUPT_AT_POST_BODY) {
						whileInterruptExits++;
						if (exitedDuringDrain.firstPostBodyCycle != exitedDuringDrain.cycles) {
							throw new AssertionError("bad post-body interrupt target");
						}
					}
					else if (exitedDuringDrain.outcome != Outcome.INTERRUPT_DRAINED) {
						throw new AssertionError("bad SPLOOPW drain outcome");
					}
					AtomicInteger restartedSamples = new AtomicInteger();
					ReplayResult restarted = buffer.replayWhileRestart(whileHandoff.ilc, 512,
						cycle -> checkRestartMasks(buffer, cycle,
							restartBufferOpsThroughMask),
						() -> restartedSamples.getAndIncrement() < 2 * ii,
						cycle -> false);
					if (restarted.outcome != Outcome.COMPLETE ||
						restarted.cycles != result.cycles) {
						throw new AssertionError("bad SPLOOPW restart at " +
							start.getMinAddress());
					}
				}
				else {
					int first = buffer.kind() == C6000LoopBuffer.Kind.SPLOOP ? 2 :
						2 + (3 / ii) + 1;
					// If SPKERNEL precedes a stage boundary, the buffer
					// emits NOP cycles through that boundary before exit.
					int expected = Math.max(dynlen, ii) + (first - 1) * ii;
					AtomicInteger firstFetch = new AtomicInteger(-1);
					ReplayResult result = buffer.replayCountedDetailed(2, 512, cycle -> {
						for (C6000LoopBuffer.Operation op : cycle.operations) {
							if (op.origin == C6000LoopBuffer.Origin.PROGRAM &&
								(unitBit(op.instruction.getMnemonicString()) &
									buffer.sourceMaskAt(op.sourceCycle)) != 0) {
								maskedSourceOps.incrementAndGet();
							}
						}
						if (cycle.lbc != cycle.number % ii || cycle.ilcAfter > cycle.ilcBefore) {
							throw new AssertionError("bad ILC/LBC at " + start.getMinAddress());
						}
						if (cycle.postBodyFetchEnabled) {
							firstFetch.compareAndSet(-1, cycle.number);
							if (cycle.postBodyCycle != cycle.number - firstFetch.get()) {
								throw new AssertionError("bad post-body fetch index");
							}
							if (overlayMask != null) {
								int mask = (int) overlayMask.getScalar(0).getUnsignedValue();
								int removed = 0;
								for (C6000LoopBuffer.Operation op : cycle.operations) {
									if (op.origin == C6000LoopBuffer.Origin.BUFFER &&
										(unitBit(op.instruction.getMnemonicString()) & mask) != 0) {
										removed++;
									}
								}
								if (cycle.overlayPostBody(List.of(overlayMask)).size() !=
									cycle.operations.size() - removed) {
									throw new AssertionError("bad SPMASK overlay at " +
										start.getMinAddress());
								}
								if (removed > 0) maskedOverlays.incrementAndGet();
							}
						}
					});
					if (result.outcome != Outcome.COMPLETE || result.cycles != expected) {
						throw new AssertionError("bad duration at " + start.getMinAddress() +
							": " + result.cycles + " != " + expected);
					}
					if (result.firstPostBodyCycle < dynlen ||
						result.firstPostBodyCycle > result.cycles ||
						(firstFetch.get() == -1 ? result.firstPostBodyCycle != result.cycles :
							firstFetch.get() != result.firstPostBodyCycle)) {
						throw new AssertionError("bad post-body fetch at " +
							start.getMinAddress());
					}
					// This firmware loop has SPKERNEL delay=(4 stages, 0 cycles),
					// ii=2 and dynlen=17: fetch resumes at cycle 18 during epilog.
					if (currentProgram.getName().equals("dsp.stage2.payload.bin") &&
						start.getMinAddress().getOffset() == 0xc0003362L &&
						(buffer.fetchDelayCycles() != 8 ||
							result.firstPostBodyCycle != 18 || result.cycles != 23)) {
						throw new AssertionError("bad stage 2 epilog fetch timing");
					}
					int lastLoadingBoundary = ((dynlen + ii - 1) / ii) * ii;
					int zeroExpected = buffer.kind() == C6000LoopBuffer.Kind.SPLOOP ?
						lastLoadingBoundary :
						Math.max(lastLoadingBoundary, dynlen + (3 / ii) * ii);
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
					if (buffer.kind() == C6000LoopBuffer.Kind.SPLOOP) {
						int oneCycles = buffer.replayCounted(1, 512, cycle -> {});
						if (oneCycles != lastLoadingBoundary) {
							throw new AssertionError("bad one-iteration duration at " +
								start.getMinAddress() + ": " + oneCycles + " != " +
								lastLoadingBoundary);
						}
					}
					AtomicInteger interruptAt = new AtomicInteger(-1);
					long[] savedIlc = { -1 };
					ReplayResult drained = buffer.replayCountedDetailed(256, 512, cycle -> {
						if (cycle.interruptBoundary) {
							if (!interruptAt.compareAndSet(-1, cycle.number) ||
								cycle.terminatingBoundary || !cycle.stageBoundary ||
								cycle.number < lastLoadingBoundary - 1 ||
								cycle.ilcBefore < (dynlen + ii - 1) / ii) {
								throw new AssertionError("bad interrupt boundary");
							}
							savedIlc[0] = cycle.ilcAfter;
						}
						if (cycle.postBodyFetchEnabled ||
							(interruptAt.get() >= 0 && cycle.ilcAfter != savedIlc[0])) {
							throw new AssertionError("bad interrupt drain at " +
								start.getMinAddress());
						}
					}, cycle -> true);
					if (drained.outcome != Outcome.INTERRUPT_DRAINED ||
						interruptAt.get() < 0 || drained.firstPostBodyCycle != -1 ||
						drained.remainingIlc != savedIlc[0]) {
						throw new AssertionError("bad interrupt result at " +
							start.getMinAddress());
					}
					C6000LoopBuffer.InterruptHandoff countedHandoff =
						buffer.interruptHandoff(drained);
					if (!countedHandoff.returnPacket.equals(start.getMinAddress()) ||
						countedHandoff.ilc != drained.remainingIlc ||
						!countedHandoff.savedSplx) {
						throw new AssertionError("bad counted interrupt handoff");
					}
					long lowIlc = (dynlen + ii - 1) / ii > 1 ? 1 : 0;
					ReplayResult tooShortToInterrupt = buffer.replayCountedDetailed(
						lowIlc, 512, cycle -> {
							if (cycle.interruptBoundary) {
								throw new AssertionError("early interrupt at " +
									start.getMinAddress());
							}
						}, cycle -> true);
					if (tooShortToInterrupt.outcome != Outcome.COMPLETE) {
						throw new AssertionError("short loop was interrupted");
					}
					ReplayResult restarted = buffer.replayCountedRestart(2, 512,
						cycle -> {
							checkRestartMasks(buffer, cycle,
								restartBufferOpsThroughMask);
							if (cycle.number == 0 && cycle.ilcBefore != 1) {
								throw new AssertionError("restart did not initially decrement ILC");
							}
						}, cycle -> false);
					int restartCycles = ii + Math.max(ii, dynlen);
					if (restarted.outcome != Outcome.COMPLETE ||
						restarted.cycles != restartCycles) {
						throw new AssertionError("bad counted restart at " +
							start.getMinAddress() + ": " + restarted.cycles +
							" != " + restartCycles);
					}
					if (currentProgram.getName().equals("dsp.stage2.payload.bin") &&
						start.getMinAddress().getOffset() == 0xc0003362L) {
						ReplayResult resumed = buffer.replayCountedRestart(
							countedHandoff.ilc, 1024, cycle -> {}, cycle -> false);
						if (resumed.outcome != Outcome.COMPLETE ||
							resumed.cycles != 513 || resumed.firstPostBodyCycle != 506 ||
							resumed.remainingIlc != 0) {
							throw new AssertionError("bad stage 2 interrupt return");
						}
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
			" skipped=" + skipped + " unsupported=" + unsupported +
			" maskOverlays=" + maskedOverlays.get() +
			" whileInterruptExits=" + whileInterruptExits +
			" maskedSourceOps=" + maskedSourceOps.get() +
			" restartBufferOpsThroughMask=" +
			restartBufferOpsThroughMask.get());
	}

	private static void checkRestartMasks(C6000LoopBuffer buffer,
			C6000LoopBuffer.Cycle cycle, AtomicInteger bufferOpsThroughMask) {
		for (C6000LoopBuffer.Operation op : cycle.operations) {
			int mask = buffer.sourceMaskAt(op.origin == C6000LoopBuffer.Origin.PROGRAM ?
				op.sourceCycle : cycle.number);
			if ((unitBit(op.instruction.getMnemonicString()) & mask) == 0) continue;
			if (op.origin == C6000LoopBuffer.Origin.PROGRAM) {
				throw new AssertionError("restart executed SPMASKed program operation");
			}
			bufferOpsThroughMask.incrementAndGet();
		}
	}

	private static int unitBit(String mnemonic) {
		int dot = mnemonic.indexOf('.');
		if (dot < 0 || dot + 2 >= mnemonic.length()) return 0;
		int side = mnemonic.charAt(dot + 2) - '1';
		if (side < 0 || side > 1) return 0;
		switch (mnemonic.charAt(dot + 1)) {
			case 'L': return 1 << side;
			case 'S': return 1 << (side + 2);
			case 'D': return 1 << (side + 4);
			case 'M': return 1 << (side + 6);
			default: return 0;
		}
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
