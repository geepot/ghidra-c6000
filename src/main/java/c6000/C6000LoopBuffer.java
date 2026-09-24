/* ###
 * Copyright 2026 ghidra-c6000 contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
package c6000;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.IntPredicate;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;

/**
 * Cycle-level schedule of a software-pipelined loop without an artificial PC branch.
 *
 * <p>Each source execute packet is fetched once. On every later iteration its
 * unmasked instructions execute from the loop buffer at the same offset within
 * the initiation interval. A consumer can execute each cycle's operations in
 * an emulator, or inspect the schedule without supplying register/memory state.
 * This models normal load, fetch and drain, interrupt drain, and loop pipe-up
 * after the caller restores saved SPLX and ILC. Handler timing and nested
 * reload require additional architectural state.
 */
public final class C6000LoopBuffer {

	public enum Kind { SPLOOP, SPLOOPD, SPLOOPW }
	public enum Origin { PROGRAM, BUFFER }
	public enum Outcome { COMPLETE, INTERRUPT_DRAINED, INTERRUPT_AT_POST_BODY }

	public static final class Operation {
		public final Instruction instruction;
		public final int sourceCycle;
		public final int iteration;
		public final Origin origin;

		private Operation(Instruction instruction, int sourceCycle, int iteration,
				Origin origin) {
			this.instruction = instruction;
			this.sourceCycle = sourceCycle;
			this.iteration = iteration;
			this.origin = origin;
		}
	}

	public static final class Cycle {
		public final int number;
		public final int lbc;
		public final long ilcBefore;
		public final long ilcAfter;
		public final boolean stageBoundary;
		public final boolean terminatingBoundary;
		public final boolean interruptBoundary;
		public final boolean postBodyFetchEnabled;
		public final int postBodyCycle;
		public final List<Operation> operations;

		private Cycle(int number, int ii, long before, long after,
				boolean terminating, boolean interrupt, int firstPostBodyCycle,
				List<Operation> operations) {
			this.number = number;
			this.lbc = number % ii;
			this.ilcBefore = before;
			this.ilcAfter = after;
			this.stageBoundary = this.lbc == ii - 1;
			this.terminatingBoundary = terminating;
			this.interruptBoundary = interrupt;
			this.postBodyFetchEnabled = firstPostBodyCycle >= 0 &&
				number >= firstPostBodyCycle;
			this.postBodyCycle = postBodyFetchEnabled ? number - firstPostBodyCycle : -1;
			this.operations = Collections.unmodifiableList(operations);
		}

		/**
		 * Combine a fetched post-body execute packet with this buffered cycle.
		 * Operations in the result are simultaneous; list order is for display.
		 * The caller supplies the packet selected by its own PC/branch state.
		 */
		public List<Operation> overlayPostBody(List<Instruction> packet) {
			if (!postBodyFetchEnabled) {
				throw new IllegalStateException("post-body fetch is disabled");
			}
			int mask = 0;
			for (Instruction insn : packet) {
				String name = insn.getMnemonicString();
				if (name.contains("SPMASKR")) {
					throw new UnsupportedOperationException("SPMASKR requires nested reload state");
				}
				if (name.contains("SPMASK")) mask |= scalar(insn) & 0xff;
			}
			List<Operation> merged = new ArrayList<>();
			for (Instruction insn : packet) {
				String name = insn.getMnemonicString();
				if (!name.contains("SPMASK") && !name.equals("CPKT")) {
					merged.add(new Operation(insn, -1, postBodyCycle, Origin.PROGRAM));
				}
			}
			for (Operation op : operations) {
				if (op.origin != Origin.BUFFER ||
					(unitBit(op.instruction.getMnemonicString()) & mask) == 0) {
					merged.add(op);
				}
			}
			return Collections.unmodifiableList(merged);
		}
	}

	/** Loop-buffer completion state; handler entry may await pending register writes. */
	public static final class ReplayResult {
		public final int cycles;
		public final Outcome outcome;
		public final long remainingIlc;
		/** -1 for interrupt drain, when post-body program fetch stays disabled. */
		public final int firstPostBodyCycle;

		private ReplayResult(int cycles, int firstPostBodyCycle,
				Outcome outcome, long remainingIlc) {
			this.cycles = cycles;
			this.firstPostBodyCycle = firstPostBodyCycle;
			this.outcome = outcome;
			this.remainingIlc = remainingIlc;
		}
	}

	/** State handed to the CPU once buffer drain and pending writes complete. */
	public static final class InterruptHandoff {
		public final Address returnPacket;
		public final long ilc;
		public final boolean savedSplx;
		public final int bufferDrainCycles;

		private InterruptHandoff(Address returnPacket, long ilc,
				int bufferDrainCycles) {
			this.returnPacket = returnPacket;
			this.ilc = ilc;
			this.savedSplx = true;
			this.bufferDrainCycles = bufferDrainCycles;
		}
	}

	private static final class SourceCycle {
		final List<Instruction> program;
		final List<Instruction> buffered;
		final int unitMask;

		SourceCycle(List<Instruction> program, List<Instruction> buffered, int unitMask) {
			this.program = program;
			this.buffered = buffered;
			this.unitMask = unitMask;
		}
	}

	private final Kind kind;
	private final int ii;
	private final Address loopStart;
	private final Address bodyStart;
	private final int sourcePackets;
	private final List<SourceCycle> source;
	private final boolean reloadable;
	private final int fetchDelay;

	private C6000LoopBuffer(Kind kind, int ii, Address loopStart, Address bodyStart,
			int sourcePackets, List<SourceCycle> source, boolean reloadable,
			int fetchDelay) {
		this.kind = kind;
		this.ii = ii;
		this.loopStart = loopStart;
		this.bodyStart = bodyStart;
		this.sourcePackets = sourcePackets;
		this.source = source;
		this.reloadable = reloadable;
		this.fetchDelay = fetchDelay;
	}

	public Kind kind() { return kind; }
	public int initiationInterval() { return ii; }
	public int dynamicLength() { return source.size(); }
	/** Unit mask issued by the source packet in this cycle, or zero afterward. */
	public int sourceMaskAt(int cycle) {
		return cycle >= 0 && cycle < source.size() ? source.get(cycle).unitMask : 0;
	}
	public int sourcePackets() { return sourcePackets; }
	public Address bodyStart() { return bodyStart; }
	/** Address of the execute packet to save in IRP/NRP for an interrupted loop. */
	public Address interruptReturnPacket() { return loopStart; }

	/** Build the IRP/NRP and ITSR/NTSR handoff after pipeline writeback. */
	public InterruptHandoff interruptHandoff(ReplayResult result) {
		if (result.outcome != Outcome.INTERRUPT_DRAINED) {
			throw new IllegalArgumentException("loop did not finish interrupt draining");
		}
		return new InterruptHandoff(loopStart, result.remainingIlc, result.cycles);
	}
	public boolean reloadable() { return reloadable; }
	public int fetchDelayCycles() { return fetchDelay; }

	/** Decode complete source execute packets from the instruction after SPLOOP through SPKERNEL. */
	public static C6000LoopBuffer fromProgram(Program program, Instruction start,
			Instruction kernel) throws MemoryAccessException {
		Scalar interval = start.getScalar(0);
		if (interval == null) throw new IllegalArgumentException("SPLOOP has no interval");
		int ii = (int) interval.getUnsignedValue();
		if (ii < 1 || ii > 14) {
			throw new IllegalArgumentException("invalid initiation interval: " + ii);
		}
		String name = start.getMnemonicString();
		Kind kind = name.contains("SPLOOPW") ? Kind.SPLOOPW :
			name.contains("SPLOOPD") ? Kind.SPLOOPD : Kind.SPLOOP;
		Listing listing = program.getListing();
		Instruction cursor = start;
		// SPLOOP is the first instruction in its packet. Parallel instructions
		// execute once in that packet and are not part of the loop body.
		while (parallelWithNext(program, cursor)) {
			cursor = nextExecutable(listing, cursor);
			if (cursor == null || cursor.getMinAddress().compareTo(kernel.getMinAddress()) >= 0) {
				throw new IllegalArgumentException("incomplete SPLOOP execute packet");
			}
		}
		cursor = nextExecutable(listing, cursor);
		if (cursor == null || cursor.getMinAddress().compareTo(kernel.getMinAddress()) > 0) {
			throw new IllegalArgumentException("missing loop body");
		}
		Address bodyStart = cursor.getMinAddress();
		List<SourceCycle> cycles = new ArrayList<>();
		int packets = 0;
		while (cursor != null && cursor.getMinAddress().compareTo(kernel.getMinAddress()) <= 0) {
			List<Instruction> packet = new ArrayList<>();
			boolean reachedKernel = false;
			while (true) {
				packet.add(cursor);
				if (cursor.equals(kernel)) reachedKernel = true;
				boolean parallel = parallelWithNext(program, cursor);
				Instruction next = parallel || !reachedKernel ?
					nextExecutable(listing, cursor) : null;
				if (parallel && (next == null || (!reachedKernel &&
						next.getMinAddress().compareTo(kernel.getMinAddress()) > 0))) {
					throw new IllegalArgumentException("incomplete SPKERNEL execute packet");
				}
				cursor = next;
				if (!parallel) break;
			}
			if (!reachedKernel && (cursor == null || cursor.getMinAddress().compareTo(
					kernel.getMinAddress()) > 0)) {
				throw new IllegalArgumentException("missing SPKERNEL execute packet");
			}
			packets++;
			int mask = 0;
			int duration = 1;
			for (Instruction insn : packet) {
				String mnemonic = insn.getMnemonicString();
				if (mnemonic.contains("SPMASK")) mask |= scalar(insn) & 0xff;
				if (mnemonic.equals("NOP")) duration = Math.max(duration, scalar(insn) + 1);
			}
			List<Instruction> programOps = new ArrayList<>();
			List<Instruction> bufferedOps = new ArrayList<>();
			for (Instruction insn : packet) {
				String mnemonic = insn.getMnemonicString();
				if (mnemonic.contains("SPMASK") || mnemonic.contains("SPKERNEL")) continue;
				programOps.add(insn);
				if ((unitBit(mnemonic) & mask) == 0 && !mnemonic.startsWith("BNOP")) {
					bufferedOps.add(insn);
				}
			}
			cycles.add(new SourceCycle(programOps, bufferedOps, mask));
			for (int i = 1; i < duration; i++) {
				cycles.add(new SourceCycle(List.of(), List.of(), 0));
			}
			if (reachedKernel) break;
		}
		if (cycles.isEmpty() || cycles.size() > 48) {
			throw new IllegalArgumentException("SPLOOP dynlen outside 1..48: " + cycles.size());
		}
		boolean reloadable = kind != Kind.SPLOOPW &&
			(name.startsWith("[") || kernel.getMnemonicString().contains("SPKERNELR"));
		return new C6000LoopBuffer(kind, ii, start.getMinAddress(), bodyStart,
			packets, List.copyOf(cycles),
			reloadable, kernel.getMnemonicString().contains("SPKERNELR") ? 0 :
			fetchDelay(ii, scalar(kernel)));
	}

	private static int fetchDelay(int ii, int encoded) {
		int cycleBits = ii == 1 ? 0 : ii == 2 ? 1 : ii <= 4 ? 2 : ii <= 8 ? 3 : 4;
		int cycle = encoded & ((1 << cycleBits) - 1);
		int stage = 0;
		for (int bit = 0; bit < 6 - cycleBits; bit++) {
			stage |= ((encoded >>> (5 - bit)) & 1) << bit;
		}
		return stage * ii + cycle;
	}

	/**
	 * Replay an ILC-counted loop, reporting the complete prolog, kernel and epilog.
	 * The ILC value is the value after the SPLOOP execute packet; for SPLOOP
	 * pass the value before its initial decrement, which is applied here.
	 */
	public int replayCounted(long initialIlc, int maxCycles, Consumer<Cycle> sink) {
		return replayCountedDetailed(initialIlc, maxCycles, sink).cycles;
	}

	public ReplayResult replayCountedDetailed(long initialIlc, int maxCycles,
			Consumer<Cycle> sink) {
		return replayCountedDetailed(initialIlc, maxCycles, sink, cycle -> false);
	}

	/**
	 * Replay an ILC-counted loop with an enabled, architecturally unblocked
	 * pending-interrupt signal. Interrupt detection is at a stage boundary;
	 * the result ends when buffer draining finishes, before pipeline writeback
	 * and handler entry. Nested reload and restart use a different state path.
	 */
	public ReplayResult replayCountedDetailed(long initialIlc, int maxCycles,
			Consumer<Cycle> sink, IntPredicate pendingInterruptAtCycle) {
		return replayCounted(initialIlc, maxCycles, sink,
			pendingInterruptAtCycle, false);
	}

	/**
	 * Resume an interrupted counted loop after the caller restores ILC and
	 * enters the SPLOOP packet with saved SPLX=1. SPLOOPD then uses SPLOOP's
	 * initial test/decrement, and source SPMASK reverses its pipe-up behavior.
	 */
	public ReplayResult replayCountedRestart(long restoredIlc, int maxCycles,
			Consumer<Cycle> sink, IntPredicate pendingInterruptAtCycle) {
		checkRestartDelays();
		return replayCounted(restoredIlc, maxCycles, sink,
			pendingInterruptAtCycle, true);
	}

	private ReplayResult replayCounted(long initialIlc, int maxCycles,
			Consumer<Cycle> sink, IntPredicate pendingInterruptAtCycle,
			boolean restart) {
		if (kind == Kind.SPLOOPW) throw new IllegalStateException("SPLOOPW uses a predicate");
		if (reloadable) throw new UnsupportedOperationException("nested reload needs RILC and an outer-loop predicate");
		if (initialIlc < 0 || initialIlc > 0xffffffffL || maxCycles < 1) {
			throw new IllegalArgumentException();
		}
		long ilc = initialIlc;
		boolean initiallyZero = (kind == Kind.SPLOOP || restart) && ilc == 0;
		if ((kind == Kind.SPLOOP || restart) && ilc != 0) ilc--;
		int finalIteration = initiallyZero ? -1 : Integer.MAX_VALUE;
		int lastLoadingBoundary = ((source.size() + ii - 1) / ii) * ii - 1;
		int drainEnd = initiallyZero ? lastLoadingBoundary : Integer.MAX_VALUE;
		int firstPostBodyCycle = initiallyZero ? lastLoadingBoundary + 1 :
			Integer.MAX_VALUE;
		boolean interrupted = false;
		int loadingStages = (source.size() + ii - 1) / ii;
		for (int t = 0; t < maxCycles; t++) {
			int iteration = t / ii;
			List<Operation> ops = operationsAt(t, finalIteration, initiallyZero,
				restart);
			long before = ilc;
			boolean terminate = false;
			boolean interrupt = false;
			if ((t + 1) % ii == 0 && !initiallyZero && finalIteration == Integer.MAX_VALUE) {
				// SPLOOPD suppresses the test and decrement for cycles 0..2.
				if (kind != Kind.SPLOOPD || restart || t >= 3) {
					if (ilc != 0 && t >= lastLoadingBoundary &&
						ilc >= loadingStages && pendingInterruptAtCycle.test(t)) {
						interrupt = true;
						interrupted = true;
						finalIteration = iteration;
						drainEnd = Math.max(t, iteration * ii + source.size() - 1);
						firstPostBodyCycle = -1;
					}
					else if (ilc == 0) {
						terminate = true;
						finalIteration = iteration;
						drainEnd = Math.max(t, iteration * ii + source.size() - 1);
						// If the initial invocation has no later iteration, the
						// buffer remains active through its last loading boundary.
						if (iteration == 0) drainEnd = Math.max(drainEnd,
							lastLoadingBoundary);
						// The fetch delay counts from the start of draining,
						// but fetching also waits for the last kernel boundary.
						firstPostBodyCycle = Math.min(drainEnd + 1,
							Math.max(lastLoadingBoundary + 1, t + 1 + fetchDelay));
					}
					else ilc--;
				}
			}
			sink.accept(new Cycle(t, ii, before, ilc, terminate, interrupt,
				firstPostBodyCycle, ops));
			if (t >= drainEnd) return new ReplayResult(t + 1,
				firstPostBodyCycle,
				interrupted ? Outcome.INTERRUPT_DRAINED : Outcome.COMPLETE, ilc);
		}
		throw new IllegalStateException("loop trace exceeds " + maxCycles + " cycles");
	}

	/**
	 * Replay a predicate-terminated SPLOOPW. ILC decrements at every stage
	 * boundary but does not decide termination. The predicate is sampled after the
	 * cycle's operations, three cycles before the corresponding stage boundary.
	 * It must return true while the loop is to continue. SPLOOPW stops without
	 * an epilog when that delayed condition becomes false.
	 */
	public int replayWhile(long initialIlc, int maxCycles, Consumer<Cycle> sink,
			BooleanSupplier continuePredicate) {
		return replayWhileDetailed(initialIlc, maxCycles, sink,
			continuePredicate).cycles;
	}

	public ReplayResult replayWhileDetailed(long initialIlc, int maxCycles,
			Consumer<Cycle> sink, BooleanSupplier continuePredicate) {
		return replayWhileDetailed(initialIlc, maxCycles, sink,
			continuePredicate, cycle -> false);
	}

	/**
	 * SPLOOPW interrupt draining keeps testing the delayed predicate. If the
	 * predicate ends the loop while draining, the next post-body instruction
	 * is the one interrupted, not the buffered loop.
	 */
	public ReplayResult replayWhileDetailed(long initialIlc, int maxCycles,
			Consumer<Cycle> sink, BooleanSupplier continuePredicate,
			IntPredicate pendingInterruptAtCycle) {
		return replayWhile(initialIlc, maxCycles, sink, continuePredicate,
			pendingInterruptAtCycle, false);
	}

	/** Resume an interrupted SPLOOPW after restoring SPLX and ILC. */
	public ReplayResult replayWhileRestart(long restoredIlc, int maxCycles,
			Consumer<Cycle> sink, BooleanSupplier continuePredicate,
			IntPredicate pendingInterruptAtCycle) {
		checkRestartDelays();
		return replayWhile(restoredIlc, maxCycles, sink, continuePredicate,
			pendingInterruptAtCycle, true);
	}

	private ReplayResult replayWhile(long initialIlc, int maxCycles,
			Consumer<Cycle> sink, BooleanSupplier continuePredicate,
			IntPredicate pendingInterruptAtCycle, boolean restart) {
		if (kind != Kind.SPLOOPW) throw new IllegalStateException("not SPLOOPW");
		if (initialIlc < 0 || initialIlc > 0xffffffffL || maxCycles < 1) {
			throw new IllegalArgumentException();
		}
		long ilc = initialIlc;
		boolean[] delayed = new boolean[3];
		int lastLoadingBoundary = ((source.size() + ii - 1) / ii) * ii - 1;
		int finalIteration = Integer.MAX_VALUE;
		int drainEnd = Integer.MAX_VALUE;
		boolean interrupted = false;
		for (int t = 0; t < maxCycles; t++) {
			List<Operation> ops = operationsAt(t, finalIteration, false, restart);
			boolean boundary = (t + 1) % ii == 0;
			boolean terminate = boundary && t >= 3 && !delayed[(t - 3) % 3];
			boolean interrupt = false;
			if (boundary && !terminate && !interrupted && t >= 3 &&
				t >= lastLoadingBoundary && pendingInterruptAtCycle.test(t)) {
				interrupt = true;
				interrupted = true;
				finalIteration = t / ii;
				drainEnd = Math.max(t, finalIteration * ii + source.size() - 1);
			}
			long before = ilc;
			if (boundary) ilc = (ilc - 1) & 0xffffffffL;
			sink.accept(new Cycle(t, ii, before, ilc, terminate, interrupt,
				interrupted ? -1 : Integer.MAX_VALUE, ops));
			if (terminate) return new ReplayResult(t + 1, t + 1,
				interrupted ? Outcome.INTERRUPT_AT_POST_BODY : Outcome.COMPLETE, ilc);
			if (t >= drainEnd) return new ReplayResult(t + 1, -1,
				Outcome.INTERRUPT_DRAINED, ilc);
			// The first three cycles cannot terminate, but their predicate
			// samples may be used at the first eligible boundary.
			delayed[t % 3] = continuePredicate.getAsBoolean();
		}
		throw new IllegalStateException("loop trace exceeds " + maxCycles + " cycles");
	}

	private List<Operation> operationsAt(int t, int finalIteration,
			boolean initiallyZero, boolean restart) {
		List<Operation> ops = new ArrayList<>();
		int memoryMask = !restart && t < source.size() ? source.get(t).unitMask : 0;
		for (int s = t % ii; s <= t && s < source.size(); s += ii) {
			int iteration = (t - s) / ii;
			SourceCycle cell = source.get(s);
			if (iteration == 0) {
				// The source is fetched once, including its SPMASKed setup code.
				for (Instruction insn : cell.program) {
					boolean masked = (unitBit(insn.getMnemonicString()) &
						cell.unitMask) != 0;
					if (restart ? !initiallyZero && !masked :
						!initiallyZero || masked) {
						ops.add(new Operation(insn, s, 0, Origin.PROGRAM));
					}
				}
			}
			else if (iteration <= finalIteration && !initiallyZero) {
				for (Instruction insn : cell.buffered) {
					if ((unitBit(insn.getMnemonicString()) & memoryMask) == 0) {
						ops.add(new Operation(insn, s, iteration, Origin.BUFFER));
					}
				}
			}
		}
		return ops;
	}

	private void checkRestartDelays() {
		for (SourceCycle cell : source) {
			for (Instruction insn : cell.program) {
				String name = insn.getMnemonicString();
				if (name.contains("BNOP") || name.contains("ADDKPC")) {
					throw new UnsupportedOperationException(
						"restart delay-slot operation needs an idle-cycle model at " +
						insn.getMinAddress());
				}
			}
		}
	}

	private static int scalar(Instruction insn) {
		Scalar value = insn.getScalar(0);
		return value == null ? 0 : (int) value.getUnsignedValue();
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

	private static Instruction nextExecutable(Listing listing, Instruction current) {
		Instruction next = listing.getInstructionAfter(current.getMinAddress());
		Instruction previous = current;
		while (next != null && next.getMnemonicString().equals("CPKT")) {
			if (!adjacent(previous, next)) {
				throw new IllegalArgumentException("undecoded bytes after " + previous.getMinAddress());
			}
			previous = next;
			next = listing.getInstructionAfter(next.getMinAddress());
		}
		if (next != null && !adjacent(previous, next)) {
			throw new IllegalArgumentException("undecoded bytes after " + previous.getMinAddress());
		}
		return next;
	}

	private static boolean adjacent(Instruction a, Instruction b) {
		return b.getMinAddress().getOffset() == a.getMaxAddress().getOffset() + 1;
	}

	private static boolean parallelWithNext(Program program, Instruction insn)
			throws MemoryAccessException {
		Address address = insn.getMinAddress();
		if (insn.getLength() == 4) return (program.getMemory().getInt(address) & 1) != 0;
		if (insn.getLength() != 2) {
			throw new IllegalArgumentException("unexpected instruction size at " + address);
		}
		long base = address.getOffset() & ~31L;
		int header = program.getMemory().getInt(address.getNewAddress(base + 28));
		if ((header >>> 28) != 0xe) {
			throw new MemoryAccessException("missing compact header at " + address);
		}
		return ((header >>> ((address.getOffset() - base) / 2)) & 1) != 0;
	}
}
