/* ###
 * Copyright 2026 ghidra-c6000 contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package c6000;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Issue #71: warn where a packet member reads a register an earlier member of its execute packet writes. */
public final class C6000SamePacketHazardAnalyzer extends AbstractAnalyzer {
	public static final String CATEGORY = "C6000 Same-Packet Hazard";
	/** Starts the function header line this analyzer owns; the decompiler shows it by default. */
	public static final String NOTE = "WARNING: C6000 same-packet hazard";
	/** GPRs and control registers; above them are context and synthetic registers. */
	private static final long ARCHITECTURAL = 0x3000, CONTROL = 0x2000;
	/** Ghidra prefixes a delay-slot instruction's mnemonic with "_". */
	private static final Pattern PREDICATE = Pattern.compile("^_?\\[(!?)(\\w+)\\]");

	public C6000SamePacketHazardAnalyzer() {
		super("C6000 Same-Packet Hazards",
			"Warns where a packet member reads a register that an earlier member of its execute packet writes: " +
				"native lifting gives it the new value, so the function's C may be wrong unless an exact schedule is active",
			AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		// After the windows and reviewed schedules are final, and after packet staging.
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after().after().after().after().after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C6000PacketContext.isC6000(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		var bookmarks = program.getBookmarkManager();
		int warned = 0;
		for (Function function : program.getFunctionManager().getFunctions(set, true)) {
			monitor.checkCancelled();
			bookmarks.removeBookmarks(function.getBody(), BookmarkType.WARNING, CATEGORY, monitor);
			List<String> hazards = new ArrayList<>();
			// An active reviewed schedule reads each packet's operands before its writes (SPRUFE8B 3.5).
			if (!C6000ProgramActions.hasActiveReview(program, function)) {
				try {
					for (Hazard hazard : hazards(program, function, monitor)) {
						hazards.add(hazard.reader().getAddress().toString());
						bookmarks.setBookmark(hazard.reader().getAddress(), BookmarkType.WARNING, CATEGORY, hazard.reader() +
							(hazard.late() == 0 ? " reads the old " + hazard.register() + ", which " + hazard.writer() + " at " +
								hazard.writer().getAddress() + " writes in the same execute packet (SPRUFE8B 3.5), but native" +
								" lifting gives it the new value" :
								" issues before " + hazard.register() + " from " + hazard.writer() + " at " + hazard.writer().getAddress() +
								" lands, " + hazard.late() + " delay slot(s) after it (SPRUFE8B 3.4), but native lifting has" +
								" already written it, and " + (hazard.straight() ? "the write could not be held back to there" :
									"control can come in or leave between the two, or a second late write to it issues, so the write could not be held back")) +
							", so " + function.getName() + " may decompile wrongly (issue " + (hazard.late() == 0 ? "#71" : "#152") + ")");
					}
				}
				catch (MemoryAccessException e) {
					Msg.debug(this, "Skipped " + function.getName() + ": " + e.getMessage());
				}
			}
			note(function, hazards);
			warned += hazards.size();
		}
		if (warned > 0) Msg.info(this, getName() + "> " + warned + " warning(s)");
		return true;
	}

	/** A packet member that reads register, which an earlier member of its execute packet writes. */
	record Hazard(Instruction reader, Instruction writer, String register, int late, boolean straight) {}

	/** A read of {@code register} that must see the value from before {@code writer}, an earlier member of packet {@code packet}. */
	record OldRead(Instruction reader, Instruction writer, Varnode register, int packet, int late, boolean straight) {}

	/**
	 * The same for a result that lands cycles after its instruction issues, a load's or a
	 * multiply's (SPRUFE8B 3.4, Table 3-8; issues #16, #152): each later instruction that issues before
	 * it lands and reads the register, or writes it and so must be overwritten by it, needs the
	 * value from before. {@code late} is the writer's delay slots. {@code straight} says that
	 * control neither comes in nor can leave between the two, so that a commit placed after the
	 * reader runs exactly when the write does.
	 */
	static List<OldRead> lateReads(Program program, Function function, TaskMonitor monitor) throws CancelledException {
		List<OldRead> found = new ArrayList<>();
		var walker = new C6000CallAnalyzer.Walker(program);
		List<Instruction> path = new ArrayList<>();
		Instruction previous = null;
		for (Instruction ins : program.getListing().getInstructions(function.getBody(), true)) {
			monitor.checkCancelled();
			boolean header = C6000CallAnalyzer.baseName(ins).equals("CPKT");
			if (previous != null && !previous.getMaxAddress().next().equals(ins.getMinAddress())) {
				late(program, walker, path, found);
				path = new ArrayList<>();
			}
			if (!header) path.add(ins);
			previous = ins;
		}
		late(program, walker, path, found);
		return found;
	}

	/**
	 * A floating-point instruction reads its operands, and writes the words of a double result, in
	 * several pipeline stages (docs/pipeline-schedules.md): which value it reads from a register
	 * written late is not a matter of its issue cycle alone, so nothing is claimed for one here,
	 * as a writer or as a reader. Only an exact schedule models those.
	 */
	private static boolean floating(Instruction ins) {
		String name = C6000CallAnalyzer.baseName(C6000PacketStagingAnalyzer.hardware(ins));
		int dot = name.indexOf('.');
		String op = dot < 0 ? name : name.substring(0, dot);
		return op.endsWith("DP") || op.endsWith("SP") || op.contains("SP2") || op.contains("DP2") || op.startsWith("SPDP") || op.startsWith("DPSP") ||
			op.endsWith("SPU") || op.endsWith("DPU") || op.endsWith("INT") && (op.startsWith("SP") || op.startsWith("DP")) || op.endsWith("TRUNC");
	}

	private static void late(Program program, C6000CallAnalyzer.Walker walker, List<Instruction> path, List<OldRead> found) {
		if (path.size() < 2) return;
		int[] cycles = walker.issueCycles(path);
		for (int w = 0; w < path.size(); w++) {
			Instruction writer = path.get(w);
			int delay = transfer(writer) || floating(writer) ? 0 : C6000CallAnalyzer.exactResultDelay(C6000PacketStagingAnalyzer.hardware(writer));
			if (delay <= 0) continue;
			// A load's address register is updated at once; only what it loads comes late.
			Register loaded = C6000CallAnalyzer.Walker.loadDestination(C6000PacketStagingAnalyzer.hardware(writer));
			Set<Varnode> late = new LinkedHashSet<>();
			if (loaded != null) add(late, loaded);
			else late.addAll(writes(writer));
			// One register holds one waiting result: past a second late write to it nothing is held.
			boolean second = false;
			for (int j = w + 1; j < path.size() && cycles[j] <= cycles[w] + delay; j++) {
				if (cycles[j] == cycles[w]) continue;
				Instruction reader = path.get(j);
				if (!transfer(reader) && C6000CallAnalyzer.resultDelay(C6000PacketStagingAnalyzer.hardware(reader)) != 0) {
					Register other = C6000CallAnalyzer.Walker.loadDestination(C6000PacketStagingAnalyzer.hardware(reader));
					Set<Varnode> also = new LinkedHashSet<>();
					if (other != null) add(also, other);
					else also.addAll(writes(reader));
					second |= overlap(late, also) != null;
				}
				if (floating(reader)) continue;
				Varnode register = overlap(late, reads(program, reader));
				if (register == null) register = overlap(late, writes(reader));
				if (register == null) continue;
				boolean straight = !second;
				for (int k = w + 1; k <= j && straight; k++)
					for (var ref : program.getReferenceManager().getReferencesTo(path.get(k).getMinAddress()))
						straight &= !ref.getReferenceType().isFlow() || ref.getReferenceType().isFallthrough();
				// A transfer that lands after the writer issues and no later than the reader may take control away between them.
				for (int t = 0; t <= j && straight; t++)
					straight = !(transfer(path.get(t)) && cycles[t] + 6 > cycles[w] && cycles[t] + 6 <= cycles[j]);
				found.add(new OldRead(reader, writer, register, 0, delay, straight));
			}
		}
	}

	/** Every such read in the function, in address order; a reader has one per register and writer. */
	static List<OldRead> oldReads(Program program, Function function, TaskMonitor monitor)
			throws CancelledException, MemoryAccessException {
		List<OldRead> found = new ArrayList<>();
		List<Instruction> packet = new ArrayList<>();
		Instruction previous = null;
		int id = 0;
		for (Instruction ins : program.getListing().getInstructions(function.getBody(), true)) {
			monitor.checkCancelled();
			if (C6000CallAnalyzer.baseName(ins).equals("CPKT")) continue;
			if (previous == null || !C6000ExecutionPackets.parallelWithNext(program, previous) ||
				!ins.getAddress().equals(next(program, previous))) { packet.clear(); id++; }
			Set<Varnode> reads = reads(program, ins);
			for (Instruction earlier : packet) {
				if (exclusive(program, earlier, ins)) continue;
				for (Varnode written : writes(earlier)) {
					if (overlap(Set.of(written), reads) == null) continue;
					if (written.getOffset() >= CONTROL && sticky(program, earlier, written) && sticky(program, ins, written)) continue;
					found.add(new OldRead(ins, earlier, written, id, 0, true));
				}
			}
			packet.add(ins);
			previous = ins;
		}
		return found;
	}

	/** Each packet member that reads what an earlier member of its execute packet writes, unless that write is staged. */
	static List<Hazard> hazards(Program program, Function function, TaskMonitor monitor)
			throws CancelledException, MemoryAccessException {
		List<Hazard> found = new ArrayList<>();
		Set<Address> seen = new java.util.HashSet<>();
		List<OldRead> reads = new ArrayList<>(oldReads(program, function, monitor));
		reads.addAll(lateReads(program, function, monitor));
		for (OldRead read : reads) {
			// A write is held up to its last reader that control cannot bypass; one past that is not covered.
			Address commit = read.late() == 0 ? null : C6000PacketStagingAnalyzer.committed(program, read.writer(), read.register());
			boolean held = read.late() == 0 ? C6000PacketStagingAnalyzer.staged(program, read.writer(), read.register()) :
				read.straight() && commit != null && commit.compareTo(read.reader().getAddress()) >= 0;
			if (held || !seen.add(read.reader().getAddress())) continue;
			Register register = program.getRegister(read.register().getAddress(), read.register().getSize());
			found.add(new Hazard(read.reader(), read.writer(), register != null ? register.getName() : read.register().toString(), read.late(), read.straight()));
		}
		return found;
	}

	/*
	 * Two read-modify-writes of a control register only OR in sticky flags, which commute
	 * (SPRUFE8B 2.8.4 CSR, 2.10 FADCR, FAUCR, FMCR): oldReads leaves that pair out.
	 */

	/** Opposite predicates on one register that earlier leaves alone: at most one of them executes. */
	private static boolean exclusive(Program program, Instruction earlier, Instruction ins) {
		var a = PREDICATE.matcher(earlier.getMnemonicString());
		var b = PREDICATE.matcher(ins.getMnemonicString());
		if (!a.find() || !b.find() || !a.group(2).equals(b.group(2)) || a.group(1).equals(b.group(1))) return false;
		Register predicate = program.getRegister(a.group(2));
		return predicate != null &&
			overlap(writes(earlier), Set.of(new Varnode(predicate.getAddress(), predicate.getMinimumByteSize()))) == null;
	}

	/** ins both reads and writes v. */
	private static boolean sticky(Program program, Instruction ins, Varnode v) {
		return overlap(writes(ins), Set.of(v)) != null && overlap(reads(program, ins, false), Set.of(v)) != null;
	}

	/** The instruction after ins, past a compact header. */
	private static Address next(Program program, Instruction ins) {
		Instruction next = program.getListing().getInstructionAfter(ins.getMaxAddress());
		while (next != null && C6000CallAnalyzer.baseName(next).equals("CPKT"))
			next = program.getListing().getInstructionAfter(next.getMaxAddress());
		return next == null ? null : next.getAddress();
	}

	/** A branch's p-code holds its laid window, so take only its target and predicate. */
	private static boolean transfer(Instruction ins) {
		var flow = C6000PacketStagingAnalyzer.flow(ins);
		return flow.isJump() || flow.isCall() || flow.isTerminal() || ins.getPrototype().hasDelaySlots();
	}

	private static Set<Varnode> reads(Program program, Instruction ins) {
		return reads(program, ins, true);
	}

	/** Registers ins reads; internal false also counts those it reads after writing them. */
	private static Set<Varnode> reads(Program program, Instruction ins, boolean external) {
		Set<Varnode> reads = new LinkedHashSet<>();
		if (transfer(ins)) {
			add(reads, ins.getRegister(0));
			var predicate = PREDICATE.matcher(ins.getMnemonicString());
			if (predicate.find()) add(reads, program.getRegister(predicate.group(2)));
			return reads;
		}
		Set<Varnode> written = new LinkedHashSet<>();
		for (PcodeOp op : C6000PacketStagingAnalyzer.hardwarePcode(ins)) {
			for (Varnode input : op.getInputs())
				if (architectural(input) && (!external || overlap(written, Set.of(input)) == null)) reads.add(input);
			if (architectural(op.getOutput())) written.add(op.getOutput());
		}
		return reads;
	}

	/** A branch writes nothing its peers read; CALLP's link is written after them (SPRUFE8B 4.2.4). */
	private static Set<Varnode> writes(Instruction ins) {
		Set<Varnode> writes = new LinkedHashSet<>();
		if (transfer(ins)) return writes;
		for (PcodeOp op : C6000PacketStagingAnalyzer.hardwarePcode(ins))
			if (architectural(op.getOutput())) writes.add(op.getOutput());
		return writes;
	}

	private static void add(Set<Varnode> set, Register register) {
		if (register != null) set.add(new Varnode(register.getAddress(), register.getMinimumByteSize()));
	}

	private static boolean architectural(Varnode v) {
		return v != null && v.isRegister() && v.getOffset() < ARCHITECTURAL;
	}

	/** The first of a that overlaps one of b, or null. */
	private static Varnode overlap(Set<Varnode> a, Set<Varnode> b) {
		for (Varnode x : a)
			for (Varnode y : b)
				if (x.getOffset() < y.getOffset() + y.getSize() && y.getOffset() < x.getOffset() + x.getSize()) return x;
		return null;
	}

	/** Replace this analyzer's header line, keeping every other line of the function comment. */
	private static void note(Function function, List<String> hazards) {
		String old = function.getComment();
		List<String> lines = new ArrayList<>();
		if (old != null)
			for (String line : old.split("\n", -1))
				if (!line.startsWith(NOTE)) lines.add(line);
		if (!hazards.isEmpty())
			lines.add(0, NOTE + " at " + String.join(", ", hazards) + ": an instruction reads a register before" +
				" an earlier write to it takes effect, in its execute packet or while a late result is in flight," +
				" so this C may be wrong (issues #71, #152)");
		String now = lines.isEmpty() ? null : String.join("\n", lines);
		if (!java.util.Objects.equals(old, now)) function.setComment(now);
	}
}
