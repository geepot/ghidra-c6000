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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Recover calls encoded as {@code B target} or {@code B reg} with B3 set to
 * the return address inside the branch's five delay slots, by ADDKPC or by an
 * MVK(L)/MVKH pair (the MVK may precede the branch packet).
 *
 * <p>Ghidra sees such a B as a jump: the unconditional immediate form has no
 * fall-through, so its delay slots and the code after the return point are
 * never decoded. A CALL flow override plus a fall-through to the delay slots
 * models the call; register targets loaded by MVK(L)/MVKH get a call
 * reference so the callee becomes a function.
 */
public class C6000CallAnalyzer extends AbstractAnalyzer {
	private static final int DELAY_CYCLES = 5;
	private static final int LOOK_BACK = 40;
	private static final int MAX_WINDOW = 24;
	static final int LOW = 1, HIGH = 2, FULL = LOW | HIGH;

	public C6000CallAnalyzer() {
		super("C6000 Delayed Calls",
			"Classifies B instructions whose delay slots set B3 as calls",
			AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		// Before the return and register-branch analyzers: a register call
		// must never be rewritten into a terminal computed jump.
		setPriority(AnalysisPriority.CODE_ANALYSIS.before().before());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C6000PacketContext.isC6000(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		Listing listing = program.getListing();
		List<Address> branches = new ArrayList<>();
		// Code decoded just before an earlier call can supply its MVK/MVKH
		// target, so revisit the look-back distance past each new range.
		AddressSet scan = new AddressSet(set);
		for (AddressRange range : set.getAddressRanges()) {
			Address end = range.getMaxAddress();
			long room = end.getAddressSpace().getMaxAddress().subtract(end);
			scan.add(end, end.add(Math.min(room, LOOK_BACK * 4L)));
		}
		InstructionIterator instructions = listing.getInstructions(scan, true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction branch = instructions.next();
			String op = baseName(branch);
			if ((op.equals("B.S1") || op.equals("B.S2")) &&
				(reclassifiable(program, branch) || missingTarget(branch)) &&
				!"B3".equals(branch.getDefaultOperandRepresentation(0))) {
				branches.add(branch.getAddress());
			}
		}

		AutoAnalysisManager analysis = AutoAnalysisManager.getAnalysisManager(program);
		Disassembler disassembler = Disassembler.getDisassembler(program, monitor, null);
		Walker walker = new Walker(program);
		Set<Function> callers = new HashSet<>();
		int recovered = 0;
		for (Address at : branches) {
			monitor.checkCancelled();
			Instruction branch = listing.getInstructionAt(at);
			if (branch == null) continue;
			Call call = walker.recognize(branch);
			if (call == null) continue;
			boolean known = branch.getFlowOverride() == FlowOverride.CALL;
			if (known && call.target() == null) continue;
			branch.setFlowOverride(FlowOverride.CALL);
			Address next = branch.getMaxAddress().next();
			if (branch.getFallThrough() == null) branch.setFallThrough(next);
			if (listing.getInstructionAt(next) == null) disassembler.disassemble(next, null, true);
			Function caller = listing.getFunctionContaining(at);
			if (caller != null) callers.add(caller);
			if (call.target() != null) {
				boolean referenced = false;
				for (Reference ref : branch.getReferencesFrom()) {
					if (!ref.getReferenceType().isFlow()) continue;
					if (ref.getToAddress().equals(call.target()) && ref.getReferenceType().isCall()) {
						referenced = true;
					}
					else if (ref.getReferenceType().isJump()) {
						program.getReferenceManager().delete(ref);
					}
				}
				if (!referenced) {
					program.getReferenceManager().addMemoryReference(at, call.target(),
						RefType.COMPUTED_CALL, SourceType.ANALYSIS, 0);
				}
			}
			Address[] flows = branch.getFlows();
			Address callee = call.target() != null ? call.target() :
				flows.length == 1 ? flows[0] : null;
			if (callee != null) {
				if (listing.getInstructionAt(callee) == null) analysis.disassemble(callee);
				analysis.createFunction(callee, false);
			}
			if (!known) recovered++;
		}
		// A body computed while the B was a jump stops at it or swallows the callee.
		for (Function caller : callers) {
			monitor.checkCancelled();
			CreateFunctionCmd.fixupFunctionBody(program, caller, monitor);
		}
		if (recovered > 0) log.appendMsg(getName(), "recovered " + recovered + " delayed call(s)");
		return true;
	}

	/**
	 * Unclassified branches, and CALL_RETURN tail calls that Ghidra's
	 * shared-return logic guessed before the delay slots were understood.
	 * A no-return callee or a terminal call form is left alone: re-overriding
	 * either lets another analyzer flip it back, and the two loop forever.
	 */
	private static boolean reclassifiable(Program program, Instruction branch) {
		FlowOverride override = branch.getFlowOverride();
		if (override == FlowOverride.NONE) return true;
		if (override != FlowOverride.CALL_RETURN ||
			branch.getPrototype().getFlowType(branch.getInstructionContext()).isTerminal()) return false;
		for (Address target : branch.getFlows()) {
			Function callee = program.getFunctionManager().getFunctionAt(target);
			if (callee != null && callee.hasNoReturn()) return false;
		}
		return true;
	}

	/** A register call recognised before its target's MVK/MVKH was decoded. */
	private static boolean missingTarget(Instruction branch) {
		if (branch.getFlowOverride() != FlowOverride.CALL || branch.getRegister(0) == null) {
			return false;
		}
		for (Reference ref : branch.getReferencesFrom()) {
			if (ref.getReferenceType().isCall()) return false;
		}
		return true;
	}

	/** A recognised call; {@code target} is set for a register branch with a known value. */
	private record Call(Address target) {
	}

	/**
	 * Walks the instructions around a branch, decoding bytes that the
	 * listing does not yet hold, and tracks MVK/MVKH/ADDKPC constants.
	 */
	static final class Walker {
		private final Program program;
		private final Listing listing;
		private final PseudoDisassembler pseudo;
		/**
		 * Decode through defined data. Only the look-back does: analysis can
		 * type code words as pointers, and there a misread merely loses a
		 * constant, while the delay window decides whether a call exists.
		 */
		private boolean throughData;

		Walker(Program program) {
			this.program = program;
			this.listing = program.getListing();
			this.pseudo = new PseudoDisassembler(program);
		}

		Call recognize(Instruction branch) {
			Map<Register, long[]> regs = new HashMap<>();
			Instruction partner = null;
			List<Instruction> path = lookBack(branch);
			List<Instruction> via = viaJump(branch, path);
			if (via != null) path = via;
			List<Instruction> slots = window(branch);
			if (slots == null) return null;
			List<Instruction> execution = new ArrayList<>(path);
			int branchIndex = execution.size();
			execution.add(branch);
			execution.addAll(slots);
			int[] issue = issueCycles(execution);
			Constants trace = new Constants(regs);
			List<PredicateFact> facts = new ArrayList<>();

			for (int i = 0; i < path.size(); i++) {
				Instruction insn = path.get(i);
				if (isFlow(insn) && predicate(insn) == null) facts.clear();
				if (via == null && predicate(insn) != null && insn.getFlowType().isJump() &&
					!insn.getFlowType().isCall() && !insn.getFlowType().isTerminal() &&
					!inWindow(insn, branch)) {
					// The straight-line path reaches branch only on this fall-through.
					addFact(facts, i, insn, false);
				}
			}
			// Taken-edge constraints take precedence over speculative physical look-back.
			if (via != null) addFact(facts, slotIndex(path, viaInsn), viaInsn, true);
			addFact(facts, branchIndex, branch, true);
			java.util.Collections.reverse(facts);
			for (int i = 0; i < path.size(); i++) {
				Instruction insn = path.get(i);
				Boolean runs = executes(execution, i, facts);
				if (Boolean.FALSE.equals(runs)) {
					if (via == null && isFlow(insn) && complementary(insn, branch) &&
						stable(execution, i, branchIndex, predicate(branch), true) &&
						branch.getMinAddress().subtract(insn.getMinAddress()) <= 24) partner = insn;
					continue;
				}
				trace.before(issue[i]);
				if (insn != viaInsn && isFlow(insn)) trace.write(issue[i], program.getRegister("B3"), null, i);
				trace.instruction(insn, runs, issue[i], i);
			}

			// SPRUFE8B 3.5 / Tables 4-6 and 4-11: all members of a
			// packet read the same E1 snapshot, before any E1 writer commits.
			trace.before(issue[branchIndex]);
			Register source = branch.getRegister(0);
			Long target = null;
			if (source != null) {
				long[] value = regs.get(source);
				if (value != null && value[1] == FULL) target = value[0];
			}

			// The rest of the branch's execute packet, then five delay cycles.
			Register b3 = program.getRegister("B3");
			Instruction current = branch;
			int cycles = 0;
			int seen = 0;
			boolean compact = branch.getLength() != 4;
			boolean branchPacket = true;
			try {
				window: while (cycles < DELAY_CYCLES) {
					int packetCycles = 1;
					do {
						if (branchPacket && !parallelWithNext(current)) break;
						Instruction next = next(current);
						if (next == null || ++seen > MAX_WINDOW) return null;
						// Reaching the return address B3 already holds ends the
						// window, even where compact packets skew the cycle count.
						int index = branchIndex + 1 + slotIndex(slots, next);
						trace.before(issue[index]);
						long[] ra = regs.get(b3);
						if (ra != null && ra[1] == FULL &&
							next.getMinAddress().getOffset() == ra[0]) break window;
						// A branch in the window must be the other arm of an
						// if/else call pair: exactly the opposite predicate.
						if (isFlow(next)) {
							if (!complementary(branch, next) ||
								!stable(execution, branchIndex + 1 + slotIndex(slots, next), branchIndex, predicate(branch), true)) return null;
							if (partner == null) partner = next;
						}
						if (next.getLength() != 4) compact = true;
						trace.instruction(next, executes(execution, index, facts), issue[index], index);
						packetCycles = Math.max(packetCycles, 1 + extraCycles(program, next));
						current = next;
					} while (parallelWithNext(current));
					if (!branchPacket) cycles += packetCycles;
					branchPacket = false;
				}
			}
			catch (MemoryAccessException e) {
				return null;
			}
			// Retire writes through the last delay cycle, including idle cycles
			// represented by ADDKPC/NOP. A load's E5 can supersede a later E1 link.
			trace.before(issue[branchIndex] + DELAY_CYCLES + 1);
			if (partner != null && jumpArm(branch, partner)) return null;
			long[] ret = regs.get(b3);
			// B3 may also be set on the look-back path.
			if (ret == null || ret[1] != FULL) return null;
			long branchAt = branch.getMinAddress().getOffset();
			long windowEnd = current.getMaxAddress().getOffset() + 1;
			if (ret[0] < branchAt + 4 || ret[0] > windowEnd + 8) return null;
			boolean headerAtEnd = (windowEnd & 31) == 28 && headerAt(branch, windowEnd);
			long partnerEnd = partner == null ? -1 : windowEnd(partner);
			if (ret[0] != windowEnd && !(compact && ret[0] <= windowEnd + 8) &&
				!(headerAtEnd && ret[0] == windowEnd + 4) && ret[0] != partnerEnd) return null;
			Address callee = target == null ? null :
				branch.getMinAddress().getNewAddress(target & 0xffffffffL);
			if (callee != null && !program.getMemory().contains(callee)) callee = null;
			return new Call(callee);
		}

		/** Relative E1 cycle of each physical instruction, including idle spans. */
		private int[] issueCycles(List<Instruction> path) {
			int[] cycles = new int[path.size()];int cycle = 0, span = 1;
			for (int i = 0; i < path.size(); i++) {
				if (i > 0) {
					Instruction prior = path.get(i - 1), current = path.get(i);
					long next = prior.getMaxAddress().getOffset() + 1;
					if ((next & 31) == 28 && headerAt(prior, next)) next += 4;
					boolean parallel;
					try { parallel = parallelWithNext(prior) && next == current.getMinAddress().getOffset(); }
					catch (MemoryAccessException unavailable) { parallel = false; }
					if (!parallel) { cycle += span;span = 1; }
				}
				cycles[i] = cycle;span = Math.max(span, 1 + extraCycles(program, path.get(i)));
			}
			return cycles;
		}

		private static boolean overlaps(Register a, Register b) {
			return a.getAddress().getAddressSpace().equals(b.getAddress().getAddressSpace()) &&
				a.getOffset() < b.getOffset() + b.getMinimumByteSize() && b.getOffset() < a.getOffset() + a.getMinimumByteSize();
		}

		private static Register loadDestination(Instruction insn) {
			String name = baseName(insn);
			return name.startsWith("LD") && insn.getNumOperands() >= 2 ? insn.getRegister(insn.getNumOperands() - 1) : null;
		}

		/** An updating load writes its base in E1, even when it aliases its E5 destination. */
		private Register updatingBase(Instruction insn) {
			String memory = insn.getDefaultOperandRepresentation(0);
			if (memory == null || (!memory.contains("++") && !memory.contains("--"))) return null;
			var match = java.util.regex.Pattern.compile("\\*\\s*(?:\\+\\+|--)?\\s*([AB][0-9]+)").matcher(memory);
			return match.find() ? program.getRegister(match.group(1)) : null;
		}

		private List<Register> issueWrites(Instruction insn) {
			List<Register> writes = new ArrayList<>();
			// Native delay carriers include their followers' results; those have
			// their own physical instruction and issue time in this walk.
			if (insn.getDelaySlotDepth() != 0) return writes;
			Register load = loadDestination(insn);
			for (Object result : insn.getResultObjects()) if (result instanceof Register r && (load == null || !overlaps(r, load))) writes.add(r);
			if (load != null) { Register base = updatingBase(insn);if (base != null && !writes.contains(base)) writes.add(base); }
			return writes;
		}

		private record Write(Register register, long[] value, int owner) {}

		/** Constants visible before E1 reads, with atomic packet commits and E5 invalidations. */
		private final class Constants {
			private final Map<Register, long[]> values;
			private final TreeMap<Integer, List<Write>> pending = new TreeMap<>();
			Constants(Map<Register, long[]> values) { this.values = values; }
			void write(int cycle, Register register, long[] value, int owner) {
				pending.computeIfAbsent(cycle, k -> new ArrayList<>()).add(new Write(register, value == null ? null : value.clone(), owner));
			}
			void before(int cycle) {
				while (!pending.isEmpty() && pending.firstKey() < cycle) {
					List<Write> writes = pending.pollFirstEntry().getValue();
					for (Write write : writes) values.keySet().removeIf(r -> overlaps(r, write.register()));
					for (Write write : writes) if (write.value() != null && writes.stream().noneMatch(other ->
						other.owner() != write.owner() && overlaps(other.register(), write.register()))) values.put(write.register(), write.value());
				}
			}
			void instruction(Instruction insn, Boolean runs, int cycle, int owner) {
				if (Boolean.FALSE.equals(runs)) return;
				Register load = loadDestination(insn);
				if (load != null) {
					// SPRUFE8B 4.2.5 / Table 4-10: E1 address update,
					// E5 data write, independent of later ADDKPC/MVK writers.
					write(cycle + 4, load, null, owner);
					for (Register r : issueWrites(insn)) write(cycle, r, null, owner);
					return;
				}
				Map<Register, long[]> result = new HashMap<>(values);
				Register known = Boolean.TRUE.equals(runs) ? track(insn, result) : null;
				for (Register r : issueWrites(insn)) write(cycle, r, r.equals(known) ? result.get(r) : null, owner);
			}
		}

		/**
		 * The straight-line code before a branch, oldest first. It is decoded
		 * forward from a fetch packet about {@link #LOOK_BACK} words back, so
		 * the delay slots of an earlier jump, which Ghidra leaves undecoded,
		 * still count; if that walk does not land on the branch, fall back to
		 * the adjacent listing instructions.
		 * ponytail: no flow merge; a far-call constant is almost always loaded
		 * a few packets before the B.
		 */
		List<Instruction> lookBack(Instruction branch) {
			Address at = branch.getMinAddress();
			MemoryBlock block = program.getMemory().getBlock(at);
			List<Instruction> before = new ArrayList<>();
			if (block != null) {
				long start = Math.max(block.getStart().getOffset(),
					(at.getOffset() - LOOK_BACK * 4L) & ~31L);
				throughData = true;
				Instruction insn;
				try {
					insn = decode(at.getNewAddress(start));
					if (insn != null && insn.getMnemonicString().equals("CPKT")) insn = next(insn);
					while (insn != null && insn.getMinAddress().compareTo(at) < 0) {
						before.add(insn);
						insn = next(insn);
					}
				}
				finally {
					throughData = false;
				}
				if (insn != null && insn.getMinAddress().equals(at)) return before;
				before.clear();
			}
			Instruction back = branch;
			for (int i = 0; i < LOOK_BACK; i++) {
				Instruction prior = listing.getInstructionBefore(back.getMinAddress());
				if (prior == null || !adjacent(prior, back)) break;
				before.add(0, prior);
				back = prior;
			}
			return before;
		}

		/**
		 * The known value an instruction copies between registers: MV, or the
		 * compiler's ADD/OR of zero. Null when it is not a copy of a known value.
		 */
		private static long[] copySource(Instruction insn, String name, Map<Register, long[]> regs) {
			int n = insn.getNumOperands();
            // Full32 exact spellings include ADD.D src,0,dst as well as
            // ADD/OR 0,src,dst. Both are copies; preserve constant recovery
            // when a scalar MV alias is displayed as its actual primitive.
            Register src = C6000EncodingInfo.registerCopySource(insn);
			if (src == null || insn.getRegister(n - 1) == null || insn.getMnemonicString().startsWith("[")) {
				return null;
			}
			long[] value = regs.get(src);
			return value == null ? null : value.clone();
		}

		/** Apply one instruction to the constant map; returns the constant register written. */
		Register track(Instruction insn, Map<Register, long[]> regs) {
			String op = baseName(insn);
			int dot = op.indexOf('.');
			String name = dot < 0 ? op : op.substring(0, dot);
			Register dst = insn.getNumOperands() >= 2 ? insn.getRegister(1) : null;
			Long value = insn.getNumOperands() >= 2 ? constant(insn) : null;
			long[] old = dst == null ? null : regs.get(dst);
			long[] copied = copySource(insn, name, regs);
			// A compact branch folds its parallel followers into its own p-code
			// as delay slots; they are tracked separately, so skip its writes.
			if (insn.getDelaySlotDepth() == 0) {
				for (Object written : insn.getResultObjects()) {
					if (written instanceof Register r) regs.remove(r);
				}
			}
			if (copied != null) {
				Register to = insn.getRegister(insn.getNumOperands() - 1);
				regs.put(to, copied);
				return to;
			}
			if (dst == null || value == null) return null;
			// Compact (16-bit) forms carry only small MVK constants.
			if (insn.getLength() != 4 && !name.equals("MVK")) return null;
			long v = value;
			switch (name) {
				case "MVK", "MVKL" -> {
					if (insn.getLength() == 4 && !op.startsWith("MVK.S") &&
						!op.startsWith("MVKL.S")) return null;
					regs.put(dst, new long[] { (short) v, FULL });
				}
				case "MVKH" -> {
					long low = old == null ? 0 : old[0] & 0xffff;
					int mask = old == null ? HIGH : (int) old[1] | HIGH;
					regs.put(dst, new long[] { ((v & 0xffff) << 16) | low, mask });
				}
				case "ADDKPC" -> regs.put(dst, new long[] { v, FULL });
				default -> {
					return null;
				}
			}
			return dst;
		}

		/** Operand 0 as a number; an in-image constant may be rendered as an address. */
		private static Long constant(Instruction insn) {
			for (Object o : insn.getOpObjects(0)) {
				if (o instanceof Scalar scalar) return scalar.getUnsignedValue();
				if (o instanceof Address address) return address.getOffset();
			}
			return null;
		}

		/** The jump the last {@link #viaJump} path went through. */
		private Instruction viaInsn;

		/** Look-back via the one B into a branch nothing falls into, plus its taken slots; else null. */
		List<Instruction> viaJump(Instruction branch, List<Instruction> linear) {
			viaInsn = null;
			Instruction last = null;
			for (Instruction insn : linear) if (isFlow(insn)) last = insn;
			if (last == null || last.getFallThrough() != null ||
				program.getSymbolTable().isExternalEntryPoint(branch.getMinAddress()) ||
				explicitFunctionEntry(branch.getMinAddress())) return null;
			List<Instruction> trailing = window(last);
			if (trailing == null || trailing.isEmpty() ||
				!adjacent(trailing.get(trailing.size() - 1), branch)) return null;
			for (Instruction slot : trailing) if (alternateEntry(slot)) return null;
			Instruction jump = null;
			for (Reference ref : program.getReferenceManager().getReferencesTo(branch.getMinAddress())) {
				if (ref.getReferenceType().isData()) return null;
				if (!ref.getReferenceType().isFlow() || ref.getReferenceType().isFallthrough()) continue;
				if (jump != null || !ref.getReferenceType().isJump()) return null;
				jump = listing.getInstructionAt(ref.getFromAddress());
				if (jump == null) return null;
			}
			if (jump == null || !baseName(jump).startsWith("B.S")) return null;
			List<Instruction> taken = window(jump);
			if (taken == null) return null;
			for (Instruction slot : taken) if (isFlow(slot)) return null;
			List<Instruction> path = new ArrayList<>(lookBack(jump));
			path.add(jump);
			path.addAll(taken);
			viaInsn = jump;
			return path;
		}

		private boolean explicitFunctionEntry(Address at) {
			Function function = listing.getFunctionAt(at);
			if (function == null) return false;
			SourceType source = function.getSymbol().getSource();
			return source == SourceType.USER_DEFINED || source == SourceType.IMPORTED;
		}

		/** An entry into physical delay slots invalidates the dead-linear-predecessor proof. */
		private boolean alternateEntry(Instruction insn) {
			for (int offset = 0; offset < insn.getLength(); offset++) {
				Address at = insn.getMinAddress().add(offset);
				if (program.getSymbolTable().isExternalEntryPoint(at) || listing.getFunctionAt(at) != null) return true;
				for (Reference ref : program.getReferenceManager().getReferencesTo(at)) {
					if (ref.getReferenceType().isData()) return true;
					if (ref.getReferenceType().isFlow() &&
						(offset != 0 || !ref.getReferenceType().isFallthrough())) return true;
				}
			}
			return false;
		}

		private static int slotIndex(List<Instruction> slots, Instruction instruction) {
			for (int i = 0; i < slots.size(); i++) {
				if (slots.get(i).getMinAddress().equals(instruction.getMinAddress())) return i;
			}
			throw new IllegalArgumentException("instruction outside proved delay window");
		}

		private record PredicateFact(int index, String predicate, boolean taken) {}

		private static void addFact(List<PredicateFact> facts, int index, Instruction insn, boolean taken) {
			String p = predicate(insn);
			if (p != null) facts.add(new PredicateFact(index, p, taken));
		}

		/** Null means a conditional write cannot supply a constant on the selected path. */
		private Boolean executes(List<Instruction> path, int index, List<PredicateFact> facts) {
			String p = predicate(path.get(index));
			if (p == null) return true;
			for (PredicateFact fact : facts) {
				if (p.replace("!", "").equals(fact.predicate().replace("!", "")) &&
					stable(path, index, fact.index(), fact.predicate(), fact.taken())) {
					return p.equals(fact.predicate()) == fact.taken();
				}
			}
			return null;
		}

		/** Follow a captured predicate forward; backwards only past writes that would have falsified it. */
		private boolean stable(List<Instruction> path, int query, int anchor, String predicate, boolean taken) {
			if (predicate == null) return false;
			Register register = program.getRegister(predicate.replace("!", ""));
			boolean nonzero = predicate.startsWith("!") != taken;
			int[] cycles = issueCycles(path);
			int first = cycles[Math.min(query, anchor)], last = cycles[Math.max(query, anchor)];
			for (int i = 0; i < path.size(); i++) {
				Instruction insn = path.get(i);Register load = loadDestination(insn);
				if (load == null || !overlaps(load, register) || cycles[i] + 4 < first || cycles[i] + 4 >= last) continue;
				String guard = predicate(insn);
				boolean skipped = query >= anchor && guard != null &&
					guard.replace("!", "").equals(register.getName()) && (guard.startsWith("!") ? !nonzero : nonzero) == false &&
					(cycles[i] >= first || stable(path, i, anchor, predicate, taken));
				if (!skipped) return false;
			}

			for (int i = Math.min(query, anchor); i < Math.max(query, anchor); i++) {
				Instruction instruction = path.get(i);
				// A packet reads predicates before any of its writes commit.
				if (samePacket(path, i, Math.max(query, anchor))) continue;
				String p = predicate(instruction);
				if (query >= anchor && p != null && p.replace("!", "").equals(register.getName()) &&
					(p.startsWith("!") ? !nonzero : nonzero) == false) continue;
				// A constant replacement can preserve the predicate's truth value,
				// even when the instruction's own predicate is not known.
				// Backwards, one that would falsify the fact cannot have run (SPRUFE8B 3.12 MVK, 4.2.1).
				Long value = constantWrite(instruction, register);
				if (value != null && ((value != 0) == nonzero) == (query >= anchor)) continue;
				// B's native delay carrier reports its followers' writes too;
				// the physical followers are present separately in this path.
				String op = baseName(instruction);
				if (op.equals("B.S1") || op.equals("B.S2")) continue;
				for (Register r : issueWrites(instruction)) if (overlaps(r, register)) return false;
			}
			return true;
		}

		/** The constant an MVK/MVKL or a self-subtracting SUB writes to register, else null. */
		private static Long constantWrite(Instruction insn, Register register) {
			String name = baseName(insn);
			if ((name.startsWith("MVK.") || name.startsWith("MVKL.")) &&
				register.equals(insn.getRegister(1)) && insn.getScalar(0) != null) return insn.getScalar(0).getValue();
			// SUB x,x,dst writes 0, the form dis6x lists as ZERO (SPRUFE8B 3.12 SUB, ZERO).
			if (name.startsWith("SUB.") && insn.getNumOperands() == 3 && register.equals(insn.getRegister(2)) &&
				insn.getRegister(0) != null && insn.getRegister(0).equals(insn.getRegister(1))) return 0L;
			return null;
		}

		private boolean samePacket(List<Instruction> path, int first, int last) {
			try {
				for (int i = first; i < last; i++) {
					Instruction following = next(path.get(i));
					if (!parallelWithNext(path.get(i)) || following == null ||
						!following.getMinAddress().equals(path.get(i + 1).getMinAddress())) return false;
				}
				return true;
			}
			catch (MemoryAccessException e) { return false; }
		}

		/** True when {@code later} is in {@code jump}'s execute packet or five delay cycles. */
		private boolean inWindow(Instruction jump, Instruction later) {
			List<Instruction> slots = window(jump);
			if (slots == null) return true; // no complete fall-through proof
			for (Instruction insn : slots) {
				if (insn.getMinAddress().equals(later.getMinAddress())) return true;
			}
			return false;
		}

		/** The rest of {@code jump}'s execute packet and its five delay cycles; null on an incomplete window. */
		private List<Instruction> window(Instruction jump) {
			List<Instruction> slots = new ArrayList<>();
			Instruction current = jump;
			int cycles = 0;
			boolean branchPacket = true;
			try {
				while (cycles < DELAY_CYCLES) {
					int packetCycles = 1;
					do {
						if (branchPacket && !parallelWithNext(current)) break;
						Instruction next = next(current);
						if (next == null || slots.size() >= MAX_WINDOW) return null;
						slots.add(next);
						packetCycles = Math.max(packetCycles, 1 + extraCycles(program, next));
						current = next;
					} while (parallelWithNext(current));
					if (!branchPacket) cycles += packetCycles;
					branchPacket = false;
				}
			}
			catch (MemoryAccessException e) {
				return null;
			}
			return slots;
		}

		/** The address just past {@code jump}'s delay window. */
		private long windowEnd(Instruction jump) {
			List<Instruction> slots = window(jump);
			if (slots == null) return -1;
			Instruction last = slots.isEmpty() ? jump : slots.get(slots.size() - 1);
			return last.getMaxAddress().getOffset() + 1;
		}

		/** True only when {@code at} itself is a physical fetch header. */
		private boolean headerAt(Instruction near, long at) {
			try {
				Address base = near.getMinAddress().getNewAddress(at);
				return (program.getMemory().getInt(base) >>> 28) == 0xe;
			}
			catch (MemoryAccessException | ghidra.program.model.address.AddressOutOfBoundsException e) {
				return false;
			}
		}

		private Instruction next(Instruction current) {
			Instruction next = decode(current.getMaxAddress().next());
			while (next != null && next.getMnemonicString().equals("CPKT")) {
				next = decode(next.getMaxAddress().next());
			}
			return next;
		}

		private Instruction decode(Address at) {
			if (at == null) return null;
			Instruction existing = listing.getInstructionAt(at);
			if (existing != null) return existing;
			if ((!throughData && listing.getDefinedDataContaining(at) != null) ||
				listing.getInstructionContaining(at) != null) return null;
			try {
				return pseudo.disassemble(at);
			}
			catch (Exception e) {
				return null;
			}
		}

		private boolean parallelWithNext(Instruction instruction) throws MemoryAccessException {
			Address address = instruction.getMinAddress();
			if (instruction.getLength() == 4) {
				return (program.getMemory().getInt(address) & 1) != 0;
			}
			long base = address.getOffset() & ~31L;
			int header = program.getMemory().getInt(address.getNewAddress(base + 28));
			if ((header >>> 28) != 0xe) {
				throw new MemoryAccessException("missing compact header at " + address);
			}
			return ((header >>> ((address.getOffset() - base) / 2)) & 1) != 0;
		}
	}

	private static boolean isFlow(Instruction insn) {
		return insn.getFlowType().isJump() || insn.getFlowType().isCall() ||
			insn.getFlowType().isTerminal();
	}

	/**
	 * In an if/else pair sharing one B3 ("call Y if p, else jump to X") only
	 * one arm is a call. A register arm is the call; between two immediate
	 * arms the nearer target is the local else-block, so that arm is the
	 * jump. Both arms to one target (one callee either way) stay calls.
	 */
	static boolean jumpArm(Instruction branch, Instruction partner) {
		Long mine = targetDistance(branch), theirs = targetDistance(partner);
		if (mine == null) return false;
		if (theirs == null) return true;
		if (java.util.Arrays.equals(branch.getFlows(), partner.getFlows())) return false;
		return mine < theirs;
	}

	/** Distance to an immediate branch target, or null for a register branch. */
	private static Long targetDistance(Instruction insn) {
		if (insn.getRegister(0) != null) return null;
		Address[] flows = insn.getFlows();
		if (flows.length != 1) return null;
		return Math.abs(flows[0].getOffset() - insn.getMinAddress().getOffset());
	}

	/** True when two predicated instructions test the same register with opposite senses. */
	static boolean complementary(Instruction a, Instruction b) {
		String p = predicate(a), q = predicate(b);
		if (p == null || q == null) return false;
		return p.replace("!", "").equals(q.replace("!", "")) &&
			p.startsWith("!") != q.startsWith("!");
	}

	private static String predicate(Instruction insn) {
		return predicate(insn.getMnemonicString());
	}

	private static String predicate(String name) {
		// Native delay-slot followers carry "_" before their predicate. Every
		// path proof must read the E1 guard, including constant tracking, not
		// just stability checks (SPRUFE8B 3.5, 3.6 and 4.2.6).
		if (name.startsWith("_")) name = name.substring(1);
		int end = name.indexOf(']');
		return name.startsWith("[") && end > 0 ? name.substring(1, end) : null;
	}

	/** Cycles beyond the first that an instruction idles its execute packet. */
	private static int extraCycles(Program program, Instruction insn) {
		String op = baseName(insn);
		// SPRUFE8B 3.10.2.2: PROT inserts four idle cycles for loads,
		// including full-width loads inside a header-based fetch packet.
		if (op.startsWith("LD")) {
			try { return C6000ExecutionPackets.protectedLoad(program, insn) ? 4 : 0; }
			catch (MemoryAccessException unavailable) { return 0; }
		}
		int operand;
		if (op.equals("NOP")) operand = 0;
		else if (op.startsWith("ADDKPC")) operand = 2;
		else return 0;
		try {
			int count = Integer.decode(insn.getDefaultOperandRepresentation(operand));
			return op.equals("NOP") ? count - 1 : count;
		}
		catch (NumberFormatException | NullPointerException e) {
			return 0;
		}
	}

	/** Mnemonic without a predicate prefix or the compact underscore marker. */
	static String baseName(Instruction insn) {
		String name = insn.getMnemonicString();
		int predicate = name.indexOf(']');
		if (predicate >= 0) name = name.substring(predicate + 1);
		return name.startsWith("_") ? name.substring(1) : name;
	}

	private static boolean adjacent(Instruction a, Instruction b) {
		return b.getMinAddress().getOffset() == a.getMaxAddress().getOffset() + 1;
	}
}
