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
import ghidra.util.Msg;
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
	static final int MAX_WINDOW = 7 + DELAY_CYCLES * 8; // SPRUFE8B 3.5: the rest of an 8-instruction execute packet, then five full ones
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
			// A B B3 is a call too when its slots set B3 past the window (issue #39), and so is a BNOP (issue #69).
			if ((op.equals("B.S1") || op.equals("B.S2") || op.equals("BNOP.S1") || op.equals("BNOP.S2")) &&
				(reclassifiable(program, branch) || missingTarget(branch))) {
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
			if (known && call.target() == null &&
				(call.returnTo() == null || call.returnTo().equals(branch.getFallThrough()))) continue;
			branch.setFlowOverride(FlowOverride.CALL);
			Address next = branch.getMaxAddress().next();
			if (call.returnTo() != null) branch.setFallThrough(call.returnTo());
			else if (branch.getFallThrough() == null) branch.setFallThrough(next);
			if (listing.getInstructionAt(next) == null) disassembler.disassemble(next, null, true);
			// Delay slots start after the branch's whole execute packet (SPRUFE8B 3.5, 4.2.6).
			Address slots = packetEnd(program, listing.getInstructionAt(at));
			if (slots != null && listing.getInstructionAt(slots) == null) disassembler.disassemble(slots, null, true);
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
		if (recovered > 0) Msg.info(this, getName() + "> recovered " + recovered + " delayed call(s)");
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
		// C6000 Returns marks every B B3 a return by name; only a proven call overrides it
		// (issue #39), and the return analyzer never touches a CALL, so they cannot loop.
		if (override == FlowOverride.RETURN) return "B3".equals(branch.getDefaultOperandRepresentation(0));
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

	/** A recognised call; {@code target} for a known register branch, {@code returnTo} for a return to earlier code. */
	private record Call(Address target, Address returnTo) {
	}

	/**
	 * A jump whose target only idles until a return issued in its delay
	 * window lands: the compiler's jump into a shared epilogue's NOP tail
	 * (SPRUFE8B 3.5, 4.2.6 B; 3.12 NOP: a landing branch ends a multicycle NOP).
	 * Taken, the jump changes nothing but which NOPs fill the transfer's last
	 * {@code cycle} delay cycles. {@code windowEnd} is the jump's last delay
	 * byte, {@code landing} the address just past those NOPs at the target, and
	 * {@code exact} whether a return window cut at {@code windowEnd} is its
	 * window on every path: the return is taken only with the jump, or the
	 * straight-line code it would otherwise run is NOPs too.
	 */
	record Preemption(Instruction jump, Instruction transfer, int cycle, Address windowEnd,
			Address landing, boolean exact) {
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
		/** Set by recognize: a predicated call's return to earlier code (issue #66). */
		private Address backwardReturn;

		Walker(Program program) {
			this.program = program;
			this.listing = program.getListing();
			this.pseudo = new PseudoDisassembler(program);
		}

		/** The return point, in its caller at or before it, of a predicated displacement B to another function; else null. */
		Address predicatedBackwardCall(Instruction branch) {
			backwardReturn = null;
			if (predicate(branch) == null || !(baseName(branch).equals("B.S1") || baseName(branch).equals("B.S2")) ||
				branch.getRegister(0) != null) return null;
			recognize(branch);
			return backwardReturn;
		}

		/** The first transfer issued in a delay cycle of {@code branch}, which lands after it (SPRUFE8B 3.5, 4.2.6); else null. */
		Instruction nestedTransfer(Instruction branch) {
			List<Instruction> slots = window(branch, delayCycles(branch));
			if (slots == null) return null;
			List<Instruction> execution = new ArrayList<>(slots);
			execution.add(0, branch);
			int[] issue = issueCycles(execution);
			for (int i = 1; i < execution.size(); i++) {
				if (issue[i] > 0 && transfer(execution.get(i))) return execution.get(i);
			}
			return null;
		}

		/** What one model runs on one path: instructions and calls in order, then where control goes. */
		private record Run(List<String> trace, String exit, String unproven) {
			static Run unproven(String why) { return new Run(List.of(), null, why); }
		}

		/** The instructions a comparison covers, and what it knows about them. */
		private record Stretch(Address start, Address stop, List<Instruction> path, Map<Address, Integer> index,
				List<Integer> predicated, List<Address> returns) {}

		private static final int MAX_PATH_TRANSFERS = 12, MAX_ISSUED = 512;

		/**
		 * Null when native lifting runs exactly what the hardware runs through {@code outer}'s delay
		 * window and every window issued in it, on each consistent outcome of their predicates; otherwise
		 * what native lifting gets wrong there.
		 *
		 * Hardware: each execute packet issues in its cycle; a taken B, BNOP or CALLP lands six cycles
		 * after its packet, cutting idle cycles short, and execution goes on at its target while other
		 * transfers are still in flight (SPRUFE8B 3.5, 3.12 BNOP/NOP/CALLP, 4.2.6). Native: each listing
		 * instruction in address order, a laid window's slots before its branch, then the branch's lifted
		 * flow, overrides included, or its fall-through. In both, a call that lands with nothing else in
		 * flight runs its callee and resumes at its return point, and a walk ends when control leaves the
		 * compared stretch with nothing in flight. An instruction whose predicate is false on a path does
		 * nothing, so it is left out of both traces.
		 */
		String nativeMismatch(Instruction outer) {
			// Start where nothing is in flight; a jump into outer from elsewhere starts there too.
			Instruction first = settled(outer);
			String why = compare(first, outer);
			if (why == null && first != outer) {
				for (Reference ref : program.getReferenceManager().getReferencesTo(outer.getMinAddress())) {
					if (ref.getReferenceType().isFlow() && !ref.getReferenceType().isFallthrough()) return compare(outer, outer);
				}
			}
			return why;
		}

		/** The instructions physically before {@code insn} that issue in the cycles a transfer can stay in flight. */
		private List<Instruction> before(Instruction insn) {
			List<Instruction> prior = new ArrayList<>();
			Instruction at = insn;
			while (prior.size() < MAX_WINDOW) {
				Instruction previous = listing.getInstructionBefore(at.getMinAddress());
				if (previous == null || (!adjacent(previous, at) && !headerBetween(previous, at))) break;
				prior.add(0, previous);
				at = previous;
				List<Instruction> path = new ArrayList<>(prior);
				path.add(insn);
				int[] issue = issueCycles(path);
				if (issue[path.size() - 1] - issue[0] > 1 + DELAY_CYCLES) break;
			}
			return prior;
		}

		/** Only a fetch-packet header lies between {@code a} and {@code b}. */
		private boolean headerBetween(Instruction a, Instruction b) {
			long gap = a.getMaxAddress().getOffset() + 1;
			return (gap & 31) == 28 && headerAt(a, gap) && gap + 4 == b.getMinAddress().getOffset();
		}

		/** The earliest transfer physically before {@code transfer} that may still be in flight when it issues. */
		private Instruction settled(Instruction transfer) {
			Instruction start = transfer;
			for (int guard = 0; guard < 8; guard++) {
				List<Instruction> path = new ArrayList<>(before(start));
				int at = path.size();
				path.add(start);
				int[] issue = issueCycles(path);
				Instruction earliest = null;
				for (int j = 0; j < at && earliest == null; j++) {
					if (transfer(path.get(j)) && issue[j] + 1 + DELAY_CYCLES >= issue[at]) earliest = path.get(j);
				}
				if (earliest == null) return start;
				start = earliest;
			}
			return start;
		}

		/** Compare from {@code first}, where nothing is in flight, through {@code outer}'s windows. */
		private String compare(Instruction first, Instruction outer) {
			List<Instruction> stretch = new ArrayList<>();
			long end = Math.max(windowEnd(first), windowEnd(outer));
			if (windowEnd(first) < 0 || windowEnd(outer) < 0) return "a delay window there is incomplete";
			Instruction current = first;
			while (current != null && current.getMinAddress().getOffset() < end) {
				if (stretch.size() > 4 * MAX_WINDOW) return "its nested windows are too long to compare";
				stretch.add(current);
				if (transfer(current)) {
					long e = windowEnd(current);
					if (e < 0) return "the window of " + current + " at " + current.getMinAddress() + " is incomplete";
					end = Math.max(end, e);
				}
				current = next(current);
			}
			if (current == null) return "the code after its windows does not decode";
			List<Instruction> path = new ArrayList<>(before(first));
			int base = path.size();
			path.addAll(stretch);
			Map<Address, Integer> index = new HashMap<>();
			List<Integer> predicated = new ArrayList<>();
			List<Address> returns = new ArrayList<>();
			for (int i = base; i < path.size(); i++) {
				Instruction insn = path.get(i);
				index.put(insn.getMinAddress(), i);
				if (!transfer(insn)) continue;
				if (predicate(insn) != null) predicated.add(i);
				Instruction listed = listing.getInstructionAt(insn.getMinAddress());
				if (listed != null && listed.getFlowType().isCall() && listed.getFallThrough() != null) returns.add(listed.getFallThrough());
			}
			if (predicated.size() > MAX_PATH_TRANSFERS) return "it has too many predicated transfers to compare";
			Stretch region = new Stretch(first.getMinAddress(), current.getMinAddress(), path, index, predicated, returns);

			for (int mask = 0; mask < 1 << predicated.size(); mask++) {
				// One outcome per predicated transfer, kept only when its predicates can agree.
				Map<Address, Boolean> taken = new HashMap<>();
				List<PredicateFact> facts = new ArrayList<>();
				boolean consistent = true;
				for (int v = 0; v < predicated.size() && consistent; v++) {
					int i = predicated.get(v);
					boolean value = (mask >> v & 1) != 0;
					Boolean forced = holds(region, i, facts);
					consistent = forced == null || forced == value;
					taken.put(path.get(i).getMinAddress(), value);
					addFact(facts, i, path.get(i), value);
				}
				if (!consistent) continue;
				Run hardware = hardware(first, region, taken, facts);
				if (hardware.unproven() != null) return hardware.unproven();
				Run lifted = lifted(first, region, taken, facts);
				if (lifted.unproven() != null) return lifted.unproven();
				if (!hardware.trace().equals(lifted.trace()) || !hardware.exit().equals(lifted.exit()))
					return difference(region, taken, hardware, lifted);
			}
			return null;
		}

		/** The facts that still hold at {@code i}: a callee may change any predicate register, so none crosses a call's return. */
		private static List<PredicateFact> factsFor(Stretch region, int i, List<PredicateFact> facts) {
			if (region.returns().isEmpty()) return facts;
			int segment = segment(region, i);
			List<PredicateFact> kept = new ArrayList<>();
			for (PredicateFact fact : facts) if (segment(region, fact.index()) == segment) kept.add(fact);
			return kept;
		}

		private static int segment(Stretch region, int i) {
			Address at = region.path().get(i).getMinAddress();
			int count = 0;
			for (Address back : region.returns()) if (back.compareTo(at) <= 0) count++;
			return count;
		}

		/** False when a predicate known on this path keeps {@code insn} from running. */
		private boolean runs(Instruction insn, Stretch region, List<PredicateFact> facts) {
			Integer i = region.index().get(insn.getMinAddress());
			if (i == null || predicate(insn) == null) return true;
			return holds(region, i, facts) != Boolean.FALSE;
		}

		/**
		 * Whether the predicate of path instruction {@code i} holds on this path: from another
		 * transfer's outcome on the same stable register, or else from the last write to that register
		 * that lands before it reads it, when that write runs and its p-code gives a constant. Null when
		 * neither decides it. Nothing is carried across a call's return.
		 */
		private Boolean holds(Stretch region, int i, List<PredicateFact> facts) {
			List<Instruction> path = region.path();
			List<PredicateFact> known = factsFor(region, i, facts);
			Boolean value = executes(path, i, known);
			if (value != null) return value;
			String p = predicate(path.get(i));
			Register register = program.getRegister(p.replace("!", ""));
			int[] cycles = issueCycles(path);
			Set<Integer> skipped = new HashSet<>();
			while (true) {
				int last = -1;
				long lands = Long.MIN_VALUE;
				boolean tie = false;
				for (int w = 0; w < i; w++) {
					if (skipped.contains(w)) continue;
					Instruction writer = path.get(w);
					Register load = loadDestination(writer);
					boolean writes = load != null ? overlaps(load, register) :
						issueWrites(writer).stream().anyMatch(r -> overlaps(r, register));
					long at = cycles[w] + resultDelay(writer);
					if (!writes || at >= cycles[i]) continue;
					if (at > lands) { lands = at; last = w; tie = false; }
					else if (at == lands) tie = true;
				}
				if (last < 0 || tie || segment(region, last) != segment(region, i)) return null;
				Boolean runs = predicate(path.get(last)) == null ? Boolean.TRUE : executes(path, last, known);
				if (runs == null) return null;
				if (!runs) { skipped.add(last); continue; }
				Long written = constantWrite(path.get(last), register);
				return written == null ? null : (written != 0) != p.startsWith("!");
			}
		}

		private static boolean idle(Instruction insn) {
			String op = baseName(insn);
			return op.equals("NOP") || op.equals("CPKT");
		}

		private static boolean inside(Address at, Stretch region) {
			return at.compareTo(region.start()) >= 0 && at.compareTo(region.stop()) < 0;
		}

		private static String destination(Instruction transfer, Address target) {
			return target != null ? target.toString() : "the address in " + transfer.getRegister(0) + " read at " + transfer.getMinAddress();
		}

		private record Flight(long lands, Instruction transfer) {}

		private Run hardware(Instruction first, Stretch region, Map<Address, Boolean> taken, List<PredicateFact> facts) {
			List<String> trace = new ArrayList<>();
			List<Flight> flights = new ArrayList<>();
			Set<Address> issued = new HashSet<>();
			Instruction at = first;
			long cycle = 0;
			try {
				while (true) {
					// One execute packet, issued in this cycle.
					int span = 1;
					Instruction insn = at;
					while (true) {
						if (!issued.add(insn.getMinAddress())) return new Run(trace, "issues " + insn.getMinAddress() + " again", null);
						if (issued.size() > MAX_ISSUED) return Run.unproven("its windows issue too many instructions to compare");
						span = Math.max(span, 1 + extraCycles(program, insn));
						if (baseName(insn).startsWith("CALLP")) span = Math.max(span, 1 + DELAY_CYCLES);
						if (transfer(insn)) {
							Boolean go = predicate(insn) == null ? Boolean.TRUE : taken.get(insn.getMinAddress());
							if (go == null) return Run.unproven(insn + " at " + insn.getMinAddress() + " issues with transfers in flight, on a predicate this check cannot follow");
							if (go) flights.add(new Flight(cycle + 1 + DELAY_CYCLES, insn));
						}
						else if (!idle(insn) && runs(insn, region, facts)) trace.add(insn.getMinAddress().toString());
						if (!parallelWithNext(insn)) break;
						insn = next(insn);
						if (insn == null) return Run.unproven("an execute packet does not decode");
					}
					long nextCycle = cycle + span;
					Flight landing = null;
					for (Flight flight : flights) if (landing == null || flight.lands() < landing.lands()) landing = flight;
					if (landing != null && landing.lands() <= nextCycle) {
						// The landing cuts idle cycles short and redirects fetch.
						flights.remove(landing);
						Instruction transfer = landing.transfer();
						Address target = transfer.getRegister(0) != null || transfer.getDefaultFlows().length != 1 ? null :
							transfer.getDefaultFlows()[0];
						Instruction listed = listing.getInstructionAt(transfer.getMinAddress());
						if (listed != null && listed.getFlowType().isCall()) {
							// The callee runs to its return, which needs nothing else in flight.
							if (!flights.isEmpty()) return new Run(trace, "calls " + destination(transfer, target) + " with transfers in flight", null);
							trace.add("calls " + destination(transfer, target));
							if (listed.getFallThrough() == null) return new Run(trace, "does not return", null);
							at = decode(listed.getFallThrough());
							cycle = landing.lands();
						}
						else {
							if (target == null) {
								if (flights.isEmpty()) return new Run(trace, "continues at " + destination(transfer, null), null);
								return Run.unproven(transfer + " at " + transfer.getMinAddress() + " lands at a register target with transfers still in flight");
							}
							if (flights.isEmpty() && !inside(target, region)) return new Run(trace, "continues at " + target, null);
							at = decode(target);
							cycle = landing.lands();
						}
						if (at == null) return Run.unproven("code at a landing does not decode");
						if (flights.isEmpty() && !inside(at.getMinAddress(), region))
							return new Run(trace, "continues at " + at.getMinAddress(), null);
						continue;
					}
					at = next(insn);
					if (at == null) return Run.unproven("the code after " + insn.getMinAddress() + " does not decode");
					cycle = nextCycle;
					if (flights.isEmpty() && !inside(at.getMinAddress(), region))
						return new Run(trace, "continues at " + at.getMinAddress(), null);
				}
			}
			catch (MemoryAccessException e) {
				return Run.unproven("a packet's parallel bits cannot be read");
			}
		}

		private Run lifted(Instruction first, Stretch region, Map<Address, Boolean> taken, List<PredicateFact> facts) {
			List<String> trace = new ArrayList<>();
			Set<Address> seen = new HashSet<>();
			Instruction insn = listing.getInstructionAt(first.getMinAddress());
			while (true) {
				if (insn == null) return new Run(trace, "has no instruction to lift", null);
				Address at = insn.getMinAddress();
				if (!inside(at, region)) return new Run(trace, "continues at " + at, null);
				if (!seen.add(at)) return new Run(trace, "issues " + at + " again", null);
				Address next = insn.getFallThrough();
				if (transfer(insn)) {
					// A laid window's slots run before the branch; Ghidra lays none that holds a transfer.
					Address last = insn.getMaxAddress().add(insn.getPrototype().getDelaySlotByteCount());
					for (Instruction slot = listing.getInstructionAfter(insn.getMaxAddress());
							slot != null && slot.getMinAddress().compareTo(last) <= 0;
							slot = listing.getInstructionAfter(slot.getMaxAddress())) {
						if (!idle(slot) && runs(slot, region, facts)) trace.add(slot.getMinAddress().toString());
					}
					Boolean go = predicate(insn) == null ? Boolean.TRUE : taken.get(at);
					if (go == null) return Run.unproven(insn + " at " + at + " is lifted on a predicate this check cannot follow");
					if (go) {
						Address target = insn.getRegister(0) != null ? null : liftedTarget(insn);
						if (target == null && insn.getRegister(0) == null)
							return Run.unproven(insn + " at " + at + " has no single lifted target");
						if (insn.getFlowType().isCall()) {
							trace.add("calls " + destination(insn, target));
							if (next == null) return new Run(trace, "does not return", null);
						}
						else if (target == null || !inside(target, region)) return new Run(trace, "continues at " + destination(insn, target), null);
						else next = target;
					}
				}
				else if (!idle(insn) && runs(insn, region, facts)) trace.add(at.toString());
				if (next == null) return new Run(trace, "stops after " + at, null);
				insn = listing.getInstructionAt(next);
			}
		}

		/** Where Ghidra sends a taken transfer: its one flow reference that is not a fall-through, the primary one if several. */
		private static Address liftedTarget(Instruction insn) {
			Address found = null, primary = null;
			int count = 0;
			for (Reference ref : insn.getReferencesFrom()) {
				if (!ref.getReferenceType().isFlow() || ref.getReferenceType().isFallthrough()) continue;
				count++;
				found = ref.getToAddress();
				if (ref.isPrimary()) primary = found;
			}
			if (count == 0) return insn.getDefaultFlows().length == 1 ? insn.getDefaultFlows()[0] : null;
			return count == 1 ? found : primary;
		}

		private String difference(Stretch region, Map<Address, Boolean> taken, Run hardware, Run lifted) {
			StringBuilder when = new StringBuilder();
			for (int i : region.predicated()) {
				Instruction t = region.path().get(i);
				when.append(when.length() == 0 ? "" : ", ").append(t).append(" at ").append(t.getMinAddress())
					.append(taken.get(t.getMinAddress()) ? " taken" : " not taken");
			}
			List<String> h = hardware.trace(), n = lifted.trace();
			int k = 0;
			while (k < h.size() && k < n.size() && h.get(k).equals(n.get(k))) k++;
			String what = k < h.size() || k < n.size() ?
				"the hardware " + (k < h.size() ? step(h.get(k)) : "runs nothing more") + " where native lifting " +
					(k < n.size() ? step(n.get(k)) : "runs nothing more") :
				"the hardware " + hardware.exit() + " where native lifting " + lifted.exit();
			return (when.length() == 0 ? "" : "with " + when + ", ") + what;
		}

		private static String step(String entry) {
			return entry.startsWith("calls ") ? entry : "runs " + entry;
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
						// The other arm is still in flight when this one issues (SPRUFE8B 3.5).
						issue[branchIndex] - issue[i] <= DELAY_CYCLES) partner = insn;
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

			// The rest of the branch's execute packet, then its delay cycles: five, or 5 - n after BNOP n.
			Register b3 = program.getRegister("B3");
			int delay = delayCycles(branch);
			Instruction current = branch;
			int cycles = 0;
			int seen = 0;
			boolean compact = branch.getLength() != 4;
			boolean branchPacket = true;
			try {
				window: do {
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
				} while (cycles < delay);
			}
			catch (MemoryAccessException e) {
				return null;
			}
			// Retire every pending write, including idle cycles represented by
			// ADDKPC/NOP/BNOP. A load's E5, or a later multi-cycle result
			// (MPYI lands in E9), supersedes an earlier E1 link even after the
			// callee is entered.
			trace.before(Integer.MAX_VALUE);
			if (partner != null && jumpArm(branch, partner)) return null;
			long[] ret = regs.get(b3);
			// B3 may also be set on the look-back path.
			if (ret == null || ret[1] != FULL) return null;
			long branchAt = branch.getMinAddress().getOffset();
			long windowEnd = current.getMaxAddress().getOffset() + 1;
			Address callee = target == null ? null :
				branch.getMinAddress().getNewAddress(target & 0xffffffffL);
			if (callee != null && !program.getMemory().contains(callee)) callee = null;
			if (predicate(branch) != null && partner == null && branch.getRegister(0) == null && ret[0] <= branchAt) {
				// A predicated call needs two fall-throughs, the return and the not-taken path (issue #66).
				backwardReturn = loopReturn(branch, ret[0]);
				return null;
			}
			if (ret[0] < branchAt) {
				// A register call has no native window.
				Address loop = partner == null && predicate(branch) == null && branch.getRegister(0) == null &&
					freshLink(execution, branchIndex, b3, facts) ? loopReturn(branch, ret[0]) : null;
				return loop == null ? null : new Call(null, loop);
			}
			if (ret[0] < branchAt + 4 || ret[0] > windowEnd + 8) return null;
			// B3 already held the return address when the B read it: a computed jump
			// to the fall-through, not a call (issue #39).
			if (target != null && (target & 0xffffffffL) == (ret[0] & 0xffffffffL)) return null;
			boolean headerAtEnd = (windowEnd & 31) == 28 && headerAt(branch, windowEnd);
			long partnerEnd = partner == null ? -1 : windowEnd(partner);
			if (ret[0] != windowEnd && !(compact && ret[0] <= windowEnd + 8) &&
				!(headerAtEnd && ret[0] == windowEnd + 4) && ret[0] != partnerEnd) return null;
			return new Call(callee, null);
		}

		/** B3 was last written after every earlier branch's window, so it is not an earlier call's link. */
		private boolean freshLink(List<Instruction> execution, int branchIndex, Register b3, List<PredicateFact> facts) {
			int writer = -1, after = -1;
			for (int i = 0; i < execution.size(); i++) {
				Instruction insn = execution.get(i);
				if (i < branchIndex && insn != viaInsn && isFlow(insn)) {
					List<Instruction> slots = window(insn, delayCycles(insn));
					if (slots == null) return false;
					after = i + slots.size();
				}
				// A nullified write leaves the old link, and MVKH keeps its low half.
				if (Boolean.FALSE.equals(executes(execution, i, facts)) || baseName(insn).startsWith("MVKH")) continue;
				Register load = loadDestination(insn);
				if ((load != null && overlaps(load, b3)) ||
					issueWrites(insn).stream().anyMatch(r -> overlaps(r, b3))) writer = i;
			}
			return writer > after;
		}

		/** Return address of a call to another function whose B3 is the caller's earlier code (SPRUFE8B 4.2.6, B). */
		private Address loopReturn(Instruction branch, long ret) {
			Function caller = listing.getFunctionContaining(branch.getMinAddress());
			if (caller == null) return null;
			Address to = branch.getMinAddress().getNewAddress(ret & 0xffffffffL);
			Instruction back = listing.getInstructionAt(to);
			if (!caller.getBody().contains(to) || back == null || back.isInDelaySlot()) return null;
			Address[] flows = branch.getFlows();
			Function callee = flows.length == 1 ? program.getFunctionManager().getFunctionAt(flows[0]) : null;
			return callee == null || callee.equals(caller) ? null : to;
		}

		/** A displacement B that Ghidra types as a jump; its target is the encoded one. */
		static boolean displacementJump(Instruction insn) {
			String op = baseName(insn);
			var flow = insn.getFlowType();
			return (op.equals("B.S1") || op.equals("B.S2")) && insn.getLength() == 4 &&
				insn.getRegister(0) == null && !insn.isInDelaySlot() &&
				insn.getFlowOverride() == FlowOverride.NONE && flow.isJump() && !flow.isCall() &&
				!flow.isTerminal() && insn.getDefaultFlows().length == 1;
		}

		/** Any branch: a transfer in flight decides where execution continues. */
		private static boolean transfer(Instruction insn) {
			String op = baseName(insn);
			return isFlow(insn) || op.startsWith("B.") || op.startsWith("BNOP.") || op.startsWith("CALLP.");
		}

		/**
		 * The transfer that preempts {@code jump}, or null. Every other transfer
		 * in the window must be the opposite arm, not taken with the jump.
		 */
		Preemption preemption(Instruction jump) {
			if (!displacementJump(jump)) return null;
			Address target = jump.getDefaultFlows()[0];
			// idle() below needs a NOP at the target: most jumps stop here, before the window is decoded.
			Instruction first = decode(target);
			if (first == null || first.getLength() != 4 || !baseName(first).equals("NOP")) return null;
			try {
				for (Address at : C6000ExecutionPackets.issuePrefix(program, jump.getMinAddress())) {
					Instruction prior = decode(at);
					if (prior == null || prior.getLength() != 4 || transfer(prior)) return null;
				}
			}
			catch (MemoryAccessException e) {
				return null;
			}
			List<Instruction> slots = window(jump);
			if (slots == null || slots.isEmpty()) return null;
			for (Instruction slot : slots) {
				String name = baseName(slot);
				// Unbounded or loop-buffer timing: no cycle count to compare.
				if (slot.getLength() != 4 || name.equals("IDLE") || name.startsWith("SPLOOP") || name.startsWith("SPKERNEL") ||
					name.startsWith("SPMASK") || name.equals("SWE") || name.equals("SWENR")) return null;
			}
			List<Instruction> execution = new ArrayList<>(lookBack(jump));
			int at = execution.size();
			execution.add(jump);
			execution.addAll(slots);
			int[] issue = issueCycles(execution);
			String guard = predicate(jump);
			int found = -1;
			for (int i = at + 1; i < execution.size(); i++) {
				Instruction slot = execution.get(i);
				// A NOP generator in the jump's own packet already spends delay cycles.
				if (issue[i] == issue[at] && extraCycles(program, slot) > 0) return null;
				if (!transfer(slot)) continue;
				if (issue[i] == issue[at]) return null;
				if (complementary(jump, slot) && stable(execution, i, at, guard, true)) continue;
				if (found >= 0) return null;
				found = i;
			}
			if (found < 0) return null;
			Instruction transfer = execution.get(found);
			String op = baseName(transfer);
			if (!op.equals("B.S1") && !op.equals("B.S2")) return null;
			int cycle = issue[found] - issue[at];
			if (cycle < 1 || cycle > DELAY_CYCLES) return null;
			// Taken with the jump: unconditional, or under the jump's own stable predicate.
			String own = predicate(transfer);
			boolean exclusive;
			if (own == null) exclusive = guard == null;
			else if (own.equals(guard) && stable(execution, found, at, guard, true)) exclusive = true;
			else return null;
			int end = execution.size() - 1;
			Address windowEnd = execution.get(end).getMaxAddress();
			if (target.compareTo(jump.getMinAddress()) >= 0 && target.compareTo(windowEnd) <= 0) return null;
			Address landing = idle(decode(target), cycle);
			if (landing == null) return null;
			// Not taken, the transfer's last cycles run straight on: the rest
			// of a multicycle NOP that outlasts the jump's window, then what follows.
			int span = 1;
			for (int i = end; i > at && issue[i] == issue[end]; i--) {
				span = Math.max(span, 1 + extraCycles(program, execution.get(i)));
			}
			int beyond = issue[end] + span - 1 - (issue[at] + DELAY_CYCLES);
			boolean idleAfter = beyond >= cycle || idle(next(execution.get(end)), cycle - Math.max(0, beyond)) != null;
			return new Preemption(jump, transfer, cycle, windowEnd, landing, exclusive || idleAfter);
		}

		/** The address after {@code cycles} cycles of NOP-only execute packets from {@code start}, else null. */
		private Address idle(Instruction start, int cycles) {
			Instruction current = start;
			try {
				while (current != null) {
					int span = 1;
					while (true) {
						if (current.getLength() != 4 || !baseName(current).equals("NOP")) return null;
						span = Math.max(span, 1 + extraCycles(program, current));
						if (!parallelWithNext(current)) break;
						current = next(current);
						if (current == null) return null;
					}
					cycles -= span;
					if (cycles <= 0) return current.getMaxAddress().next();
					current = next(current);
				}
			}
			catch (MemoryAccessException e) {
				return null;
			}
			return null;
		}

		/**
		 * The preemption whose transfer is {@code transfer}, from a decoded jump
		 * before it; the code between may still be undecoded.
		 */
		Preemption preempting(Instruction transfer) {
			Address at = transfer.getMinAddress();
			for (int i = 1; i <= MAX_WINDOW && at.getOffset() >= 4L * i; i++) {
				Instruction jump = listing.getInstructionAt(at.subtract(4L * i));
				if (jump == null || !displacementJump(jump)) continue;
				Preemption found = preemption(jump);
				if (found != null && found.transfer().getMinAddress().equals(at)) return found;
			}
			return null;
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

		/** LD*, and LL/CMTL, which also write in E5 (SPRU732, LL and CMTL). */
		private static Register loadDestination(Instruction insn) {
			String name = baseName(insn);
			return loadDestinationName(name) && insn.getNumOperands() >= 2 ? insn.getRegister(insn.getNumOperands() - 1) : null;
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
				int delay = resultDelay(insn);
				if (delay > 0) {
					// The old value stays until the last result write; neither is a constant.
					for (Register r : issueWrites(insn)) { write(cycle, r, null, owner);write(cycle + delay, r, null, owner); }
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
					if (insn != null && baseName(insn).equals("CPKT")) insn = next(insn);
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
				Instruction insn = path.get(i);int delay = resultDelay(insn);Register load = loadDestination(insn);
				if (delay == 0 || cycles[i] + delay < first || cycles[i] + delay >= last ||
					(load != null ? !overlaps(load, register) : issueWrites(insn).stream().noneMatch(r -> overlaps(r, register)))) continue;
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
		/** The constant {@code insn} writes to {@code register} when it runs, from its p-code; null if none. */
		private Long constantWrite(Instruction insn, Register register) {
			if (transfer(insn)) return null;
			String p = predicate(insn);
			Register guard = p == null ? null : program.getRegister(p.replace("!", ""));
			var code = insn.getPcode();
			long offset = register.getAddress().getOffset();
			int size = register.getMinimumByteSize();
			if (guard == null) return C6000LoopCounterProof.constantOutput(program.getLanguage(), code, offset, size);
			// Running means its predicate held.
			return C6000LoopCounterProof.constantOutput(program.getLanguage(), code, offset, size,
				guard.getAddress().getOffset(), guard.getMinimumByteSize(), p.startsWith("!") ? 0 : 1);
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

		/** The rest of {@code jump}'s execute packet and its delay cycles (delayCycles); null on an incomplete window. */
		private List<Instruction> window(Instruction jump) {
			return window(jump, delayCycles(jump));
		}

		/** The rest of {@code jump}'s execute packet and {@code delay} cycles after it; null on an incomplete window. */
		private List<Instruction> window(Instruction jump, int delay) {
			if (delay < 0) return null;
			List<Instruction> slots = new ArrayList<>();
			Instruction current = jump;
			int cycles = 0;
			boolean branchPacket = true;
			try {
				do {
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
				} while (cycles < delay);
			}
			catch (MemoryAccessException e) {
				return null;
			}
			return slots;
		}

		/** Delay cycles left for physical slots: none after CALLP, 5 - n after BNOP n (SPRUFE8B 3.12 BNOP, CALLP). */
		private static int delayCycles(Instruction insn) {
			String op = baseName(insn);
			if (op.startsWith("CALLP")) return 0;
			if (!op.startsWith("BNOP")) return DELAY_CYCLES;
			Scalar n = insn.getScalar(1);
			return n == null ? -1 : Math.max(0, DELAY_CYCLES - (int) n.getValue());
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
			// A header decoded in a laid delay window is "_CPKT": skip it as well, or it takes a cycle
			// (SPRUFE8B 3.10).
			while (next != null && baseName(next).equals("CPKT")) {
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

	private static Address packetEnd(Program program, Instruction insn) {
		try {
			while (insn != null && C6000ExecutionPackets.parallelWithNext(program, insn)) {
				insn = program.getListing().getInstructionAt(insn.getMaxAddress().next());
			}
		}
		catch (MemoryAccessException e) {
			return null;
		}
		return insn == null ? null : insn.getMaxAddress().next();
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
		// Where the function bodies already say which target is the caller's own code, that decides.
		Boolean local = localTarget(branch), other = localTarget(partner);
		if (local != null && other != null && !local.equals(other)) return local;
		// ponytail: distance only while bodies are incomplete; the nearer target is the local else-block.
		return mine < theirs;
	}

	/** True when an immediate branch targets its own function's code, false for another function's entry or body; null if unknown. */
	private static Boolean localTarget(Instruction insn) {
		Address[] flows = insn.getDefaultFlows();
		if (insn.getRegister(0) != null || flows.length != 1) return null;
		var functions = insn.getProgram().getFunctionManager();
		Function caller = functions.getFunctionContaining(insn.getMinAddress());
		Function entered = functions.getFunctionAt(flows[0]);
		if (entered != null) return caller == null ? null : entered.equals(caller);
		Function owner = functions.getFunctionContaining(flows[0]);
		if (caller == null || owner == null) return null;
		return owner.equals(caller);
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

	private static final Set<String> ONE_DELAY = Set.of("MPY", "MPYU", "MPYUS", "MPYSU", "MPYH", "MPYHU",
		"MPYHUS", "MPYHSU", "MPYHL", "MPYHLU", "MPYHULS", "MPYHSLU", "MPYLH", "MPYLHU", "MPYLUHS", "MPYLSHU",
		"SMPY", "SMPYH", "SMPYHL", "SMPYLH", "AVG2", "AVGU4", "BITC4", "BITR", "DEAL", "SHFL", "ROTL",
		"XPND2", "XPND4", "SPDP", "ABSDP", "RCPDP", "RSQRDP", "CMPEQDP", "CMPGTDP", "CMPLTDP");
	private static final Set<String> THREE_DELAY = Set.of("ADDSP", "SUBSP", "MPYSP", "INTSP", "INTSPU",
		"SPINT", "SPTRUNC", "DPSP", "DPINT", "DPTRUNC");
	private static final Map<String, Integer> LONG_DELAY = Map.of("INTDP", 4, "INTDPU", 4, "MPYSP2DP", 4,
		"ADDDP", 6, "SUBDP", 6, "MPYSPDP", 6, "MPYI", 8, "MPYID", 9, "MPYDP", 9);

	/**
	 * Delay slots before an instruction's last register result lands
	 * (SPRUFE8B 4.2 and each instruction's pipeline table; SPRU733A for
	 * C67x floating point). Loads, LL and CMTL write in E5.
	 * ponytail: any other .M instruction is taken as three delay slots, the
	 * C64x+ multiply latency; an overestimate only loses a call proof.
	 */
	static int resultDelay(Instruction insn) {
		String name = baseName(insn);
		if (loadDestinationName(name)) return 4;
		int dot = name.indexOf('.');
		String op = dot < 0 ? name : name.substring(0, dot);
		if (LONG_DELAY.containsKey(op)) return LONG_DELAY.get(op);
		if (THREE_DELAY.contains(op)) return 3;
		if (ONE_DELAY.contains(op)) return 1;
		return dot >= 0 && name.startsWith("M", dot + 1) ? 3 : 0;
	}

	private static boolean loadDestinationName(String name) {
		return name.startsWith("LD") || name.startsWith("LL.") || name.startsWith("CMTL.");
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
		// SPRUFE8B 3.12 BNOP: the NOP cycles are inserted whether or not
		// the branch is taken.
		else if (op.startsWith("BNOP")) operand = 1;
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
