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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.WeakHashMap;

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
import ghidra.program.model.lang.InstructionPrototype;
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
			// A latched branch transfers where it lands, and an override on it would change a landing it carries.
			if (branch == null || C6000PacketStagingAnalyzer.inert(branch)) continue;
			Call call = walker.recognize(branch);
			if (call == null) continue;
			boolean known = branch.getFlowOverride() == FlowOverride.CALL;
			if (known && call.target() == null &&
				(call.returnTo() == null || call.returnTo().equals(branch.getFallThrough()))) continue;
			branch.setFlowOverride(FlowOverride.CALL);
			Address next = branch.getMaxAddress().next();
			if (call.returnTo() != null) branch.setFallThrough(call.returnTo());
			else if (branch.getFallThrough() == null) branch.setFallThrough(next);
			if (listing.getInstructionAt(next) == null) C6000DelaySlots.announce(program, disassembler.disassemble(next, null, true));
			// Delay slots start after the branch's whole execute packet (SPRUFE8B 3.5, 4.2.6).
			Address slots = packetEnd(program, listing.getInstructionAt(at));
			if (slots != null && listing.getInstructionAt(slots) == null) C6000DelaySlots.announce(program, disassembler.disassemble(slots, null, true));
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

	/**
	 * A recognised call; {@code target} for a known register branch, {@code link} the address B3 holds
	 * when it lands, {@code returnTo} that address when it is earlier code, which has no window to wait for.
	 */
	private record Call(Address target, Address returnTo, Address link) {
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

		/**
		 * True when {@code flag}, written at path index {@code compare} and nonzero for an index out of
		 * range, keeps the transfer at {@code dispatch} from issuing taken out of range: the dispatch is
		 * predicated on the flag being zero, or a branch taken on the flag lands before the dispatch can
		 * issue, and the flag is unchanged meanwhile (SPRUFE8B 3.5, 3.6, 4.2.6).
		 */
		boolean guards(List<Instruction> path, int compare, Register flag, int dispatch) {
			int[] cycles = issueCycles(path);
			String own = predicate(path.get(dispatch));
			if (own != null && own.equals("!" + flag.getName()) && cycles[compare] < cycles[dispatch] &&
				unchanged(path, cycles, compare, dispatch, flag)) return true;
			// The path came in through a jump taken on the flag being zero.
			if (enteredBy > compare && enteredBy < dispatch && ("!" + flag.getName()).equals(predicate(path.get(enteredBy))) &&
				cycles[compare] < cycles[enteredBy] && unchanged(path, cycles, compare, enteredBy, flag)) return true;
			for (int j = compare + 1; j < dispatch; j++) {
				Instruction t = path.get(j);
				if (!transfer(t) || !flag.getName().equals(predicate(t))) continue;
				if (cycles[compare] < cycles[j] && cycles[j] + 1 + DELAY_CYCLES <= cycles[dispatch] &&
					unchanged(path, cycles, compare, j, flag)) return true;
			}
			return false;
		}

		/** No write to {@code register} lands from the write at {@code from} up to the read at {@code to}. */
		boolean unchanged(List<Instruction> path, int from, int to, Register register) {
			return unchanged(path, issueCycles(path), from, to, register);
		}

		private boolean unchanged(List<Instruction> path, int[] cycles, int from, int to, Register register) {
			for (int k = 0; k < path.size(); k++) {
				if (k == from) continue;
				Instruction insn = path.get(k);
				Register load = loadDestination(insn);
				boolean writes = load != null ? overlaps(load, register) : issueWrites(insn).stream().anyMatch(r -> overlaps(r, register));
				long lands = cycles[k] + resultDelay(insn);
				if (writes && lands >= cycles[from] && lands < cycles[to]) return false;
			}
			return true;
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
			String why = compare(first, outer, null);
			if (why == null && first != outer) {
				for (Reference ref : program.getReferenceManager().getReferencesTo(outer.getMinAddress())) {
					if (ref.getReferenceType().isFlow() && !ref.getReferenceType().isFallthrough()) return compare(outer, outer, null);
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

		/**
		 * A lifting the window layer may apply instead of the listing's: {@code jump} continued to its
		 * fall-through, and {@code transfer}'s window cut after {@code cut} (issue #50).
		 */
		private record Proposal(Instruction jump, Instruction transfer, Address cut) {}

		/**
		 * Compare from {@code first}, where nothing is in flight, through {@code outer}'s windows, with
		 * the listing's lifting or, given a proposal, that one.
		 */
		private String compare(Instruction first, Instruction outer, Proposal proposal) {
			return compare(first, outer, proposal, null);
		}

		/**
		 * One latched branch: where it lands, as what (1 jump, 2 call, 3 return), its target unless that is
		 * in a register, and whether its latch is set on every path that reaches the landing.
		 */
		record Latch(Instruction branch, int slot, Instruction land, int kind, Address target, boolean sure) {}

		/** A lifting of a stretch by latched branches, planned or read back from the listing. */
		record Lifting(Instruction first, Address last, List<Latch> latches) {}

		private static final String[] UNLIFTABLE = { "CALLP", "BDEC", "BPOS" };

		/**
		 * Latch every transfer from where nothing is in flight before {@code outer} to the end of the
		 * windows issued there: each lands behind the last instruction that issues, in address order,
		 * before its sixth cycle. That is the hardware's order whenever at most one of them is taken;
		 * {@link #liftMismatch} says whether it is on every path. Null when a transfer has no latched
		 * form or the stretch needs more latches or landings than there are.
		 */
		/** Why the last liftPlan gave no plan. */
		String liftRefusal;

		private Lifting refuse(String why) {
			liftRefusal = why;
			return null;
		}

		Lifting liftPlan(Instruction outer) {
			liftRefusal = null;
			Instruction first = settled(outer);
			List<Instruction> stretch = new ArrayList<>();
			long end = Math.max(windowEnd(first), windowEnd(outer));
			if (windowEnd(first) < 0 || windowEnd(outer) < 0) return refuse("a delay window there does not decode");
			Instruction current = first;
			while (current != null && current.getMinAddress().getOffset() < end) {
				if (stretch.size() > 4 * MAX_WINDOW) return refuse("the nested windows are too long");
				stretch.add(current);
				if (transfer(current)) {
					long e = windowEnd(current);
					if (e < 0) return refuse("a delay window there does not decode");
					end = Math.max(end, e);
				}
				current = next(current);
			}
			if (current == null || stretch.isEmpty()) return refuse("the code after the windows does not decode");
			List<Instruction> timed = new ArrayList<>(stretch);
			timed.add(current);
			int[] issue = issueCycles(timed);
			// Where an earlier branch is taken too, a later one lands in the code that one went to: the
			// hardware's own run of every outcome says behind which instruction.
			Map<Address, Map<Address, Instruction>> sites;
			String why;
			Map<Address, Set<Boolean>> calls;
			landedBehind = new HashMap<>();
			landedAsCall = new HashMap<>();
			try {
				why = compare(first, outer, null, null);
			}
			finally {
				sites = landedBehind;
				calls = landedAsCall;
				landedBehind = null;
				landedAsCall = null;
			}
			if (why != null) return refuse(why);
			List<Latch> latches = new ArrayList<>();
			Map<Address, Integer> landings = new HashMap<>();
			int[] busy = new int[8];
			java.util.Arrays.fill(busy, -1);
			for (int i = 0; i < stretch.size(); i++) {
				Instruction branch = stretch.get(i);
				if (!transfer(branch)) continue;
				String op = baseName(branch);
				for (String form : UNLIFTABLE) if (op.startsWith(form)) return refuse(branch + " at " + branch.getMinAddress() + " has no latched form");
				if (untimed(program, branch)) return refuse("its timing is outside the cycle model");
				int land = -1;
				for (int j = i; j < stretch.size() && issue[j] < issue[i] + 1 + DELAY_CYCLES; j++) land = j;
				if (land < 0 || issue[land + 1] < issue[i] + 1 + DELAY_CYCLES) return refuse("a branch lands past the end of the stretch");
				Instruction behind = stretch.get(land);
				if (landings.merge(behind.getMinAddress(), 1, Integer::sum) > 2) return refuse("more than two branches land behind one instruction");
				var flow = C6000PacketStagingAnalyzer.flow(branch);
				boolean register = branch.getRegister(0) != null;
				Address target = register || C6000PacketStagingAnalyzer.hardware(branch).getDefaultFlows().length != 1 ? null : C6000PacketStagingAnalyzer.hardware(branch).getDefaultFlows()[0];
				if (!register && target == null) return refuse("a branch has no single target");
				Set<Boolean> called = calls.getOrDefault(branch.getMinAddress(), Set.of());
				if (called.size() > 1) return refuse(branch + " at " + branch.getMinAddress() + " lands as a call on some paths only");
				// A B through B3 returns wherever it issues, as C6000ReturnAnalyzer classifies one outside a window (SPRUFE8B 3.5, 4.2.6).
				boolean ret = register && (flow.isTerminal() || "B3".equals(branch.getDefaultOperandRepresentation(0)) &&
					(branch.getFlowOverride() == FlowOverride.NONE || branch.getFlowOverride() == FlowOverride.RETURN));
				int kind = flow.isCall() || called.contains(true) ? 2 : ret ? 3 : 1;
				// A latch is free again once the branch that used it has landed behind an earlier instruction.
				int slot = -1;
				for (int k = 0; k < busy.length && slot < 0; k++) if (busy[k] < i) slot = k;
				if (slot < 0) return refuse("more than eight branches are in flight at once");
				busy[slot] = land;
				latches.add(new Latch(branch, slot, behind, kind, target, false));
			}
			if (latches.isEmpty()) return refuse("no branch to latch");
			Address last = stretch.get(stretch.size() - 1).getMaxAddress();
			for (Latch latch : List.copyOf(latches)) {
				for (Instruction site : sites.getOrDefault(latch.branch().getMinAddress(), Map.of()).values()) {
					Address at = site.getMinAddress();
					if (at.equals(latch.land().getMinAddress())) continue;
					if (landings.merge(at, 1, Integer::sum) > 2) return refuse("more than two branches land behind one instruction");
					if (at.compareTo(first.getMinAddress()) < 0 || at.compareTo(last) > 0) {
						// ponytail: one stretch's landings per instruction outside it; merge them when two stretches' targets meet
						Instruction listed = listing.getInstructionAt(at);
						// A native delay slot holds no flow of its own.
						if (listed == null || listed.isInDelaySlot() || !landingsAt(at).isEmpty()) return refuse("a branch lands behind " + at + ", which cannot carry it");
						for (Instruction prior : before(listed))
							if (C6000PacketStagingAnalyzer.inert(prior)) return refuse("a branch lands behind " + at + ", inside another latched stretch");
					}
					latches.add(new Latch(latch.branch(), latch.slot(), site, latch.kind(), latch.target(), false));
				}
			}
			// A landing whose latch is set whenever its instruction is reached needs no test, and then
			// has no fall-through: the plan's own run of every outcome says which, unless something
			// outside it also reaches the code it runs.
			Lifting plan = new Lifting(first, last, latches);
			Map<String, boolean[]> uses;
			Set<Address> walked;
			landingUse = new HashMap<>();
			landingWalk = new HashSet<>();
			try {
				why = compare(first, outer, null, plan);
			}
			finally {
				uses = landingUse;
				walked = landingWalk;
				landingUse = null;
				landingWalk = null;
			}
			if (why != null || entered(walked, first, latches)) return plan;
			List<Latch> sure = new ArrayList<>();
			for (Latch latch : latches) {
				boolean[] use = uses.get(latch.land().getMinAddress() + "/" + latch.slot());
				// Outside the stretch a run ends once nothing is in flight, so a landing there is not seen passed.
				Address at = latch.land().getMinAddress();
				boolean inside = at.compareTo(first.getMinAddress()) >= 0 && at.compareTo(last) <= 0;
				sure.add(new Latch(latch.branch(), latch.slot(), latch.land(), latch.kind(), latch.target(), inside && use != null && use[0] && !use[1]));
			}
			return new Lifting(first, last, sure);
		}

		/** Set while planning: per landing, whether it ever fired and whether it was ever passed with its latch clear; and every instruction run. */
		private Map<String, boolean[]> landingUse;
		private Set<Address> landingWalk;

		/** True when code a plan runs, past its first instruction, is also reached from outside the plan. */
		private boolean entered(Set<Address> walked, Instruction first, List<Latch> latches) {
			Set<Address> own = new HashSet<>();
			for (Latch latch : latches) {
				own.add(latch.branch().getMinAddress());
				own.add(latch.land().getMinAddress());
			}
			for (Address at : walked) {
				if (at.equals(first.getMinAddress())) continue;
				Instruction insn = listing.getInstructionAt(at);
				if (insn == null || externalEntry(insn)) return true;
				for (Reference ref : program.getReferenceManager().getReferencesTo(at))
					if (ref.getReferenceType().isFlow() && !ref.getReferenceType().isFallthrough() && !own.contains(ref.getFromAddress())) return true;
				// Falling in from an instruction the plan does not run.
				Instruction prior = listing.getInstructionBefore(at);
				if (prior == null || walked.contains(prior.getMinAddress()) || !adjacent(prior, insn) && !headerBetween(prior, insn)) continue;
				Instruction owner = C6000DelaySlots.unitOwner(program, prior);
				if (walked.contains(owner.getMinAddress())) continue;
				if (!transfer(owner) || C6000PacketStagingAnalyzer.flow(owner).hasFallthrough()) return true;
			}
			return false;
		}

		/** Set while planning: each transfer the hardware lands, and the instructions it lands behind. */
		private Map<Address, Map<Address, Instruction>> landedBehind;
		/** Set while planning: whether each transfer the hardware lands is a call there. */
		private Map<Address, Set<Boolean>> landedAsCall;

		/** Null when {@code plan} runs what the hardware runs on every consistent outcome; else the first difference. */
		String liftMismatch(Lifting plan, Instruction outer) {
			return compare(plan.first(), outer, null, plan);
		}

		/** The lifting the listing's own context fields give. */
		private static final Lifting LISTED = new Lifting(null, null, List.of());

		/** True when the listing has a latched branch from {@code first} to before {@code stop}. */
		private boolean listed(Instruction first, Address stop) {
			for (Instruction insn = listing.getInstructionAt(first.getMinAddress());
					insn != null && insn.getMinAddress().compareTo(stop) < 0; insn = listing.getInstructionAfter(insn.getMaxAddress()))
				if (C6000PacketStagingAnalyzer.inert(insn)) return true;
			return false;
		}

		/** One landing an instruction carries: the latch it reads, as what it lands, and where unless at the latched register target. */
		record Landing(int slot, int kind, Address target, boolean sure) {}

		/** The landings the listing's instruction at {@code at} carries. */
		List<Landing> landingsAt(Address at) {
			Instruction insn = listing.getInstructionAt(at);
			List<Landing> lands = new ArrayList<>();
			if (insn == null) return lands;
			for (String land : new String[] { "c_land1", "c_land2" }) {
				int kind = field(insn, land);
				if (kind == 0) continue;
				Address target = field(insn, land + "_ind") != 0 ? null :
					at.getNewAddress((at.getOffset() & ~31L) + 2L * signed(insn, land + "_disp"));
				lands.add(new Landing(field(insn, land + "_t"), kind, target, field(insn, land + "_sure") != 0));
			}
			return lands;
		}

		/**
		 * The latched branch that lands behind {@code land} through latch {@code slot} in address order;
		 * null when none does. A landing in the code another branch went to has its branch elsewhere.
		 * ponytail: such a landing's branch stays unknown; follow the taken branch back when one needs it.
		 */
		private Instruction latchedBranch(Instruction land, int slot) {
			Instruction branch = null, at = land;
			List<Instruction> path = new ArrayList<>();
			// The branch issued at most five cycles before; one with no delay cycles left lands behind itself.
			for (int n = 0; n <= MAX_WINDOW && at != null && branch == null; n++) {
				path.add(0, at);
				if (C6000PacketStagingAnalyzer.inert(at) && field(at, "c_latch_t") == slot) branch = at;
				at = listing.getInstructionBefore(at.getMinAddress());
			}
			if (branch == null) return null;
			Instruction after = next(land);
			if (after != null) path.add(after);
			int[] issue = issueCycles(path);
			int landed = issue[0] + 1 + DELAY_CYCLES, here = after != null ? path.size() - 2 : path.size() - 1;
			return issue[here] >= landed || (after != null && issue[here + 1] < landed) ? null : branch;
		}

		/** The transfer behind a flow reference from {@code from} to {@code label}: {@code from}, or the latched branch it lands. */
		private Instruction entering(Instruction from, Address label) {
			if (from == null || transfer(from)) return from;
			for (Landing land : landingsAt(from.getMinAddress()))
				if (label.equals(land.target())) return latchedBranch(from, land.slot());
			return from;
		}

		/**
		 * The register targets the latched branches landing behind {@code land} read as they issued,
		 * where the look-back proves them; null when one of them is not proven.
		 */
		List<Long> landingTargets(Instruction land) {
			List<Long> targets = new ArrayList<>();
			for (String name : new String[] { "c_land1", "c_land2" }) {
				if (field(land, name) == 0 || field(land, name + "_ind") == 0) continue;
				Instruction branch = latchedBranch(land, field(land, name + "_t"));
				Long target = branch == null ? null : issueTarget(branch);
				if (target == null) return null;
				targets.add(target);
			}
			return targets;
		}

		int field(Instruction insn, String name) {
			Register register = program.getRegister(name);
			var value = register == null ? null : insn.getValue(register, false);
			return value == null ? 0 : value.intValue();
		}

		private int signed(Instruction insn, String name) {
			Register register = program.getRegister(name);
			var value = register == null ? null : insn.getValue(register, true);
			return value == null ? 0 : value.intValue();
		}

		/**
		 * The lifting by latched branches, planned or the listing's: instructions in address order; a
		 * latched branch only writes whether it is taken into its latch, and an instruction carrying a
		 * landing for a set latch clears it and calls the target and goes on, or leaves for it. Like the
		 * hardware's, the run goes on outside the stretch while a latch is set.
		 */
		private Run latched(Instruction first, Stretch region, Map<Address, Boolean> taken, List<PredicateFact> facts, Lifting lifting) {
			Map<Address, Integer> slotAt = new HashMap<>();
			Map<Address, List<Landing>> landAt = new HashMap<>();
			for (Latch latch : lifting.latches()) {
				slotAt.put(latch.branch().getMinAddress(), latch.slot());
				landAt.computeIfAbsent(latch.land().getMinAddress(), k -> new ArrayList<>()).add(new Landing(latch.slot(), latch.kind(), latch.target(), latch.sure()));
			}
			List<String> trace = new ArrayList<>();
			Set<Address> seen = new HashSet<>();
			Instruction[] set = new Instruction[8];
			Instruction insn = first;
			while (true) {
				if (insn == null) return Run.unproven("the latched lifting runs into code that does not decode");
				Address at = insn.getMinAddress();
				boolean flying = java.util.Arrays.stream(set).anyMatch(java.util.Objects::nonNull);
				if (!flying && !inside(at, region)) return new Run(trace, "continues at " + at, null);
				if (!seen.add(at)) {
					if (flying) return Run.unproven("the latched lifting loops back to " + at + " with a branch still to land");
					return new Run(trace, "issues " + at + " again", null);
				}
				if (seen.size() > MAX_ISSUED) return Run.unproven("the latched lifting runs too far to compare");
				if (landingWalk != null) landingWalk.add(at);
				Instruction next = next(insn);
				if (transfer(insn)) {
					Instruction listed = lifting == LISTED ? listing.getInstructionAt(at) : null;
					Integer slot = lifting != LISTED ? slotAt.get(at) :
						listed != null && C6000PacketStagingAnalyzer.inert(listed) ? Integer.valueOf(field(listed, "c_latch_t")) : null;
					if (slot == null) return Run.unproven(insn + " at " + at + " is not latched with the others");
					Boolean go = predicate(insn) == null ? Boolean.TRUE : taken.get(at);
					if (go == null) return Run.unproven(insn + " at " + at + " is latched on a predicate this check cannot follow");
					set[slot] = go ? insn : null;
				}
				else if (!idle(insn) && runs(insn, region, facts)) trace.add(at.toString());
				for (Landing land : lifting == LISTED ? landingsAt(at) : landAt.getOrDefault(at, List.of())) {
					Instruction branch = set[land.slot()];
					if (landingUse != null) landingUse.computeIfAbsent(at + "/" + land.slot(), k -> new boolean[2])[branch != null ? 0 : 1] = true;
					if (branch == null && land.sure()) return Run.unproven("the landing at " + at + " takes its latch as set, and it is not on this path");
					if (branch == null) continue;
					set[land.slot()] = null;
					boolean others = java.util.Arrays.stream(set).anyMatch(java.util.Objects::nonNull);
					if (land.target() == null && branch.getRegister(0) == null)
						return Run.unproven("a landing at " + at + " reads a register target " + branch + " never latched");
					String where = destination(branch, land.target());
					if (others && (land.kind() == 2 || land.target() == null))
						return Run.unproven("the latched lifting leaves for " + where + " with a branch still to land");
					if (land.kind() == 2) { trace.add("calls " + where); continue; }
					if (land.target() == null || (!others && !inside(land.target(), region))) return new Run(trace, "continues at " + where, null);
					next = decode(land.target());
					break;
				}
				insn = next;
			}
		}

		private String compare(Instruction first, Instruction outer, Proposal proposal, Lifting lifting) {
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
				if (listed == null || !C6000PacketStagingAnalyzer.flow(listed).isCall()) continue;
				// A latched call returns behind the instruction it lands behind.
				Instruction site = C6000PacketStagingAnalyzer.inert(listed) ? C6000PacketStagingAnalyzer.landingSite(listed) : null;
				Address back = site != null ? site.getMaxAddress().next() : listed.getFallThrough();
				if (back != null) returns.add(back);
			}
			if (predicated.size() > MAX_PATH_TRANSFERS) return "it has too many predicated transfers to compare";
			Stretch region = new Stretch(first.getMinAddress(), current.getMinAddress(), path, index, predicated, returns);
			// The listing may already lift this stretch by latched branches.
			if (proposal == null && lifting == null && listed(first, current.getMinAddress())) lifting = LISTED;

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
				if (landedBehind != null) continue; // planning: only where the hardware lands each branch
				Run lifted = proposal != null ? proposed(first, region, taken, facts, proposal) :
					lifting != null ? latched(first, region, taken, facts, lifting) : lifted(first, region, taken, facts);
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
			// B3 as the instructions run here leave it: a constant written since the last call is a return link.
			Register b3 = program.getRegister("B3");
			Map<Register, long[]> link = new HashMap<>();
			try {
				while (true) {
					// One execute packet, issued in this cycle.
					int span = 1;
					Instruction insn = at;
					while (true) {
						if (!issued.add(insn.getMinAddress())) {
							// A loop: the same code again is only the same run with nothing in flight.
							if (!flights.isEmpty()) return Run.unproven("it loops back to " + insn.getMinAddress() + " with transfers still in flight");
							return new Run(trace, "issues " + insn.getMinAddress() + " again", null);
						}
						if (issued.size() > MAX_ISSUED) return Run.unproven("its windows issue too many instructions to compare");
						if (untimed(program, insn)) return Run.unproven(insn + " at " + insn.getMinAddress() + " has timing outside the cycle model");
						span = Math.max(span, 1 + extraCycles(program, insn));
						if (transfer(insn)) {
							Boolean go = predicate(insn) == null ? Boolean.TRUE : taken.get(insn.getMinAddress());
							if (go == null) return Run.unproven(insn + " at " + insn.getMinAddress() + " issues with transfers in flight, on a predicate this check cannot follow");
							if (go) flights.add(new Flight(cycle + 1 + DELAY_CYCLES, insn));
						}
						else if (!idle(insn) && runs(insn, region, facts)) {
							trace.add(insn.getMinAddress().toString());
							Register load = loadDestination(insn);
							if (load != null ? overlaps(load, b3) : issueWrites(insn).stream().anyMatch(r -> overlaps(r, b3))) {
								// Only a write that surely runs, with a value its p-code gives, is known.
								Integer i = region.index().get(insn.getMinAddress());
								boolean sure = predicate(insn) == null || (i != null && holds(region, i, facts) == Boolean.TRUE);
								Long value = load != null || !sure ? null : constantWrite(insn, b3, link);
								if (value == null) link.remove(b3);
								else link.put(b3, new long[] { value, FULL });
							}
						}
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
						if (landedBehind != null)
							landedBehind.computeIfAbsent(transfer.getMinAddress(), k -> new LinkedHashMap<>()).put(insn.getMinAddress(), insn);
						Address target = transfer.getRegister(0) != null || C6000PacketStagingAnalyzer.hardware(transfer).getDefaultFlows().length != 1 ? null :
							C6000PacketStagingAnalyzer.hardware(transfer).getDefaultFlows()[0];
						Instruction listed = listing.getInstructionAt(transfer.getMinAddress());
						boolean call = listed != null && C6000PacketStagingAnalyzer.flow(listed).isCall();
						// A transfer that lands with a fresh link in B3 is a call that returns there, whatever
						// the listing makes of it; one through B3 itself goes where B3 pointed before.
						Address linked = null;
						long[] held = link.get(b3);
						boolean latched = listed != null && C6000PacketStagingAnalyzer.inert(listed);
						if ((!call || latched) && held != null && !b3.equals(transfer.getRegister(0))) {
							Address to = transfer.getMinAddress().getNewAddress(held[0] & 0xffffffffL);
							if (!to.equals(target) && listing.getInstructionAt(to) != null) linked = to;
						}
						// Of two arms on opposite predicates that share one link, an arm into its own
						// function's code is the else-branch and the link is the other arm's. An arm
						// through B3 is the return and leaves the link to this one. Where the listing
						// already says call, that was decided with both arms in view.
						if (linked != null && !call && Boolean.TRUE.equals(localTarget(transfer))) for (int i : region.predicated()) {
							Instruction arm = region.path().get(i);
							if (!arm.getMinAddress().equals(transfer.getMinAddress()) && complementary(transfer, arm) &&
								!b3.equals(arm.getRegister(0))) linked = null;
						}
						if (landedAsCall != null) landedAsCall.computeIfAbsent(transfer.getMinAddress(), k -> new HashSet<>()).add(call || linked != null);
						if (call || linked != null) {
							// The callee runs to its return, which needs nothing else in flight.
							if (!flights.isEmpty()) return new Run(trace, "calls " + destination(transfer, target) + " with transfers in flight", null);
							trace.add("calls " + destination(transfer, target));
							link.clear();
							// It returns where B3 points; a latched call's listed fall-through is only its next instruction.
							Address back = linked != null ? linked : C6000PacketStagingAnalyzer.inert(listed) ? returnPoint(listed) : listed.getFallThrough();
							if (back == null) return new Run(trace, "does not return", null);
							at = decode(back);
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
						if (C6000PacketStagingAnalyzer.flow(insn).isCall()) {
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

		/** The proposal's lifting: the jump runs straight on, the transfer's window ends at the cut, every other transfer keeps its whole window. */
		private Run proposed(Instruction first, Stretch region, Map<Address, Boolean> taken, List<PredicateFact> facts, Proposal proposal) {
			List<String> trace = new ArrayList<>();
			Set<Address> seen = new HashSet<>();
			Instruction insn = first;
			while (true) {
				if (insn == null) return Run.unproven("the proposed lifting runs into code that does not decode");
				Address at = insn.getMinAddress();
				if (!inside(at, region)) return new Run(trace, "continues at " + at, null);
				if (!seen.add(at)) return new Run(trace, "issues " + at + " again", null);
				Instruction next = next(insn);
				if (transfer(insn) && !at.equals(proposal.jump().getMinAddress())) {
					List<Instruction> slots;
					if (at.equals(proposal.transfer().getMinAddress())) {
						slots = new ArrayList<>();
						for (Instruction slot = next; slot != null && slot.getMaxAddress().compareTo(proposal.cut()) <= 0; slot = next(slot)) slots.add(slot);
					}
					else slots = window(insn);
					if (slots == null) return Run.unproven("the window of " + insn + " at " + at + " is incomplete");
					for (Instruction slot : slots) if (!idle(slot) && runs(slot, region, facts)) trace.add(slot.getMinAddress().toString());
					if (!slots.isEmpty()) next = next(slots.get(slots.size() - 1));
					Boolean go = predicate(insn) == null ? Boolean.TRUE : taken.get(at);
					if (go == null) return Run.unproven(insn + " at " + at + " is lifted on a predicate this check cannot follow");
					if (go) {
						Address target = insn.getRegister(0) != null || C6000PacketStagingAnalyzer.hardware(insn).getDefaultFlows().length != 1 ? null : C6000PacketStagingAnalyzer.hardware(insn).getDefaultFlows()[0];
						if (target == null && insn.getRegister(0) == null) return Run.unproven(insn + " at " + at + " has no single target");
						if (target == null || !inside(target, region)) return new Run(trace, "continues at " + destination(insn, target), null);
						next = decode(target);
					}
				}
				else if (!transfer(insn) && !idle(insn) && runs(insn, region, facts)) trace.add(at.toString());
				insn = next;
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
			if (count == 0) return C6000PacketStagingAnalyzer.hardware(insn).getDefaultFlows().length == 1 ? C6000PacketStagingAnalyzer.hardware(insn).getDefaultFlows()[0] : null;
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

		/** A branch taken: what has issued when it lands, the target it read, and what led there. */
		private record Arrival(Landed landed, Long target, List<PredicateFact> facts, int branchIndex, Constants trace) {}

		/** How many jumps back an entry's own look-back is followed, and how many entering jumps are compared. */
		private static final int ENTRY_DEPTH = 2, ENTRY_PATHS = 4;
		private int entryDepth = ENTRY_DEPTH;

		/**
		 * Code a jump from elsewhere enters is also reached without what the look-back saw before it.
		 * Keep a register constant across {@code label} only when every entering jump arrives with the
		 * same value, or has not written the register since it last passed the label (a loop's back
		 * edge). A call, or a path this cannot follow, leaves nothing known. With {@code only}, nothing
		 * falls into the label: what the entering jumps agree on replaces what the look-back held.
		 */
		private boolean meetEntries(Instruction label, Map<Register, long[]> regs, Constants trace, boolean only) {
			boolean clean = true;
			List<Instruction> jumps = new ArrayList<>();
			Boolean external = null;
			for (Reference ref : program.getReferenceManager().getReferencesTo(label.getMinAddress())) {
				if (!ref.getReferenceType().isFlow() || ref.getReferenceType().isFallthrough()) continue;
				// A latched branch enters where it lands: the look-back follows the branch itself.
				Instruction jump = entering(listing.getInstructionAt(ref.getFromAddress()), label.getMinAddress());
				if (jump == null || ref.getReferenceType().isCall() || entryDepth == 0 || jumps.size() == ENTRY_PATHS ||
					(external == null ? (external = externalEntry(label)) : external)) {
					trace.forget();
					return true;
				}
				jumps.add(jump);
			}
			if (jumps.isEmpty()) {
				// A function or program entry, or an address held as data: how it is reached is not known.
				trace.forget();
				return true;
			}
			Instruction savedVia = viaInsn;
			Address savedReturn = backwardReturn;
			// Only a nested arrival's trace is read back (writtenSince), and only by the level above.
			boolean topLevel = entryDepth == ENTRY_DEPTH;
			entryDepth--;
			try {
				for (Instruction jump : jumps) {
					// Nothing known to merge: another entering jump could only forget nothing.
					if (!only && topLevel && trace.holdsNothing()) break;
					// Only the registers at the landing matter here, whatever else is in flight with the jump.
					boolean saved = targetOnly;
					targetOnly = false;
					Arrival other = arrive(jump, true);
					targetOnly = saved;
					if (other == null) {
						trace.forget();
						return true;
					}
					// The jump arrives with another transfer of its window still in flight.
					if (only && other.landed().nested()) clean = false;
					List<Instruction> issued = other.landed().issued();
					int since = -1;
					for (int i = 0; i < issued.size(); i++) if (issued.get(i).getMinAddress().equals(label.getMinAddress())) since = i;
					if (only) {
						trace.forget();
						for (var entry : other.landed().values().entrySet()) if (entry.getValue()[1] == FULL) regs.put(entry.getKey(), entry.getValue().clone());
						only = false;
						continue;
					}
					// A back edge whose look-back does not reach the label: every instruction from the label
					// to the end of what the jump issues is a superset of the loop body's writes.
					List<Register> body = since < 0 ? writesBetween(label, issued.get(issued.size() - 1)) : null;
					Map<Register, long[]> theirs = other.landed().values();
					for (Register r : new ArrayList<>(regs.keySet())) {
						long[] mine = regs.get(r), value = theirs.get(r);
						if (value != null && value[0] == mine[0] && value[1] == mine[1]) continue;
						boolean written = since >= 0 ? other.trace().writtenSince(r, since) :
							body == null || body.stream().anyMatch(w -> overlaps(w, r));
						if (written) regs.remove(r);
					}
				}
			}
			finally {
				entryDepth++;
				viaInsn = savedVia;
				backwardReturn = savedReturn;
			}
			return clean;
		}

		Call recognize(Instruction branch) {
			Arrival arrival = arrive(branch);
			if (arrival == null) return null;
			Landed landed = arrival.landed();
			Long target = arrival.target();
			List<PredicateFact> facts = arrival.facts();
			int branchIndex = arrival.branchIndex();
			Register b3 = program.getRegister("B3");
			Instruction partner = landed.partner();
			if (partner != null && jumpArm(branch, partner)) return null;
			long[] ret = landed.values().get(b3);
			// B3 may also be set on the look-back path.
			if (ret == null || ret[1] != FULL) return null;
			long branchAt = branch.getMinAddress().getOffset();
			long windowEnd = landed.end();
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
				timedPath = landed.issued();
				timedCycles = landed.cycles();
				try {
					Address loop = partner == null && predicate(branch) == null && branch.getRegister(0) == null &&
						freshLink(landed.issued(), branchIndex, b3, facts) ? loopReturn(branch, ret[0]) : null;
					return loop == null ? null : new Call(null, loop, loop);
				}
				finally {
					timedPath = null;
				}
			}
			// B3 already held the return address when the B read it: a computed jump
			// to the fall-through, not a call (issue #39).
			if (target != null && (target & 0xffffffffL) == (ret[0] & 0xffffffffL)) return null;
			// A call returns to where its caller goes on: right after what this arm issued before it
			// landed, or after what the other arm of its if/else pair issued, where the two join. Only
			// a fetch-packet header, which never issues, may lie before that point.
			if (!joins(branch, windowEnd, ret[0])) {
				Instruction saved = viaInsn;
				Arrival other = partner == null ? null : arrive(partner);
				viaInsn = saved;
				if (other == null || !joins(branch, other.landed().end(), ret[0])) return null;
			}
			return new Call(callee, null, branch.getMinAddress().getNewAddress(ret[0] & 0xffffffffL));
		}

		/** Where the callee of a recognised call returns to: the address B3 holds when the call lands; else null. */
		Address returnPoint(Instruction branch) {
			Call call = recognize(branch);
			return call == null ? null : call.link();
		}

		/** {@code ret} is {@code end}, or the first instruction past a fetch-packet header at {@code end}. */
		private boolean joins(Instruction near, long end, long ret) {
			return ret == end || ((end & 31) == 28 && headerAt(near, end) && ret == end + 4);
		}

		private Arrival arrive(Instruction branch) {
			return arrive(branch, false);
		}

		/**
		 * The address a register branch reads from its register at E1, before any write in its own
		 * execute packet commits (SPRUFE8B 3.5, Table 4-11), when the look-back proves it; else null.
		 */
		Long issueTarget(Instruction branch) {
			if (branch.getRegister(0) == null || !transfer(branch)) return null;
			Instruction savedVia = viaInsn;
			targetOnly = true;
			try {
				Arrival arrival = arrive(branch, false);
				return arrival == null || arrival.target() == null ? null : arrival.target() & 0xffffffffL;
			}
			finally {
				targetOnly = false;
				viaInsn = savedVia;
			}
		}

		private boolean targetOnly;

		/** {@code valuesOnly}: other transfers may issue in the window; only the registers at the landing are wanted. */
		private Arrival arrive(Instruction branch, boolean valuesOnly) {
			Map<Register, long[]> regs = new HashMap<>();
			Instruction partner = null;
			List<Instruction> path = lookBack(branch);
			List<Instruction> via = viaJump(branch, path);
			if (via != null) path = via;
			List<Instruction> execution = new ArrayList<>(path);
			int branchIndex = execution.size();
			execution.add(branch);
			int[] issue = issueCycles(execution);
			Constants trace = new Constants(regs);
			// The branch is taken with nothing else in flight. An earlier transfer still in flight is
			// lifted as an immediate jump, so the lifted code reaches the branch only when that one is not
			// taken; the path where both are is the nested-window check's to compare.
			List<PredicateFact> facts = new ArrayList<>();

			// Code a jump from elsewhere enters is also reached without what the look-back saw before it:
			// neither a fall-through fact nor a register constant from before the entry holds there.
			boolean[] entered = new boolean[execution.size()];
			for (int i = 0; i < execution.size(); i++)
				entered[i] = !(via != null && i == branchIndex) && enteredFromElsewhere(execution.get(i));
			for (int i = 0; i < path.size(); i++) {
				Instruction insn = path.get(i);
				if ((isFlow(insn) && predicate(insn) == null) || entered[i]) facts.clear();
				if (via == null && predicate(insn) != null && C6000PacketStagingAnalyzer.flow(insn).isJump() &&
					!C6000PacketStagingAnalyzer.flow(insn).isCall() && !C6000PacketStagingAnalyzer.flow(insn).isTerminal() &&
					!inWindow(insn, branch)) {
					// The straight-line path reaches branch only on this fall-through.
					addFact(facts, i, insn, false);
				}
			}
			// Taken-edge constraints take precedence over speculative physical look-back.
			if (entered[branchIndex]) facts.clear();
			if (via != null) addFact(facts, slotIndex(path, viaInsn), viaInsn, true);
			addFact(facts, branchIndex, branch, true);
			java.util.Collections.reverse(facts);
			List<Integer> returns = new ArrayList<>();
			int dead = Integer.MAX_VALUE;
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
				// A callee may change every register the ABI does not make it preserve. That is done
				// when it returns, before the return point's own writes.
				for (var back = returns.iterator(); back.hasNext();) {
					if (back.next() <= issue[i]) { back.remove(); trace.forget(callClobbered()); }
				}
				if (entered[i]) {
					// Reached only with another transfer in flight: nothing from there is known.
					if (!meetEntries(insn, regs, trace, dead <= issue[i])) trace.forget();
					dead = Integer.MAX_VALUE;
				}
				if (insn != viaInsn && isFlow(insn)) {
					trace.write(issue[i], program.getRegister("B3"), null, i);
					if (C6000PacketStagingAnalyzer.flow(insn).isCall()) returns.add(issue[i] + 1 + DELAY_CYCLES);
					// Past the window of a jump or return that always goes, nothing falls through.
					if (!C6000PacketStagingAnalyzer.flow(insn).isCall() && predicate(insn) == null) dead = issue[i] + 1 + DELAY_CYCLES;
				}
				trace.instruction(insn, runs, issue[i], i);
			}

			// SPRUFE8B 3.5 / Tables 4-6 and 4-11: all members of a
			// packet read the same E1 snapshot, before any E1 writer commits.
			trace.before(issue[branchIndex]);
			for (int back : returns) if (back <= issue[branchIndex]) trace.forget(callClobbered());
			// A branch reached only by a jump with another transfer in flight does not arrive alone.
			if (entered[branchIndex] && !meetEntries(branch, regs, trace, dead <= issue[branchIndex]) && !targetOnly && !valuesOnly)
				return null;
			Register source = branch.getRegister(0);
			Long target = null;
			if (source != null) {
				long[] value = regs.get(source);
				if (value != null && value[1] == FULL) target = value[0];
			}

			if (targetOnly) return new Arrival(null, target, facts, branchIndex, trace);
			// What the hardware has issued when the branch lands: B3 then is where the callee returns to.
			Landed landed = land(branch, execution, issue, branchIndex, regs, trace, facts, partner, valuesOnly);
			if (landed == null) return null;
			return new Arrival(landed, target, facts, branchIndex, trace);
		}

		/** Every register an instruction from {@code from} to {@code to}, in address order, can write; null when unknown. */
		private List<Register> writesBetween(Instruction from, Instruction to) {
			if (to.getMinAddress().compareTo(from.getMinAddress()) < 0) return null;
			List<Register> writes = new ArrayList<>();
			Instruction insn = from;
			for (int guard = 0; guard < 1024; guard++) {
				if (insn == null) return null;
				writes.addAll(issueWrites(insn));
				Register load = loadDestination(insn);
				if (load != null) writes.add(load);
				if (insn.getMinAddress().compareTo(to.getMinAddress()) >= 0) return writes;
				insn = next(insn);
			}
			return null;
		}

		private List<Register> clobbered;

		/** The registers a callee need not preserve: all but A10-A15 and B10-B15 (C6000 EABI, SPRAB89 3.2). */
		private List<Register> callClobbered() {
			if (clobbered == null) {
				clobbered = new ArrayList<>();
				for (char side : new char[] { 'A', 'B' }) {
					for (int n = 0; n < 32; n++) {
						Register r = n >= 10 && n <= 15 ? null : program.getRegister(side + Integer.toString(n));
						if (r != null) clobbered.add(r);
					}
				}
			}
			return clobbered;
		}

		/**
		 * Reached in ways this cannot see: a function or program entry, or an address something holds as
		 * data, at any byte of {@code insn}.
		 */
		private boolean externalEntry(Instruction insn) {
			for (Address at = insn.getMinAddress(); at.compareTo(insn.getMaxAddress()) <= 0; at = at.next()) {
				if (program.getSymbolTable().isExternalEntryPoint(at) || program.getFunctionManager().getFunctionAt(at) != null) return true;
				for (Reference ref : program.getReferenceManager().getReferencesTo(at)) if (ref.getReferenceType().isData()) return true;
			}
			return false;
		}

		/** A jump, branch or call from another address targets {@code insn}, or it is an entry. */
		private boolean enteredFromElsewhere(Instruction insn) {
			if (externalEntry(insn)) return true;
			for (Reference ref : program.getReferenceManager().getReferencesTo(insn.getMinAddress())) {
				if (ref.getReferenceType().isFlow() && !ref.getReferenceType().isFallthrough()) return true;
			}
			return false;
		}

		/** The registers when the branch lands, the address after the last instruction issued before that, and the issue order. */
		private record Landed(Map<Register, long[]> values, long end, Instruction partner, List<Instruction> issued, int[] cycles,
				boolean nested) {}

		/**
		 * Issue what the hardware issues from {@code branch}'s packet until {@code branch}, taken, lands six
		 * cycles later: the rest of its packet, then each next packet (SPRUFE8B 3.5, 4.2.6). Constants and
		 * predicates follow that order. Null when it does not decode, cannot be timed, or issues a transfer
		 * that may be taken with the branch.
		 */
		private Landed land(Instruction branch, List<Instruction> prefix, int[] prefixCycles, int branchIndex,
				Map<Register, long[]> values, Constants trace, List<PredicateFact> facts, Instruction partner, boolean valuesOnly) {
			List<Instruction> issued = new ArrayList<>(prefix);
			int[] cycles = java.util.Arrays.copyOf(prefixCycles, prefix.size() + MAX_WINDOW + 1);
			List<Instruction> outerPath = timedPath;
			int[] outerCycles = timedCycles;
			timedPath = issued;
			timedCycles = cycles;
			try {
				int cycle = cycles[branchIndex];
				long ours = cycle + 1 + DELAY_CYCLES;
				int span = 1;
				for (int i = branchIndex; i >= 0 && cycles[i] == cycle; i--) {
					if (untimed(program, prefix.get(i))) return null;
					span = Math.max(span, 1 + extraCycles(program, prefix.get(i)));
				}
				Instruction last = branch;
				boolean nested = false;
				long end = branch.getMaxAddress().getOffset() + 1;
				Instruction at = parallelWithNext(branch) ? next(branch) : null;
				if (at == null && parallelWithNext(branch)) return null;
				while (true) {
					for (Instruction insn = at; insn != null;) {
						int index = issued.size();
						if (index - prefix.size() >= MAX_WINDOW || untimed(program, insn)) return null;
						issued.add(insn);
						cycles[index] = cycle;
						Boolean runs = executes(issued, index, facts);
						if (transfer(insn)) {
							// One that may be taken with the branch lands in the callee: no call to place here.
							if (!Boolean.FALSE.equals(runs)) {
								if (!valuesOnly) return null;
								nested = true;
							}
							if (partner == null && complementary(branch, insn)) partner = insn;
						}
						trace.before(cycle);
						trace.instruction(insn, runs, cycle, index);
						span = Math.max(span, 1 + extraCycles(program, insn));
						last = insn;
						end = insn.getMaxAddress().getOffset() + 1;
						if (!parallelWithNext(insn)) break;
						insn = next(insn);
						if (insn == null) return null;
					}
					long nextCycle = cycle + (long) span;
					if (ours <= nextCycle) break;
					at = next(last);
					cycle = (int) nextCycle;
					if (at == null) return null;
					span = 1;
				}
				// Retire every pending write: a load's E5 or a later multi-cycle result supersedes an
				// earlier E1 link even after the callee is entered.
				trace.before(Integer.MAX_VALUE);
				return new Landed(values, end, partner, issued, cycles, nested);
			}
			catch (MemoryAccessException e) {
				return null;
			}
			finally {
				timedPath = outerPath;
				timedCycles = outerCycles;
			}
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
			if (!(op.equals("B.S1") || op.equals("B.S2"))) return false;
			var flow = C6000PacketStagingAnalyzer.flow(insn);
			// A latched branch transfers behind another instruction: it is no jump to continue or re-lay.
			return !C6000PacketStagingAnalyzer.inert(insn) && insn.getLength() == 4 &&
				insn.getRegister(0) == null && !insn.isInDelaySlot() &&
				insn.getFlowOverride() == FlowOverride.NONE && flow.isJump() && !flow.isCall() &&
				!flow.isTerminal() && C6000PacketStagingAnalyzer.hardware(insn).getDefaultFlows().length == 1;
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
			Address target = C6000PacketStagingAnalyzer.hardware(jump).getDefaultFlows()[0];
			// The target must idle while the transfer is in flight: most jumps stop here, before the window is decoded.
			Instruction first = decode(target);
			if (first == null || !baseName(first).equals("NOP")) return null;
			try {
				for (Address at : C6000ExecutionPackets.issuePrefix(program, jump.getMinAddress())) {
					Instruction prior = decode(at);
					if (prior == null || transfer(prior)) return null;
				}
			}
			catch (MemoryAccessException e) {
				return null;
			}
			List<Instruction> slots = window(jump);
			if (slots == null || slots.isEmpty()) return null;
			for (Instruction slot : slots) if (untimed(program, slot)) return null;
			List<Instruction> execution = new ArrayList<>(lookBack(jump));
			int at = execution.size();
			execution.add(jump);
			execution.addAll(slots);
			int[] issue = issueCycles(execution);
			String guard = predicate(jump);
			int found = -1;
			for (int i = at + 1; i < execution.size(); i++) {
				Instruction slot = execution.get(i);
				if (!transfer(slot)) continue;
				if (issue[i] == issue[at]) return null;
				if (complementary(jump, slot) && stable(execution, i, at, guard, true)) continue;
				if (found >= 0) return null;
				found = i;
			}
			if (found < 0) return null;
			Instruction transfer = execution.get(found);
			int cycle = issue[found] - issue[at];
			int end = execution.size() - 1;
			Address windowEnd = execution.get(end).getMaxAddress();
			if (target.compareTo(jump.getMinAddress()) >= 0 && target.compareTo(windowEnd) <= 0) return null;
			// Where the transfer lands in the jump's target, once its remaining cycles idle there.
			Address landing = idle(decode(target), cycle);
			if (landing == null) return null;
			// Exact when the proposed lifting runs what the hardware runs on every path.
			boolean exact = compare(jump, jump, new Proposal(jump, transfer, windowEnd)) == null;
			return new Preemption(jump, transfer, cycle, windowEnd, landing, exact);
		}

		/** The address after {@code cycles} cycles of NOP-only execute packets from {@code start}, else null. */
		private Address idle(Instruction start, int cycles) {
			Instruction current = start;
			try {
				while (current != null) {
					int span = 1;
					while (true) {
						if (!baseName(current).equals("NOP")) return null;
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
			// A sequence built in issue order (land) carries its own cycles; address order says nothing there.
			if (path == timedPath) return timedCycles;
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
			// By the prototype: the slot depth is 0 for some windows that hold compact slots or a header.
			if (insn.getPrototype().hasDelaySlots()) return writes;
			Register load = loadDestination(insn);
			for (Object result : C6000PacketStagingAnalyzer.hardware(insn).getResultObjects()) if (result instanceof Register r && (load == null || !overlaps(r, load))) writes.add(r);
			if (load != null) { Register base = updatingBase(insn);if (base != null && !writes.contains(base)) writes.add(base); }
			return writes;
		}

		private record Write(Register register, long[] value, int owner) {}

		private List<Instruction> timedPath;
		private int[] timedCycles;

		/** Constants visible before E1 reads, with atomic packet commits and E5 invalidations. */
		private final class Constants {
			private final Map<Register, long[]> values;
			private final TreeMap<Integer, List<Write>> pending = new TreeMap<>();
			Constants(Map<Register, long[]> values) { this.values = values; }
			private final Map<Register, Integer> lastWriter = new HashMap<>();
			private int forgotten = -1, at = -1;
			/** True when {@code register} may have been written at or after issue-order index {@code since}. */
			boolean writtenSince(Register register, int since) {
				if (forgotten >= since) return true;
				for (var entry : lastWriter.entrySet()) if (entry.getValue() >= since && overlaps(entry.getKey(), register)) return true;
				return false;
			}
			/** The values of {@code registers}, held or still to land, become unknown. */
			void forget(List<Register> registers) {
				values.keySet().removeIf(r -> registers.stream().anyMatch(c -> overlaps(c, r)));
				for (List<Write> writes : pending.values())
					writes.replaceAll(w -> registers.stream().anyMatch(c -> overlaps(c, w.register())) ? new Write(w.register(), null, w.owner()) : w);
				for (Register r : registers) lastWriter.merge(r, at, Math::max);
			}
			/** No value is held or still to land. */
			boolean holdsNothing() {
				if (!values.isEmpty()) return false;
				for (List<Write> writes : pending.values()) for (Write w : writes) if (w.value() != null) return false;
				return true;
			}
			/** Every value, held or still to land, becomes unknown; the writes still land. */
			void forget() {
				forgotten = at;
				values.clear();
				for (List<Write> writes : pending.values()) writes.replaceAll(w -> new Write(w.register(), null, w.owner()));
			}

			void write(int cycle, Register register, long[] value, int owner) {
				lastWriter.merge(register, owner, Math::max);
				at = Math.max(at, owner);
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
				at = Math.max(at, owner);
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
		 * Apply one instruction, assumed to run, to the constant map, from its p-code with the known
		 * registers as inputs; returns the register it writes a constant to, else null.
		 */
		Register track(Instruction insn, Map<Register, long[]> regs) {
			// A compact branch folds its parallel followers into its own p-code
			// as delay slots; they are tracked separately, so skip its writes.
			if (insn.getPrototype().hasDelaySlots() || transfer(insn)) return null;
			List<Register> written = new ArrayList<>();
			for (Object result : C6000PacketStagingAnalyzer.hardware(insn).getResultObjects()) if (result instanceof Register r) written.add(r);
			Long value = written.size() == 1 ? constantWrite(insn, written.get(0), regs) : null;
			for (Register r : written) regs.keySet().removeIf(known -> overlaps(known, r));
			if (value == null) return null;
			regs.put(written.get(0), new long[] { value, FULL });
			return written.get(0);
		}


		/** The index, in the last {@link #entryPath}, of the jump it came in through; -1 for a straight line. */
		int enteredBy = -1;

		/**
		 * The code that runs before {@code branch}, oldest first: {@code linear}, its straight-line
		 * look-back, unless the nearest label before it is reached only by one jump, with nothing
		 * falling into it. Then it is what runs before that jump, the jump, what issues until it lands,
		 * and the code from the label on. A jump latched with others enters where it lands. Any other
		 * transfer on the way must land before {@code branch} issues, so that reaching it means none was
		 * taken.
		 */
		List<Instruction> entryPath(Instruction branch, List<Instruction> linear) {
			enteredBy = -1;
			for (int k = linear.size() - 1; k > 0; k--) {
				Instruction label = listing.getInstructionAt(linear.get(k).getMinAddress());
				if (label == null) return linear;
				List<Instruction> jumps = new ArrayList<>();
				for (Reference ref : program.getReferenceManager().getReferencesTo(label.getMinAddress())) {
					if (ref.getReferenceType().isData()) return linear;
					if (!ref.getReferenceType().isFlow() || ref.getReferenceType().isFallthrough()) continue;
					Instruction jump = entering(listing.getInstructionAt(ref.getFromAddress()), label.getMinAddress());
					if (jump == null || ref.getReferenceType().isCall() || !transfer(jump)) return linear;
					jumps.add(jump);
				}
				if (externalEntry(label)) return linear;
				if (jumps.isEmpty()) continue;
				// Something falls into the label too: the straight line is one of two ways in.
				Instruction prior = listing.getInstructionBefore(label.getMinAddress());
				Instruction owner = prior == null ? null : C6000DelaySlots.unitOwner(program, prior);
				boolean falls = owner == null || !transfer(owner) || predicate(owner) != null ||
					C6000PacketStagingAnalyzer.flow(owner).isCall();
				if (jumps.size() != 1 || falls) return linear;
				Instruction jump = jumps.get(0);
				List<Instruction> taken = window(jump);
				if (taken == null || branch.getRegister(0) == null) return linear;
				List<Instruction> path = new ArrayList<>(lookBack(jump));
				int at = path.size();
				path.add(jump);
				path.addAll(taken);
				path.addAll(linear.subList(k, linear.size()));
				path.add(branch);
				int[] issue = issueCycles(path);
				for (int i = at + 1; i < path.size() - 1; i++)
					if (transfer(path.get(i)) && issue[i] + 1 + DELAY_CYCLES > issue[path.size() - 1]) return linear;
				path.remove(path.size() - 1);
				enteredBy = at;
				return path;
			}
			return linear;
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
				if (cycles[i] == last) continue;
				String p = predicate(instruction);
				if (query >= anchor && p != null && p.replace("!", "").equals(register.getName()) &&
					(p.startsWith("!") ? !nonzero : nonzero) == false) continue;
				// A constant replacement can preserve the predicate's truth value,
				// even when the instruction's own predicate is not known.
				// Backwards, one that would falsify the fact cannot have run (SPRUFE8B 3.12 MVK, 4.2.1).
				Long value = constantWrite(instruction, register);
				if (value != null && ((value != 0) == nonzero) == (query >= anchor)) continue;
				for (Register r : issueWrites(instruction)) if (overlaps(r, register)) return false;
			}
			return true;
		}

		/** The constant {@code insn} writes to {@code register} when it runs, from its p-code; null if none. */
		private Long constantWrite(Instruction insn, Register register) {
			return constantWrite(insn, register, Map.of());
		}

		/** The same, with the registers in {@code known} holding their full values. */
		private Long constantWrite(Instruction insn, Register register, Map<Register, long[]> known) {
			if (transfer(insn)) return null;
			List<long[]> seeds = new ArrayList<>();
			for (var entry : known.entrySet()) {
				if (entry.getValue()[1] != FULL) continue;
				Register r = entry.getKey();
				seeds.add(new long[] { r.getAddress().getOffset(), r.getMinimumByteSize(), entry.getValue()[0] });
			}
			// Running means its predicate held.
			String p = predicate(insn);
			Register guard = p == null ? null : program.getRegister(p.replace("!", ""));
			if (guard != null) seeds.add(new long[] { guard.getAddress().getOffset(), guard.getMinimumByteSize(), p.startsWith("!") ? 0 : 1 });
			Long value = C6000LoopCounterProof.constantOutput(program.getLanguage(), C6000PacketStagingAnalyzer.hardwarePcode(insn),
				register.getAddress().getOffset(), register.getMinimumByteSize(), seeds);
			return value == null ? null : value & 0xffffffffL;
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
						if (next == null || slots.size() >= MAX_WINDOW || untimed(program, next)) return null;
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
		var flow = C6000PacketStagingAnalyzer.flow(insn);
		return flow.isJump() || flow.isCall() || flow.isTerminal();
	}

	/**
	 * In an if/else pair sharing one B3 ("call Y if p, else jump to X") only
	 * one arm is a call. A register arm is the call; between two immediate
	 * arms the nearer target is the local else-block, so that arm is the
	 * jump. Both arms to one target (one callee either way) stay calls.
	 */
	static boolean jumpArm(Instruction branch, Instruction partner) {
		Long mine = targetDistance(branch), theirs = targetDistance(partner);
		// A branch through B3 reads the caller's return address as it issues: beside an arm that
		// targets another function, the link set in the window is that arm's, and this one returns.
		Register through = C6000PacketStagingAnalyzer.hardware(branch).getRegister(0);
		if (through != null && through.getName().equals("B3") && Boolean.FALSE.equals(localTarget(partner))) return true;
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
		Address[] flows = C6000PacketStagingAnalyzer.hardware(insn).getDefaultFlows();
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
	/** Idle cycles beyond the issue cycle, from C6000ExecutionPackets.cycles; none where untimed. */
	private static int extraCycles(Program program, Instruction insn) {
		try {
			Integer cycles = C6000ExecutionPackets.cycles(program, insn);
			return cycles == null ? 0 : cycles - 1;
		}
		catch (MemoryAccessException unavailable) { return 0; }
	}

	/** Timing outside the cycle model (C6000ExecutionPackets.cycles). */
	private static boolean untimed(Program program, Instruction insn) {
		try { return C6000ExecutionPackets.cycles(program, insn) == null; }
		catch (MemoryAccessException unavailable) { return true; }
	}

	private static final Map<InstructionPrototype, String> MNEMONICS = java.util.Collections.synchronizedMap(new WeakHashMap<>());

	/**
	 * {@code insn.getMnemonicString()}, which prints it from the parse tree on every call. Every
	 * piece of a mnemonic in this language is a literal or a subtable with constant text (no field
	 * value), so it depends only on the constructors and the delay-slot flag: what a prototype is.
	 */
	static String mnemonic(Instruction insn) {
		return MNEMONICS.computeIfAbsent(insn.getPrototype(), p -> insn.getMnemonicString());
	}

	/** Mnemonic without a predicate prefix or the compact underscore marker. */
	static String baseName(Instruction insn) {
		String name = mnemonic(insn);
		int predicate = name.indexOf(']');
		if (predicate >= 0) name = name.substring(predicate + 1);
		return name.startsWith("_") ? name.substring(1) : name;
	}

	private static boolean adjacent(Instruction a, Instruction b) {
		return b.getMinAddress().getOffset() == a.getMaxAddress().getOffset() + 1;
	}
}
