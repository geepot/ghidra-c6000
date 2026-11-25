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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Issue #73: a branch issued in another branch's delay window lands after it, and native lifting
 * gives each branch one window that holds no other branch (SPRUFE8B 3.5, 4.2.6). Where the hardware
 * and the listing then run different instructions, this latches the branches of the stretch: each
 * records its predicate and target as it issues and does not transfer, and the instruction it lands
 * behind carries its jump, call or return (c6000.sinc Land). The latched lifting is kept only when
 * it runs what the hardware runs on every consistent outcome of the predicates, by the same
 * comparison that decides the nested-window warning; anything else keeps that warning.
 */
public final class C6000NestedLiftAnalyzer extends AbstractAnalyzer {
	public C6000NestedLiftAnalyzer() {
		super("C6000 Nested Branch Lifting",
			"Latches branches issued in each other's delay windows and lands each behind the instruction the hardware does, " +
				"where that is what the hardware runs on every path",
			AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		// After the windows and issue #52 releases; before packet staging and the warnings.
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after().after().after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C6000PacketContext.isC6000(program) && program.getRegister("c_inert") != null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		var walker = new C6000CallAnalyzer.Walker(program);
		int lifted = 0;
		for (Function function : program.getFunctionManager().getFunctions(set, true)) {
			monitor.checkCancelled();
			if (C6000ProgramActions.hasActiveReview(program, function)) continue;
			Set<Address> tried = new HashSet<>();
			boolean again = true;
			// A lifting decodes its stretch again, so start over after each one.
			while (again) {
				again = false;
				for (Instruction branch : program.getListing().getInstructions(function.getBody(), true)) {
					monitor.checkCancelled();
					String op = C6000CallAnalyzer.baseName(branch);
					if (!op.startsWith("B") || op.startsWith("BITC") || op.startsWith("BITR") || !tried.add(branch.getAddress())) continue;
					// Nested with another transfer, or a predicated call that returns to earlier code,
					// which needs its return and its fall-through both (issue #66).
					if ((walker.nestedTransfer(branch) == null && walker.predicatedBackwardCall(branch) == null) ||
						walker.nativeMismatch(branch) == null) continue;
					var plan = walker.liftPlan(branch);
					if (plan == null || walker.liftMismatch(plan, branch) != null) continue;
					try {
						if (lift(program, walker, plan, branch)) {
							lifted++;
							again = true;
							break;
						}
					}
					catch (Exception e) {
						log.appendMsg(getName(), "left " + branch.getAddress() + " as it was: " + e.getMessage());
					}
				}
			}
		}
		if (lifted > 0) Msg.info(this, getName() + "> latched " + lifted + " stretch(es)");
		return true;
	}

	/** Why the last plan for each branch was dropped though its check passed, for the warning that stays. */
	private static final Map<Program, Map<Address, String>> DROPPED = java.util.Collections.synchronizedMap(new java.util.WeakHashMap<>());

	static String dropped(Program program, Address branch) {
		Map<Address, String> reasons = DROPPED.get(program);
		return reasons == null ? null : reasons.get(branch);
	}

	private static boolean drop(Program program, Instruction outer, String why) {
		DROPPED.computeIfAbsent(program, k -> new java.util.concurrent.ConcurrentHashMap<>()).put(outer.getMinAddress(), why);
		return false;
	}

	private static boolean lift(Program program, C6000CallAnalyzer.Walker walker, final C6000CallAnalyzer.Walker.Lifting planned,
			Instruction outer) throws Exception {
		Map<Address, String> reasons = DROPPED.get(program);
		if (reasons != null) reasons.remove(outer.getMinAddress());
		C6000CallAnalyzer.Walker.Lifting plan = planned;
		Address start = plan.first().getMinAddress();
		// A landing some other stretch put on an instruction of this one stays: the instruction
		// carries it beside the plan's own, and the plan keeps off that stretch's latch, which may
		// be set while this stretch runs (issue #140).
		Map<Address, List<C6000CallAnalyzer.Walker.Landing>> foreign = new TreeMap<>();
		Set<Integer> theirs = new HashSet<>();
		for (Instruction insn : program.getListing().getInstructions(new ghidra.program.model.address.AddressSet(start, plan.last()), true))
			for (var held : walker.landingsAt(insn.getMinAddress()))
				if (planned.latches().stream().noneMatch(l -> l.land().getMinAddress().equals(insn.getMinAddress()) &&
						(l.kind() == held.kind() && java.util.Objects.equals(l.target(), held.target())))) {
					foreign.computeIfAbsent(insn.getMinAddress(), k -> new ArrayList<>()).add(held);
					theirs.add(held.slot());
				}
		if (!foreign.isEmpty()) {
			Set<Integer> used = new HashSet<>(theirs);
			for (var latch : plan.latches()) used.add(latch.slot());
			Map<Integer, Integer> renumbered = new HashMap<>();
			for (var latch : plan.latches()) {
				if (!theirs.contains(latch.slot()) || renumbered.containsKey(latch.slot())) continue;
				int free = 0;
				while (free < 8 && used.contains(free)) free++;
				if (free == 8) return drop(program, outer, "another stretch's landing inside it leaves no free latch");
				used.add(free);
				renumbered.put(latch.slot(), free);
			}
			if (!renumbered.isEmpty()) {
				List<C6000CallAnalyzer.Walker.Latch> latches = new ArrayList<>();
				for (var latch : plan.latches()) latches.add(new C6000CallAnalyzer.Walker.Latch(latch.branch(),
					renumbered.getOrDefault(latch.slot(), latch.slot()), latch.land(), latch.kind(), latch.target(), latch.sure()));
				plan = new C6000CallAnalyzer.Walker.Lifting(plan.first(), plan.last(), latches);
			}
		}
		Map<Address, Map<Register, BigInteger>> fields = new TreeMap<>();
		Map<Address, Integer> landings = new HashMap<>();
		// The other stretch's landings first, as they were.
		for (var entry : foreign.entrySet()) {
			Address at = entry.getKey();
			var land = fields.computeIfAbsent(at, k -> new HashMap<>());
			Instruction site = program.getListing().getInstructionAt(at);
			if (site != null && C6000PacketStagingAnalyzer.inert(site)) {
				// A latched branch of that stretch: its own fields stay too.
				put(program, land, "c_inert_wrap", site.getRegister(0) != null ? 2 : 1);
				put(program, land, "c_inert", 1);
				put(program, land, "c_latch_t", C6000PacketStagingAnalyzer.field(site, "c_latch_t"));
				put(program, land, "c_flow_delay", 0);
			}
			else put(program, land, "c_staged", 1);
			for (var held : entry.getValue()) {
				if (landings.merge(at, 1, Integer::sum) > 2) return drop(program, outer, "the instruction at " + at + " would carry three landings");
				String slot = landings.get(at) == 1 ? "c_land1" : "c_land2";
				put(program, land, slot, held.kind() == 4 ? 3 : held.kind());
				put(program, land, slot + "_t", held.slot());
				put(program, land, slot + "_ind", held.target() == null ? 1 : 0);
				put(program, land, slot + "_sure", held.sure() ? 1 : 0);
				put(program, land, slot + "_disp", held.target() == null ? 0 : (int) ((held.target().getOffset() - (at.getOffset() & ~31L)) / 2));
			}
		}
		for (var latch : plan.latches()) {
			var branch = fields.computeIfAbsent(latch.branch().getMinAddress(), k -> new HashMap<>());
			put(program, branch, "c_inert_wrap", latch.branch().getRegister(0) != null ? 2 : 1);
			put(program, branch, "c_inert", 1);
			put(program, branch, "c_latch_t", latch.slot());
			put(program, branch, "c_flow_delay", 0);
		}
		for (var latch : plan.latches()) {
			Address at = latch.land().getMinAddress();
			var land = fields.computeIfAbsent(at, k -> new HashMap<>());
			int count = landings.merge(at, 1, Integer::sum);
			if (count > 2) return drop(program, outer, "the instruction at " + at + " would carry three landings, another stretch's among them");
			String slot = count == 1 ? "c_land1" : "c_land2";
			// A plain instruction carries the landing in its wrapper; a latched branch in its own ending.
			if (!land.containsKey(program.getRegister("c_inert"))) put(program, land, "c_staged", 1);
			put(program, land, slot, latch.kind() == 4 ? 3 : latch.kind());
			put(program, land, slot + "_t", latch.slot());
			put(program, land, slot + "_ind", latch.target() == null ? 1 : 0);
			long disp = latch.target() == null ? 0 : (latch.target().getOffset() - (at.getOffset() & ~31L)) / 2;
			put(program, land, slot + "_sure", latch.sure() ? 1 : 0);
			if (disp < -(1 << 19) || disp >= 1 << 19 || (latch.target() != null && (latch.target().getOffset() & 1) != 0))
				return drop(program, outer, "the landing at " + at + " cannot reach " + latch.target());
			put(program, land, slot + "_disp", (int) disp);
		}
		// A user's own override of a branch stands.
		for (var latch : plan.latches())
			for (Reference ref : latch.branch().getReferencesFrom())
				if (ref.getReferenceType().isOverride() && ref.getSource() == ghidra.program.model.symbol.SourceType.USER_DEFINED)
					return drop(program, outer, "the branch at " + latch.branch().getMinAddress() + " has a user's flow override");
		Set<Address> before = new HashSet<>();
		for (Address at : fields.keySet()) {
			Instruction now = program.getListing().getInstructionAt(at);
			if (now != null && (C6000PacketStagingAnalyzer.inert(now) || !walker.landingsAt(at).isEmpty())) before.add(at);
		}
		// The stretch, then each instruction outside it that carries a landing.
		List<C6000DelaySlots.Relifted> undo = new ArrayList<>();
		String failed = null;
		try {
			Map<Address, Map<Register, BigInteger>> inside = new TreeMap<>(fields);
			inside.keySet().removeIf(at -> at.compareTo(start) < 0 || at.compareTo(planned.last()) > 0);
			undo.add(C6000DelaySlots.relift(program, start, plan.last(), inside));
			Set<Address> relifted = new HashSet<>();
			for (var entry : fields.entrySet()) {
				Address at = entry.getKey();
				if (at.compareTo(start) >= 0 && at.compareTo(plan.last()) <= 0 || relifted.contains(at)) continue;
				Instruction site = program.getListing().getInstructionAt(at);
				if (site == null) throw new IllegalStateException("no instruction at " + at);
				// A branch latched outside the stretch takes its native window with it, so those slots become plain code (SPRUFE8B 3.5, 4.2.6).
				Address end = site.getPrototype().hasDelaySlots() ? site.getMaxAddress().add(site.getPrototype().getDelaySlotByteCount()) : site.getMaxAddress();
				Map<Address, Map<Register, BigInteger>> part = new TreeMap<>(fields);
				part.keySet().removeIf(a -> a.compareTo(at) < 0 || a.compareTo(end) > 0);
				relifted.addAll(part.keySet());
				undo.add(C6000DelaySlots.relift(program, at, end, part));
			}
			// A landing into another window's slots is one more entry into it: past the decompiler's
			// limit the function would not decompile at all, so the nest keeps its warning (issue #99).
			// Only a landing whose target is a native delay slot adds such an entry; asking the
			// decompiler about a large function for every lifting would cost minutes.
			Function owner = program.getFunctionManager().getFunctionContaining(outer.getMinAddress());
			boolean enters = false;
			for (var latch : plan.latches()) {
				Instruction target = latch.target() == null ? null : program.getListing().getInstructionContaining(latch.target());
				enters |= target != null && (target.isInDelaySlot() || !target.getMinAddress().equals(latch.target()));
			}
			boolean runs = kept(program, walker, plan, outer);
			boolean over = runs && enters && owner != null && C6000DelaySlots.pastOverlapLimit(program, owner, ghidra.util.task.TaskMonitor.DUMMY);
			failed = !runs ? keptWhy :
				"it adds an entry into a native delay window, past what the decompiler takes in one function (issue #99)";
			if (runs && !over) {
				// Ghidra types every flow of an instruction that also lands a call as a call: give each
				// landed jump's target its own type, or it becomes a function.
				var references = program.getReferenceManager();
				for (var latch : plan.latches()) {
					if ((latch.kind() != 1 && latch.kind() != 4) || latch.target() == null) continue;
					for (Reference ref : references.getReferencesFrom(latch.land().getMinAddress())) {
						if (!ref.getToAddress().equals(latch.target()) || !ref.getReferenceType().isCall()) continue;
						references.delete(ref);
						references.addMemoryReference(ref.getFromAddress(), ref.getToAddress(),
							latch.sure() ? ghidra.program.model.symbol.RefType.UNCONDITIONAL_JUMP : ghidra.program.model.symbol.RefType.CONDITIONAL_JUMP,
							ghidra.program.model.symbol.SourceType.ANALYSIS, ref.getOperandIndex());
					}
				}
				// The landings are new flows: a call among them needs a function at its target, and the
				// code a landed call returns to may never have been decoded (a call lifted as a tail
				// call before, issue #114).
				var analysis = ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(program);
				for (Address at : fields.keySet()) {
					Instruction site = program.getListing().getInstructionAt(at);
					if (site == null) continue;
					C6000DelaySlots.announce(program, new ghidra.program.model.address.AddressSet(at, site.getMaxAddress()));
					Address after = site.getFallThrough();
					if (after != null && program.getListing().getInstructionContaining(after) == null && analysis != null) analysis.disassemble(after);
				}
				return true;
			}
		}
		catch (Exception e) {
			for (int i = undo.size() - 1; i >= 0; i--) undo.get(i).putBack();
			throw e;
		}
		for (int i = undo.size() - 1; i >= 0; i--) undo.get(i).putBack();
		// Nothing of a lifting taken back may stay in the listing's context.
		for (Address at : fields.keySet()) {
			Instruction now = program.getListing().getInstructionAt(at);
			if (now != null && (C6000PacketStagingAnalyzer.inert(now) || !walker.landingsAt(at).isEmpty()) && !before.contains(at))
				throw new IllegalStateException("the lifting at " + at + " could not be taken back");
		}
		return drop(program, outer, failed);
	}

	/** Moves the latched branches' flows to where they land; false when the listing does not then run what the hardware runs. */
	private static boolean kept(Program program, C6000CallAnalyzer.Walker walker, C6000CallAnalyzer.Walker.Lifting plan, Instruction outer) {
		Set<Address> done = new HashSet<>();
		for (var latch : plan.latches()) {
			Instruction branch = program.getListing().getInstructionAt(latch.branch().getMinAddress());
			// An encoding with no latched form decodes as it was.
			if (branch == null || !latches(program, branch, latch.slot())) {
				keptWhy = "the branch at " + latch.branch().getMinAddress() + " has no latched form";
				return false;
			}
			if (!done.add(branch.getMinAddress())) continue;
			if (branch.isFallThroughOverridden()) branch.clearFallThroughOverride();
			// Its landing says what it is; an override here would change a landing it carries for another branch.
			branch.setFlowOverride(ghidra.program.model.listing.FlowOverride.NONE);
			for (Reference ref : branch.getReferencesFrom()) {
				if (!ref.getReferenceType().isFlow() || ref.getReferenceType().isFallthrough()) continue;
				// Its register target's references go where the transfer now is.
				if (latch.target() == null) for (var site : plan.latches())
					if (site.branch().getMinAddress().equals(branch.getMinAddress()))
						program.getReferenceManager().addMemoryReference(site.land().getMinAddress(), ref.getToAddress(), ref.getReferenceType(), ref.getSource(), 0);
				program.getReferenceManager().delete(ref);
			}
		}
		Instruction now = program.getListing().getInstructionAt(outer.getMinAddress());
		keptWhy = now == null ? "its outer branch no longer decodes" : walker.nativeMismatch(now);
		if (keptWhy != null) keptWhy = "the listing it gave does not run as the hardware does: " + keptWhy;
		return keptWhy == null;
	}

	/** Why the last {@link #kept} refused. */
	private static String keptWhy;

	/** The instruction's p-code records its predicate in its latch: it is the latched form. */
	private static boolean latches(Program program, Instruction branch, int slot) {
		Register latch = program.getRegister("C6000_LATCH_T" + slot);
		for (PcodeOp op : branch.getPcode())
			if (latch != null && op.getOutput() != null && op.getOutput().isRegister() && op.getOutput().getAddress().equals(latch.getAddress())) return true;
		return false;
	}

	private static void put(Program program, Map<Register, BigInteger> fields, String name, int value) {
		Register field = program.getRegister(name);
		fields.put(field, BigInteger.valueOf(value).and(BigInteger.ONE.shiftLeft(field.getBitLength()).subtract(BigInteger.ONE)));
	}
}
