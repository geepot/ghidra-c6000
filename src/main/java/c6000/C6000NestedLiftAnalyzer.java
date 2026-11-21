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
					if (walker.nestedTransfer(branch) == null || walker.nativeMismatch(branch) == null) continue;
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

	private static boolean lift(Program program, C6000CallAnalyzer.Walker walker, C6000CallAnalyzer.Walker.Lifting plan,
			Instruction outer) throws Exception {
		Map<Address, Map<Register, BigInteger>> fields = new TreeMap<>();
		Map<Address, Integer> landings = new HashMap<>();
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
			String slot = landings.merge(at, 1, Integer::sum) == 1 ? "c_land1" : "c_land2";
			// A plain instruction carries the landing in its wrapper; a latched branch in its own ending.
			if (!land.containsKey(program.getRegister("c_inert"))) put(program, land, "c_staged", 1);
			put(program, land, slot, latch.kind());
			put(program, land, slot + "_t", latch.slot());
			put(program, land, slot + "_ind", latch.target() == null ? 1 : 0);
			long disp = latch.target() == null ? 0 : (latch.target().getOffset() - (at.getOffset() & ~31L)) / 2;
			if (disp < -(1 << 20) || disp >= 1 << 20 || (latch.target() != null && (latch.target().getOffset() & 1) != 0))
				return false;
			put(program, land, slot + "_disp", (int) disp);
		}
		Address start = plan.first().getMinAddress();
		var undo = C6000DelaySlots.relift(program, start, plan.last(), fields);
		// A latched branch falls through to its next instruction and holds no flow of its own any more.
		for (var latch : plan.latches()) {
			Instruction branch = program.getListing().getInstructionAt(latch.branch().getMinAddress());
			if (branch == null || !branch.getFlowType().isFallthrough()) {
				// This encoding has no latched form.
				undo.putBack();
				return false;
			}
			Instruction land = program.getListing().getInstructionAt(latch.land().getMinAddress());
			if (branch.isFallThroughOverridden()) branch.clearFallThroughOverride();
			for (Reference ref : branch.getReferencesFrom()) {
				if (!ref.getReferenceType().isFlow() || ref.getReferenceType().isFallthrough()) continue;
				// Its register target's references go where the transfer now is.
				if (latch.target() == null && land != null)
					program.getReferenceManager().addMemoryReference(land.getMinAddress(), ref.getToAddress(), ref.getReferenceType(), ref.getSource(), 0);
				program.getReferenceManager().delete(ref);
			}
		}
		// Keep it only if the listing now runs what the hardware runs.
		Instruction now = program.getListing().getInstructionAt(outer.getMinAddress());
		if (now == null || walker.nativeMismatch(now) != null) {
			undo.putBack();
			return false;
		}
		return true;
	}

	private static void put(Program program, Map<Register, BigInteger> fields, String name, int value) {
		Register field = program.getRegister(name);
		fields.put(field, BigInteger.valueOf(value).and(BigInteger.ONE.shiftLeft(field.getBitLength()).subtract(BigInteger.ONE)));
	}
}
