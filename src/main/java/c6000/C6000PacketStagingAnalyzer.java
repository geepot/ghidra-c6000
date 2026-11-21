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
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Issue #71: every member of an execute packet reads its operands before any member writes (SPRUFE8B 3.5),
 * but p-code runs the members in order. Where a member reads a register an earlier member writes, the
 * earlier member's write is staged: its register keeps the old value and the result waits in a
 * C6000_NEW register until the last member that reads the old value has run (c6000.sinc StagePre,
 * StagePost and StageCommit, selected by context fields this analyzer sets). A read this cannot stage
 * stays for the same-packet hazard warning.
 */
public final class C6000PacketStagingAnalyzer extends AbstractAnalyzer {
	private static final String[] FIELDS = { "c_staged", "c_defer", "c_defer_reg", "c_cm1", "c_cm1_reg", "c_cm2", "c_cm2_reg" };

	public C6000PacketStagingAnalyzer() {
		super("C6000 Packet Staging",
			"Stages a packet member's write when a later member of its execute packet reads the old value, " +
				"so native lifting reads before it writes as the hardware does",
			AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		// After the windows are final; before the same-packet hazard warning.
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after().after().after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C6000PacketContext.isC6000(program) && program.getRegister("c_staged") != null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		int staged = 0;
		for (Function function : program.getFunctionManager().getFunctions(set, true)) {
			monitor.checkCancelled();
			// An active reviewed schedule already reads each packet's operands before its writes.
			if (C6000ProgramActions.hasActiveReview(program, function)) continue;
			try {
				staged += stage(program, function, monitor);
			}
			catch (MemoryAccessException e) {
				Msg.debug(this, "Skipped " + function.getName() + ": " + e.getMessage());
			}
			catch (CancelledException e) {
				throw e;
			}
			catch (Exception e) {
				log.appendMsg(getName(), "left " + function.getName() + " unstaged: " + e.getMessage());
			}
		}
		if (staged > 0) Msg.info(this, getName() + "> staged " + staged + " write(s)");
		return true;
	}

	/** Clear the staging fields of a decode context: what the instruction is without staging. */
	static void unstage(Program program, ghidra.program.model.lang.ProcessorContextImpl context) {
		if (program.getRegister("c_staged") == null) return;
		for (String name : FIELDS)
			context.setRegisterValue(new ghidra.program.model.lang.RegisterValue(program.getRegister(name), BigInteger.ZERO));
	}

	/**
	 * The instruction without staging: what the hardware instruction reads, writes and does. Analyses
	 * that model the pipeline themselves ask this, not the staged listing.
	 */
	static Instruction hardware(Instruction ins) {
		Program program = ins.getProgram();
		if (program.getRegister("c_staged") == null) return ins;
		boolean any = false;
		for (String name : new String[] { "c_staged", "c_cm1", "c_cm2" }) {
			BigInteger value = ins.getValue(program.getRegister(name), false);
			any |= value != null && value.signum() != 0;
		}
		if (!any) return ins;
		try {
			var context = new ghidra.program.model.lang.ProcessorContextImpl(program.getLanguage());
			var value = ins.getRegisterValue(program.getLanguage().getContextBaseRegister());
			if (value != null) context.setRegisterValue(value);
			unstage(program, context);
			var buffer = new ghidra.program.model.mem.DumbMemBufferImpl(program.getMemory(), ins.getAddress());
			var prototype = program.getLanguage().parse(buffer, context, ins.isInDelaySlot());
			return new ghidra.app.util.PseudoInstruction(program, ins.getAddress(), prototype, buffer, context);
		}
		catch (Exception e) {
			return ins;
		}
	}

	static PcodeOp[] hardwarePcode(Instruction ins) {
		return hardware(ins).getPcode();
	}

	/** True when {@code writer}'s write to {@code register} is staged. */
	static boolean staged(Program program, Instruction writer, Varnode register) {
		Register defer = program.getRegister("c_defer");
		if (defer == null) return false;
		BigInteger on = writer.getValue(defer, false);
		Integer index = index(program, register);
		return on != null && on.intValue() == 1 && index != null &&
			index == writer.getValue(program.getRegister("c_defer_reg"), false).intValue();
	}

	/** The staging index of a whole A or B register, 0-31 and 32-63; null for anything else. */
	private static Integer index(Program program, Varnode v) {
		Register r = program.getRegister(v.getAddress(), v.getSize());
		if (r == null || v.getSize() != 4 || !r.getName().matches("[AB]([0-9]|[12][0-9]|3[01])")) return null;
		return (r.getName().charAt(0) == 'B' ? 32 : 0) + Integer.parseInt(r.getName().substring(1));
	}

	private static boolean transfer(Instruction ins) {
		var flow = ins.getFlowType();
		return flow.isJump() || flow.isCall() || flow.isTerminal() || ins.getPrototype().hasDelaySlots();
	}

	/** One staged write: the member that writes, its register, and the member after which the result is committed. */
	private record Stage(Instruction writer, int register, Instruction committer) {}

	private static int stage(Program program, Function function, TaskMonitor monitor) throws Exception {
		// The old reads of each writer's register, grouped by writer.
		Map<Address, List<C6000SamePacketHazardAnalyzer.OldRead>> byWriter = new LinkedHashMap<>();
		for (var read : C6000SamePacketHazardAnalyzer.oldReads(program, function, monitor))
			byWriter.computeIfAbsent(read.writer().getAddress(), k -> new ArrayList<>()).add(read);
		List<Stage> stages = new ArrayList<>();
		Map<Address, Integer> commits = new HashMap<>();
		for (var reads : byWriter.values()) {
			Instruction writer = reads.get(0).writer();
			Integer register = index(program, reads.get(0).register());
			// One whole A or B register per writer; a transfer's own writes are not its peers' to read.
			if (register == null || transfer(writer) ||
				reads.stream().anyMatch(r -> !r.register().equals(reads.get(0).register()))) continue;
			Instruction last = reads.get(reads.size() - 1).reader();
			// Two results at most are committed after one member.
			if (commits.merge(last.getAddress(), 1, Integer::sum) > 2) continue;
			stages.add(new Stage(writer, register, last));
		}
		Map<Address, Map<String, Integer>> wanted = wanted(stages);
		apply(program, function, wanted, monitor);
		// Keep only what the p-code now does; anything else goes back and stays a warned hazard.
		List<Stage> held = new ArrayList<>();
		for (Stage stage : stages) if (holds(program, stage)) held.add(stage);
		if (held.size() != stages.size()) apply(program, function, wanted(held), monitor);
		return held.size();
	}

	private static Map<Address, Map<String, Integer>> wanted(List<Stage> stages) {
		Map<Address, Map<String, Integer>> wanted = new TreeMap<>();
		for (Stage stage : stages) {
			var writer = wanted.computeIfAbsent(stage.writer().getAddress(), k -> new HashMap<>());
			writer.put("c_staged", 1);
			writer.put("c_defer", 1);
			writer.put("c_defer_reg", stage.register());
			var committer = wanted.computeIfAbsent(stage.committer().getAddress(), k -> new HashMap<>());
			// A branch commits after its own reads, inside its delay table; anything else in the wrapper.
			if (!transfer(stage.committer())) committer.put("c_staged", 1);
			String slot = committer.containsKey("c_cm1") ? "c_cm2" : "c_cm1";
			committer.put(slot, 1);
			committer.put(slot + "_reg", stage.register());
		}
		return wanted;
	}

	/** Set the staging fields of every instruction in the function to {@code wanted}, zero elsewhere. */
	private static void apply(Program program, Function function, Map<Address, Map<String, Integer>> wanted,
			TaskMonitor monitor) throws Exception {
		Map<Address, Map<Address, Map<Register, BigInteger>>> units = new TreeMap<>();
		for (Instruction ins : program.getListing().getInstructions(function.getBody(), true)) {
			monitor.checkCancelled();
			Map<Register, BigInteger> change = new HashMap<>();
			for (String name : FIELDS) {
				Register field = program.getRegister(name);
				BigInteger now = ins.getValue(field, false);
				int want = wanted.getOrDefault(ins.getAddress(), Map.of()).getOrDefault(name, 0);
				if ((now == null ? 0 : now.intValue()) != want) change.put(field, BigInteger.valueOf(want));
			}
			if (change.isEmpty()) continue;
			Instruction owner = C6000DelaySlots.unitOwner(program, ins);
			units.computeIfAbsent(owner.getAddress(), k -> new HashMap<>()).put(ins.getAddress(), change);
		}
		// Never polled past here: a unit is decoded whole or not at all.
		for (var unit : units.entrySet()) C6000DelaySlots.recontext(program, unit.getKey(), unit.getValue());
	}

	/** The writer's p-code holds its result, and the committer's p-code moves it into the register. */
	private static boolean holds(Program program, Stage stage) {
		String name = (stage.register() >= 32 ? "B" : "A") + (stage.register() & 31);
		Register real = program.getRegister(name), held = program.getRegister("C6000_NEW_" + name);
		Instruction writer = program.getListing().getInstructionAt(stage.writer().getAddress());
		Instruction committer = program.getListing().getInstructionAt(stage.committer().getAddress());
		if (real == null || held == null || writer == null || committer == null) return false;
		boolean holds = false, commits = false;
		for (PcodeOp op : writer.getPcode()) holds |= writes(op, held);
		for (PcodeOp op : committer.getPcode())
			commits |= op.getOpcode() == PcodeOp.COPY && writes(op, real) && op.getInput(0).isRegister() &&
				op.getInput(0).getAddress().equals(held.getAddress());
		return holds && commits;
	}

	private static boolean writes(PcodeOp op, Register register) {
		Varnode out = op.getOutput();
		return out != null && out.isRegister() && out.getAddress().equals(register.getAddress()) && out.getSize() == register.getMinimumByteSize();
	}
}
