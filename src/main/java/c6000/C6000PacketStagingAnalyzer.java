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
	private static final String[] FIELDS = { "c_staged", "c_defer", "c_defer_pair", "c_defer_reg", "c_cm1", "c_cm1_reg", "c_cm2", "c_cm2_reg" };
	/** Every field that changes native lifting only: staging, and latched branches with their landings. */
	static final String[] LIFTING = { "c_staged", "c_defer", "c_defer_pair", "c_defer_reg", "c_cm1", "c_cm1_reg", "c_cm2", "c_cm2_reg",
		"c_inert_wrap", "c_inert", "c_latch_t", "c_land1", "c_land1_ind", "c_land1_t", "c_land1_sure", "c_land1_disp",
		"c_land2", "c_land2_ind", "c_land2_t", "c_land2_sure", "c_land2_disp" };

	public C6000PacketStagingAnalyzer() {
		super("C6000 Packet Staging",
			"Stages a packet member's write when a later member of its execute packet reads the old value, " +
				"so native lifting reads before it writes as the hardware does",
			AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		// After the windows are final; before the same-packet hazard warning.
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after().after().after().after());
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
		for (String name : LIFTING)
			context.setRegisterValue(new ghidra.program.model.lang.RegisterValue(program.getRegister(name), BigInteger.ZERO));
	}

	/**
	 * The instruction without staging: what the hardware instruction reads, writes and does. Analyses
	 * that model the pipeline themselves ask this, not the staged listing.
	 */
	static synchronized Instruction hardware(Instruction ins) {
		// The analyses ask this for the same instruction objects many times between changes to the
		// program; each answer costs a context read from the database and often a decode.
		Program owner = ins.getProgram();
		long stamp = owner.getModificationNumber();
		if (hardwareOf.get() != owner || hardwareStamp != stamp || hardwareCache.size() > 200_000) {
			hardwareCache.clear();
			hardwareOf = new java.lang.ref.WeakReference<>(owner);
			hardwareStamp = stamp;
		}
		Instruction known = hardwareCache.get(ins);
		if (known == null) hardwareCache.put(ins, known = hardwareNow(ins));
		return known;
	}

	private static final java.util.IdentityHashMap<Instruction, Instruction> hardwareCache = new java.util.IdentityHashMap<>();
	private static java.lang.ref.WeakReference<Program> hardwareOf = new java.lang.ref.WeakReference<>(null);
	private static long hardwareStamp;

	private static Instruction hardwareNow(Instruction ins) {
		Program program = ins.getProgram();
		Register[] fields = HARDWARE_FIELDS.computeIfAbsent(program.getLanguage(), C6000PacketStagingAnalyzer::hardwareFields);
		if (fields.length == 0) return ins;
		// One context read per instruction: reading each field on its own goes to the database again.
		var value = ins.getRegisterValue(program.getLanguage().getContextBaseRegister());
		if (value == null) return ins;
		boolean any = false;
		for (Register field : fields) {
			BigInteger set = value.getRegisterValue(field).getUnsignedValue();
			any |= set != null && set.signum() != 0;
		}
		if (!any) return ins;
		try {
			var context = new ghidra.program.model.lang.ProcessorContextImpl(program.getLanguage());
			context.setRegisterValue(value);
			unstage(program, context);
			var buffer = new ghidra.program.model.mem.DumbMemBufferImpl(program.getMemory(), ins.getAddress());
			var prototype = program.getLanguage().parse(buffer, context, ins.isInDelaySlot());
			return new ghidra.app.util.PseudoInstruction(program, ins.getAddress(), prototype, buffer, context);
		}
		catch (Exception e) {
			return ins;
		}
	}

	private static final Map<ghidra.program.model.lang.Language, Register[]> HARDWARE_FIELDS =
		new java.util.concurrent.ConcurrentHashMap<>();

	/** The context fields that make the listing's instruction differ from the hardware's; none without staging. */
	private static Register[] hardwareFields(ghidra.program.model.lang.Language language) {
		if (language.getRegister("c_staged") == null) return new Register[0];
		List<Register> fields = new ArrayList<>();
		for (String name : new String[] { "c_staged", "c_cm1", "c_cm2", "c_inert_wrap", "c_inert", "c_land1", "c_land2" })
			fields.add(language.getRegister(name));
		return fields.toArray(Register[]::new);
	}

	/**
	 * The hardware instruction's flow, with the listing's override: a latched branch is still a
	 * branch, and the instruction it lands behind is not. A latched branch has no override of its own,
	 * which would change the landing it may carry for another branch: it is a call or a return as
	 * the landing that reads its latch says.
	 */
	public static ghidra.program.model.symbol.FlowType flow(Instruction ins) {
		Instruction hardware = hardware(ins);
		if (hardware == ins) return ins.getFlowType();
		var override = ins.getFlowOverride();
		if (inert(ins)) {
			Instruction site = landingSite(ins);
			int kind = site == null ? 0 : landingKind(site, field(ins, "c_latch_t"));
			override = kind == 2 ? ghidra.program.model.listing.FlowOverride.CALL :
				kind == 3 ? ghidra.program.model.listing.FlowOverride.RETURN : ghidra.program.model.listing.FlowOverride.NONE;
		}
		return ghidra.program.model.listing.FlowOverride.getModifiedFlowType(hardware.getFlowType(), override);
	}

	/**
	 * The instruction the latched branch {@code branch} lands behind in address order: the first one
	 * from it on that carries a landing for its latch, which is not used again until then. Null if none.
	 */
	public static Instruction landingSite(Instruction branch) {
		int slot = field(branch, "c_latch_t");
		Instruction at = branch;
		// The rest of its execute packet and five more of up to eight instructions (SPRUFE8B 3.5; issue #122).
		for (int n = 0; n <= C6000CallAnalyzer.MAX_WINDOW && at != null; n++, at = at.getNext())
			if (landingKind(at, slot) != 0) return at;
		return null;
	}

	/** The kind of the landing {@code ins} carries for latch {@code slot}: 1 jump, 2 call, 3 return; 0 if none. */
	private static int landingKind(Instruction ins, int slot) {
		for (String name : new String[] { "c_land1", "c_land2" })
			if (field(ins, name) != 0 && field(ins, name + "_t") == slot) return field(ins, name);
		return 0;
	}

	private static int field(Instruction ins, String name) {
		Register field = ins.getProgram().getRegister(name);
		BigInteger value = field == null ? null : ins.getValue(field, false);
		return value == null ? 0 : value.intValue();
	}

	/** True when {@code ins} is a latched branch: it records its predicate and target and transfers elsewhere. */
	public static boolean inert(Instruction ins) {
		Register field = ins.getProgram().getRegister("c_inert");
		BigInteger value = field == null ? null : ins.getValue(field, false);
		return value != null && value.signum() != 0;
	}

	/** True when a latched branch lands behind {@code ins}. */
	static boolean landing(Instruction ins) {
		for (String name : new String[] { "c_land1", "c_land2" }) {
			Register field = ins.getProgram().getRegister(name);
			BigInteger value = field == null ? null : ins.getValue(field, false);
			if (value != null && value.signum() != 0) return true;
		}
		return false;
	}

	static PcodeOp[] hardwarePcode(Instruction ins) {
		return hardware(ins).getPcode();
	}

	/** True when {@code writer}'s write to {@code register} is staged. */
	static boolean staged(Program program, Instruction writer, Varnode register) {
		Register defer = program.getRegister("c_defer");
		if (defer == null) return false;
		BigInteger on = writer.getValue(defer, false);
		int[] index = index(program, register);
		// An unset field reads as null: register 0 (A0) is then what it selects.
		BigInteger held = writer.getValue(program.getRegister("c_defer_reg"), false);
		BigInteger pair = writer.getValue(program.getRegister("c_defer_pair"), false);
		if (on == null || on.intValue() != 1 || index == null) return false;
		int reg = held == null ? 0 : held.intValue();
		boolean both = pair != null && pair.intValue() == 1;
		for (int i : index) if (i != reg && !(both && i == (reg ^ 1))) return false;
		return true;
	}

	/**
	 * The staging indexes a write covers: one whole A or B register (0-31, 32-63), or both halves
	 * of a register pair, even half first; null for anything else.
	 */
	private static int[] index(Program program, Varnode v) {
		if (v.getSize() == 8) {
			Register pair = program.getRegister(v.getAddress(), 8);
			if (pair == null) return null;
			int[] halves = new int[2];
			int n = 0;
			for (Register half : pair.getChildRegisters()) {
				Integer i = half.getMinimumByteSize() == 4 ? index(half) : null;
				if (i == null || n == 2) return null;
				halves[n++] = i;
			}
			if (n != 2 || (halves[0] ^ halves[1]) != 1) return null;
			return new int[] { Math.min(halves[0], halves[1]), Math.max(halves[0], halves[1]) };
		}
		Register r = v.getSize() == 4 ? program.getRegister(v.getAddress(), 4) : null;
		Integer i = r == null ? null : index(r);
		return i == null ? null : new int[] { i };
	}

	private static Integer index(Register r) {
		if (!r.getName().matches("[AB]([0-9]|[12][0-9]|3[01])")) return null;
		return (r.getName().charAt(0) == 'B' ? 32 : 0) + Integer.parseInt(r.getName().substring(1));
	}

	private static boolean transfer(Instruction ins) {
		var flow = C6000PacketStagingAnalyzer.flow(ins);
		return flow.isJump() || flow.isCall() || flow.isTerminal() || ins.getPrototype().hasDelaySlots();
	}

	/** One staged write: the member that writes, its register, and the member after which the result is committed. */
	private record Stage(Instruction writer, int[] registers, Instruction committer) {}

	private static int stage(Program program, Function function, TaskMonitor monitor) throws Exception {
		// The old reads of each writer's register, grouped by writer.
		Map<Address, List<C6000SamePacketHazardAnalyzer.OldRead>> byWriter = new LinkedHashMap<>();
		for (var read : C6000SamePacketHazardAnalyzer.oldReads(program, function, monitor))
			byWriter.computeIfAbsent(read.writer().getAddress(), k -> new ArrayList<>()).add(read);
		List<Stage> stages = new ArrayList<>();
		Map<Address, Integer> commits = new HashMap<>();
		for (var reads : byWriter.values()) {
			Instruction writer = reads.get(0).writer();
			int[] registers = index(program, reads.get(0).register());
			// One whole A or B register, or one pair, per writer; a transfer's own writes are not its peers' to read.
			if (registers == null || transfer(writer) ||
				reads.stream().anyMatch(r -> !r.register().equals(reads.get(0).register()))) continue;
			Instruction last = reads.get(reads.size() - 1).reader();
			// Two results at most are committed after one member; a pair takes both.
			if (commits.merge(last.getAddress(), registers.length, Integer::sum) > 2) {
				commits.merge(last.getAddress(), -registers.length, Integer::sum);
				continue;
			}
			stages.add(new Stage(writer, registers, last));
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
			writer.put("c_defer_reg", stage.registers()[0]);
			if (stage.registers().length == 2) writer.put("c_defer_pair", 1);
			var committer = wanted.computeIfAbsent(stage.committer().getAddress(), k -> new HashMap<>());
			// A branch commits after its own reads, inside its delay table; anything else in the wrapper.
			if (!transfer(stage.committer())) committer.put("c_staged", 1);
			for (int register : stage.registers()) {
				String slot = committer.containsKey("c_cm1") ? "c_cm2" : "c_cm1";
				committer.put(slot, 1);
				committer.put(slot + "_reg", register);
			}
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
				// The wrapper also carries a latched branch's landing behind a plain instruction.
				if (name.equals("c_staged") && landing(ins) && !inert(ins)) want = 1;
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
		Instruction writer = program.getListing().getInstructionAt(stage.writer().getAddress());
		Instruction committer = program.getListing().getInstructionAt(stage.committer().getAddress());
		if (writer == null || committer == null) return false;
		for (int register : stage.registers()) {
			String name = (register >= 32 ? "B" : "A") + (register & 31);
			Register real = program.getRegister(name), held = program.getRegister("C6000_NEW_" + name);
			if (real == null || held == null) return false;
			boolean holds = false, commits = false;
			for (PcodeOp op : writer.getPcode()) holds |= writes(op, held);
			for (PcodeOp op : committer.getPcode())
				commits |= op.getOpcode() == PcodeOp.COPY && writes(op, real) && op.getInput(0).isRegister() &&
					op.getInput(0).getAddress().equals(held.getAddress());
			if (!holds || !commits) return false;
		}
		return true;
	}

	private static boolean writes(PcodeOp op, Register register) {
		Varnode out = op.getOutput();
		return out != null && out.isRegister() && out.getAddress().equals(register.getAddress()) && out.getSize() == register.getMinimumByteSize();
	}
}
