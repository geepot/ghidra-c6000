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

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
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
	private static final int LOW = 1, HIGH = 2, FULL = LOW | HIGH;

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
		InstructionIterator instructions = listing.getInstructions(set, true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction branch = instructions.next();
			String op = baseName(branch);
			if ((op.equals("B.S1") || op.equals("B.S2")) &&
				// Only unclassified branches: Ghidra's no-return analysis turns a
				// call into CALL_RETURN, and re-overriding it would loop forever.
				branch.getFlowOverride() == FlowOverride.NONE &&
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
			branch.setFlowOverride(FlowOverride.CALL);
			Address next = branch.getMaxAddress().next();
			if (branch.getFallThrough() == null) branch.setFallThrough(next);
			if (listing.getInstructionAt(next) == null) disassembler.disassemble(next, null, true);
			Function caller = listing.getFunctionContaining(at);
			if (caller != null) callers.add(caller);
			if (call.target() != null) {
				boolean known = false;
				for (Reference ref : branch.getReferencesFrom()) {
					if (!ref.getReferenceType().isFlow()) continue;
					if (ref.getToAddress().equals(call.target()) && ref.getReferenceType().isCall()) {
						known = true;
					}
					else if (ref.getReferenceType().isJump()) {
						program.getReferenceManager().delete(ref);
					}
				}
				if (!known) {
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
			recovered++;
		}
		// A body computed while the B was a jump stops at it or swallows the callee.
		for (Function caller : callers) {
			monitor.checkCancelled();
			CreateFunctionCmd.fixupFunctionBody(program, caller, monitor);
		}
		if (recovered > 0) log.appendMsg(getName(), "recovered " + recovered + " delayed call(s)");
		return true;
	}

	/** A recognised call; {@code target} is set for a register branch with a known value. */
	private record Call(Address target) {
	}

	/**
	 * Walks the instructions around a branch, decoding bytes that the
	 * listing does not yet hold, and tracks MVK/MVKH/ADDKPC constants.
	 */
	private static final class Walker {
		private final Program program;
		private final Listing listing;
		private final PseudoDisassembler pseudo;

		Walker(Program program) {
			this.program = program;
			this.listing = program.getListing();
			this.pseudo = new PseudoDisassembler(program);
		}

		Call recognize(Instruction branch) {
			Map<Register, long[]> regs = new HashMap<>();
			// ponytail: straight-line look-back, no flow merge; a far-call
			// constant is almost always loaded a few packets before the B.
			List<Instruction> before = new ArrayList<>();
			Instruction back = branch;
			for (int i = 0; i < LOOK_BACK; i++) {
				Instruction prior = listing.getInstructionBefore(back.getMinAddress());
				if (prior == null || !adjacent(prior, back)) break;
				before.add(0, prior);
				back = prior;
			}
			for (Instruction insn : before) {
				if (insn.getFlowType().isJump() || insn.getFlowType().isCall() ||
					insn.getFlowType().isTerminal()) {
					regs.remove(program.getRegister("B3"));
				}
				track(insn, regs);
			}

			Register source = branch.getRegister(0);
			Long target = null;
			if (source != null) {
				long[] value = regs.get(source);
				if (value != null && value[1] == FULL) target = value[0];
			}

			// The rest of the branch's execute packet, then five delay cycles.
			Register b3 = program.getRegister("B3");
			boolean wroteB3 = false;
			Instruction current = branch;
			int cycles = 0;
			int seen = 0;
			boolean branchPacket = true;
			try {
				while (cycles < DELAY_CYCLES) {
					int packetCycles = 1;
					do {
						if (branchPacket && !parallelWithNext(current)) break;
						Instruction next = next(current);
						if (next == null || ++seen > MAX_WINDOW ||
							next.getFlowType().isJump() || next.getFlowType().isCall() ||
							next.getFlowType().isTerminal()) return null;
						if (track(next, regs) == b3) wroteB3 = true;
						packetCycles = Math.max(packetCycles, 1 + extraCycles(next));
						current = next;
					} while (parallelWithNext(current));
					if (!branchPacket) cycles += packetCycles;
					branchPacket = false;
				}
			}
			catch (MemoryAccessException e) {
				return null;
			}
			long[] ret = regs.get(b3);
			if (!wroteB3 || ret == null || ret[1] != FULL) return null;
			long branchAt = branch.getMinAddress().getOffset();
			long windowEnd = current.getMaxAddress().getOffset() + 1;
			if (ret[0] < branchAt + 4 || ret[0] > windowEnd + 8) return null;
			Address callee = target == null ? null :
				branch.getMinAddress().getNewAddress(target & 0xffffffffL);
			if (callee != null && !program.getMemory().contains(callee)) callee = null;
			return new Call(callee);
		}

		/** Apply one instruction to the constant map; returns the constant register written. */
		private Register track(Instruction insn, Map<Register, long[]> regs) {
			String op = baseName(insn);
			int dot = op.indexOf('.');
			String name = dot < 0 ? op : op.substring(0, dot);
			Register dst = insn.getNumOperands() >= 2 ? insn.getRegister(1) : null;
			Long value = insn.getNumOperands() >= 2 ? constant(insn) : null;
			long[] old = dst == null ? null : regs.get(dst);
			for (Object written : insn.getResultObjects()) {
				if (written instanceof Register r) regs.remove(r);
			}
			if (dst == null || value == null || insn.getLength() != 4) return null;
			long v = value;
			switch (name) {
				case "MVK", "MVKL" -> {
					if (!op.startsWith("MVK.S") && !op.startsWith("MVKL.S")) return null;
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
			if (listing.getDefinedDataContaining(at) != null ||
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

	/** Cycles beyond the first that an instruction idles its execute packet. */
	private static int extraCycles(Instruction insn) {
		String op = baseName(insn);
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
