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
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Recover the TI compiler's switch dispatch through a table of code pointers:
 *
 * <pre>
 *   CMPLTU  N, idx, p           ; guard: p = idx out of range
 *   [!p] MVK/MVKH table, t      ; table base
 *   ADD     t, scaled_idx, t
 *   [!p] LDW *+t(0), r
 *   B/BNOP  r                   ; dispatch; [p] B default is in the delay slots
 * </pre>
 *
 * Ghidra's decompiler finds the table but, with the guard and the predicated
 * loads spread over the delay slots, cannot bound it ("Too many branches").
 * This reads the N+1 entries the guard allows, stopping at the first that
 * is not a code address, adds them as computed-jump references, decodes them and writes a
 * jump-table override so the decompiler emits the switch.
 */
public class C6000JumpTableAnalyzer extends AbstractAnalyzer {
	private static final int MAX_ENTRIES = 256;

	public C6000JumpTableAnalyzer() {
		super("C6000 Jump Tables",
			"Recovers switch tables dispatched by LDW from an MVK/MVKH table and a register branch",
			AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		// The override lives in the function holding the dispatch, so run per
		// new function (including ones a script creates later); the late branch
		// pass calls recover() on new code to decode the cases in the meantime.
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C6000PacketContext.isC6000(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		AddressSet bodies = new AddressSet();
		for (Address entry : set.getAddresses(true)) {
			Function function = program.getFunctionManager().getFunctionAt(entry);
			if (function != null) bodies.add(function.getBody());
		}
		int recovered = recover(program, bodies, monitor, log);
		if (recovered > 0) log.appendMsg(getName(), "recovered " + recovered + " jump table(s)");
		return true;
	}

	/** Recover the dispatches in {@code region}; returns how many were found. */
	static int recover(Program program, AddressSetView region, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		AddressSetView set = region;
		Listing listing = program.getListing();
		List<Address> branches = new ArrayList<>();
		InstructionIterator instructions = listing.getInstructions(set, true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction insn = instructions.next();
			String op = C6000CallAnalyzer.baseName(insn);
			if ((op.equals("B.S2") || op.equals("BNOP.S2")) && insn.getRegister(0) != null &&
				!"B3".equals(insn.getDefaultOperandRepresentation(0)) &&
				insn.getFlowOverride() == FlowOverride.NONE && insn.getFlowType().isComputed()) {
				branches.add(insn.getAddress());
			}
		}

		C6000CallAnalyzer.Walker walker = new C6000CallAnalyzer.Walker(program);
		Disassembler disassembler = Disassembler.getDisassembler(program, monitor, null);
		Set<Function> bodies = new HashSet<>();
		int recovered = 0;
		for (Address at : branches) {
			monitor.checkCancelled();
			Instruction branch = listing.getInstructionAt(at);
			if (branch == null) continue;
			List<Address> targets = targets(program, walker, branch);
			if (targets.size() < 2) continue;
			boolean changed = false;
			for (Address target : targets) {
				if (!hasFlowTo(branch, target)) {
					program.getReferenceManager().addMemoryReference(at, target,
						RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0);
					changed = true;
				}
				if (listing.getInstructionAt(target) == null) {
					disassembler.disassemble(target, null, true);
					changed = true;
				}
			}
			Function function = listing.getFunctionContaining(at);
			// Rewriting an existing override or refixing an unchanged body would
			// retrigger function analysis on the same function forever.
			boolean wrote = false;
			if (function != null && !hasOverride(program, function, at)) {
				try {
					new JumpTable(at, new ArrayList<>(targets), true, 0).writeOverride(function);
					wrote = true;
				}
				catch (InvalidInputException e) {
					log.appendMsg("C6000 Jump Tables",
						"no switch override at " + at + ": " + e.getMessage());
				}
			}
			// Only new references or code can change the body.
			if (function != null && changed) bodies.add(function);
			if (changed || wrote) recovered++;
		}
		for (Function function : bodies) {
			monitor.checkCancelled();
			CreateFunctionCmd.fixupFunctionBody(program, function, monitor);
		}
		return recovered;
	}

	/** The table entries a register branch dispatches to, or an empty list. */
	static List<Address> targets(Program program, C6000CallAnalyzer.Walker walker,
			Instruction branch) {
		Map<Register, long[]> regs = new HashMap<>();
		Map<Register, Long> tableBase = new HashMap<>();	// holds table (+ index)
		Map<Register, Long> loaded = new HashMap<>();		// holds an entry of table
		Long bound = null;
		for (Instruction insn : walker.lookBack(branch)) {
			String op = C6000CallAnalyzer.baseName(insn);
			String name = op.contains(".") ? op.substring(0, op.indexOf('.')) : op;
			int n = insn.getNumOperands();
			Register dst = n > 0 ? insn.getRegister(n - 1) : null;
			Long base = null, entryOf = null;
			if ((name.equals("ADD") || name.equals("ADDAW")) && n == 3) {
				base = table(program, regs, tableBase, insn.getRegister(0));
				if (base == null) base = table(program, regs, tableBase, insn.getRegister(1));
			}
			else if (name.equals("LDW") && n == 2) {
				for (Object o : insn.getOpObjects(0)) {
					if (o instanceof Register r && entryOf == null) {
						entryOf = table(program, regs, tableBase, r);
					}
				}
			}
			else if ((name.equals("CMPLTU") || name.equals("CMPGTU")) && n == 3) {
				// The guard: CMPLTU K,idx (K < idx) or CMPGTU idx,K (idx > K)
				// flags an index past K; K may be an immediate or a constant register.
				Long limit = operandValue(insn, name.equals("CMPLTU") ? 0 : 1, regs);
				if (limit != null) bound = limit;
			}
			for (Object written : insn.getResultObjects()) {
				if (written instanceof Register r) {
					tableBase.remove(r);
					loaded.remove(r);
				}
			}
			walker.track(insn, regs);
			if (dst != null && base != null) tableBase.put(dst, base);
			if (dst != null && entryOf != null) loaded.put(dst, entryOf);
		}
		Long table = loaded.get(branch.getRegister(0));
		List<Address> targets = new ArrayList<>();
		// No guard, no table: reading until a non-code word runs into the next table.
		if (table == null || bound == null) return targets;
		Memory memory = program.getMemory();
		MemoryBlock code = memory.getBlock(branch.getAddress());
		long count = Math.min(bound + 1, MAX_ENTRIES);
		Address entry = branch.getAddress().getNewAddress(table);
		for (int i = 0; i < count; i++) {
			try {
				Address target = branch.getAddress().getNewAddress(
					memory.getInt(entry.add(4L * i)) & 0xffffffffL);
				// The guard bounds the table; a word that is not an even address
				// in the dispatching block ends it early.
				if (!code.contains(target) || (target.getOffset() & 1) != 0) break;
				targets.add(target);
			}
			catch (MemoryAccessException | ghidra.program.model.address.AddressOutOfBoundsException e) {
				break;
			}
		}
		return targets;
	}

	private static Long operandValue(Instruction insn, int index, Map<Register, long[]> regs) {
		Scalar scalar = insn.getScalar(index);
		if (scalar != null) return scalar.getUnsignedValue();
		long[] value = regs.get(insn.getRegister(index));
		return value != null && value[1] == C6000CallAnalyzer.FULL ? value[0] & 0xffffffffL : null;
	}

	/** Table address held by a register: an in-image constant, or table + index. */
	private static Long table(Program program, Map<Register, long[]> regs,
			Map<Register, Long> tableBase, Register r) {
		if (r == null) return null;
		Long base = tableBase.get(r);
		if (base != null) return base;
		long[] value = regs.get(r);
		if (value == null || value[1] != C6000CallAnalyzer.FULL) return null;
		long address = value[0] & 0xffffffffL;
		try {
			if ((address & 3) == 0 &&
				program.getMemory().contains(program.getAddressFactory()
					.getDefaultAddressSpace().getAddress(address))) {
				return address;
			}
		}
		catch (ghidra.program.model.address.AddressOutOfBoundsException e) {
			return null;
		}
		return null;
	}

	/** True when {@code function} already carries a switch override for the branch at {@code at}. */
	private static boolean hasOverride(Program program, Function function, Address at) {
		for (Symbol symbol : program.getSymbolTable().getSymbols(at)) {
			Namespace parent = symbol.getParentNamespace();
			if (symbol.getName().equals("switch") && parent != null &&
				parent.getParentNamespace() != null &&
				parent.getParentNamespace().getID() == function.getID()) return true;
		}
		return false;
	}

	private static boolean hasFlowTo(Instruction branch, Address target) {
		for (Reference ref : branch.getReferencesFrom()) {
			if (ref.getReferenceType().isFlow() && ref.getToAddress().equals(target)) return true;
		}
		return false;
	}
}
