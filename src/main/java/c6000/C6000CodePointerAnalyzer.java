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

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A function passed as a callback or stored in a pointer is only ever named by its address: code
 * loads the constant (MVKL/MVKH) and something else branches through it. Where an instruction of a
 * function refers to an address as a value, and that address is the start of code no function
 * owns and nothing falls into, this makes it a function. An address that is a return link or a
 * local label lies inside its function's body and is left alone, and so is data: an address with
 * no code yet must decode as a subroutine.
 */
public final class C6000CodePointerAnalyzer extends AbstractAnalyzer {
	public C6000CodePointerAnalyzer() {
		super("C6000 Code Pointers",
			"Creates a function where code takes the address of other code as a value, such as a callback",
			AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		// After the bodies settle: a return link or a local label is then inside its function.
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C6000PacketContext.isC6000(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		var analysis = AutoAnalysisManager.getAnalysisManager(program);
		var pseudo = new PseudoDisassembler(program);
		java.util.Set<Address> found = new java.util.HashSet<>();
		for (Function function : program.getFunctionManager().getFunctions(set, true)) {
			for (Instruction insn : program.getListing().getInstructions(function.getBody(), true)) {
				monitor.checkCancelled();
				for (Reference ref : insn.getReferencesFrom()) {
					RefType type = ref.getReferenceType();
					// A value, not a transfer and not memory this instruction reads or writes.
					if (type != RefType.PARAM && type != RefType.DATA) continue;
					Address target = ref.getToAddress();
					// B3 holds the return address (SPRAB89 3.3): an address put there is a return point, not a callee.
					if (java.util.Arrays.asList(C6000PacketStagingAnalyzer.hardware(insn).getResultObjects()).contains(program.getRegister("B3"))) continue;
					if (!target.isMemoryAddress() || !entry(program, pseudo, target)) continue;
					if (found.add(target)) analysis.createFunction(target, false);
				}
			}
		}
		if (!found.isEmpty()) Msg.info(this, getName() + "> " + found.size() + " function(s) from code pointers");
		return true;
	}

	/** True when {@code at} starts code that no function owns and nothing falls into. */
	private static boolean entry(Program program, PseudoDisassembler pseudo, Address at) {
		MemoryBlock block = program.getMemory().getBlock(at);
		if (block == null || !block.isInitialized() || !block.isExecute() || (at.getOffset() & 1) != 0) return false;
		var listing = program.getListing();
		if (program.getFunctionManager().getFunctionContaining(at) != null) return false;
		if (listing.getDefinedDataContaining(at) != null) return false;
		Instruction here = listing.getInstructionContaining(at);
		if (here == null) return pseudo.isValidSubroutine(at, true);
		if (!here.getMinAddress().equals(at) || here.isInDelaySlot()) return false;
		// A function does not start inside an execute packet, and nothing reads its code as data.
		Instruction before = listing.getInstructionBefore(at);
		try {
			if (before != null && before.getMaxAddress().next().equals(at) && C6000ExecutionPackets.parallelWithNext(program, before)) return false;
		}
		catch (ghidra.program.model.mem.MemoryAccessException e) {
			return false;
		}
		for (Reference ref : program.getReferenceManager().getReferencesTo(at))
			if (ref.getReferenceType().isRead() || ref.getReferenceType().isWrite()) return false;
		// Code of a function that jumps or falls in makes it part of that function; padding that no
		// function owns, decoded on the way past a return's delay slots, does not.
		var functions = program.getFunctionManager();
		for (Reference ref : program.getReferenceManager().getReferencesTo(at))
			if (ref.getReferenceType().isJump() && functions.getFunctionContaining(ref.getFromAddress()) != null) return false;
		Instruction prior = listing.getInstructionBefore(at);
		return prior == null || !at.equals(prior.getFallThrough()) || functions.getFunctionContaining(prior.getMinAddress()) == null;
	}
}
