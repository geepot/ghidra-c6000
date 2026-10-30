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

import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Use terminal p-code for unpredicated register branches after ordinary code
 * discovery. Initial conservative flow keeps delay instructions discoverable;
 * the late form supplies terminal flow and the packet-aware pass materializes
 * proven byte windows through SLEIGH native delay slots.
 */
public class C6000RegisterBranchAnalyzer extends AbstractAnalyzer {
	public C6000RegisterBranchAnalyzer() {
		super("C6000 Register Branch Flow",
			"Corrects unconditional register branches after code discovery",
			AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		// The Decompiler Switch analyzer runs at CODE_ANALYSIS.  Correct
		// pre-disassembled register branches before it decompiles the sweep;
		// otherwise a tiny branch thunk can look like a huge fall-through
		// function and exhaust its timeout or heap.
		setPriority(AnalysisPriority.CODE_ANALYSIS.before());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C6000PacketContext.isC6000(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		Listing listing = program.getListing();
		Register mode = program.getRegister("c_branch_terminal");
		List<Address> candidates = new ArrayList<>();
		// Calls discovered during later analysis can materialize branch thunks
		// outside the current added set. Revisit every decoded branch here so
		// those thunks receive terminal p-code before decompilation.
		InstructionIterator instructions = listing.getInstructions(true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();
			String name = instruction.getMnemonicString();
			FlowOverride override = instruction.getFlowOverride();
			if (!(name.equals("B.S2") || name.equals("BNOP.S2")) ||
				instruction.getNumOperands() == 0 ||
				!instruction.getDefaultOperandRepresentation(0).matches("[AB]([0-9]|[12][0-9]|3[01])") ||
				!((override == FlowOverride.NONE && instruction.getFlowType().isComputed()) ||
					(override == FlowOverride.RETURN &&
						"B3".equals(instruction.getDefaultOperandRepresentation(0)))) ||
				BigInteger.ONE.equals(program.getProgramContext().getValue(mode,
					instruction.getAddress(), false))) continue;
			candidates.add(instruction.getAddress());
		}

		Disassembler disassembler = Disassembler.getDisassembler(program, monitor, null);
		ReferenceManager references = program.getReferenceManager();
		List<Address> terminal = new ArrayList<>();
		for (Address at : candidates) {
			monitor.checkCancelled();
			Instruction old = listing.getInstructionAt(at);
			if (old == null || (old.getFlowOverride() != FlowOverride.NONE &&
				old.getFlowOverride() != FlowOverride.RETURN)) continue;
			boolean isReturn = old.getFlowOverride() == FlowOverride.RETURN;
			Reference[] saved = old.getReferencesFrom();
			Address end = old.getMaxAddress();
			listing.clearCodeUnits(at, end, false);
			try {
				program.getProgramContext().setValue(mode, at, at, BigInteger.ONE);
			}
			catch (ContextChangeException e) {
				log.appendException(e);
				disassembler.disassemble(at, new AddressSet(at, end), false);
				Instruction fallback = listing.getInstructionAt(at);
				if (fallback != null && isReturn) {
					fallback.setFlowOverride(FlowOverride.RETURN);
				}
				restoreReferences(references, at, saved, false);
				continue;
			}
			disassembler.disassemble(at, new AddressSet(at, end), false);
			Instruction replacement = listing.getInstructionAt(at);
			if (replacement != null && isReturn) replacement.setFlowOverride(FlowOverride.RETURN);
			if (replacement == null || replacement.getFlowType().hasFallthrough() ||
				(isReturn ? !replacement.getFlowType().isTerminal() :
					!replacement.getFlowType().isJump())) {
				log.appendMsg(getName(), "could not correct branch at " + at);
				restoreReferences(references, at, saved, false);
				continue;
			}
			restoreReferences(references, at, saved, true, isReturn);
			terminal.add(at);
		}
		if (!terminal.isEmpty()) log.appendMsg(getName(), "corrected " + terminal.size() + " branch(es)");
		try {
			C6000DelaySlots.recover(program, monitor, log);
		}
		catch (CancelledException e) { throw e; }
		catch (Exception e) {
			throw new IllegalStateException("C6000 delay-window recovery failed", e);
		}
		clearTails(program, terminal, monitor);
		C6000JumpTableAnalyzer.repairDetachedOverrides(program, monitor, log);
		return true;
	}

	/**
	 * The first decode gave each corrected branch a fall-through, so code past
	 * its delay window was disassembled although execution continues at the
	 * target (SPRUFE8B 4.2.6, Table 4-11). Clear that flow; code reached from
	 * elsewhere, functions and entry points are kept.
	 */
	private static void clearTails(Program program, List<Address> branches, TaskMonitor monitor)
			throws CancelledException {
		Listing listing = program.getListing();
		AddressSet tails = new AddressSet();
		for (Address at : branches) {
			Instruction branch = listing.getInstructionAt(at);
			Address end = branch == null ? null : C6000DelaySlots.windowEnd(program, branch, monitor);
			Address past = end == null ? null : end.next();
			if (past != null && listing.getInstructionAt(past) != null) tails.add(past);
		}
		if (!tails.isEmpty()) new ClearFlowAndRepairCmd(tails, false, false, true).applyTo(program, monitor);
	}

	private static void restoreReferences(ReferenceManager manager, Address from,
			Reference[] saved, boolean terminal) {
		restoreReferences(manager, from, saved, terminal, false);
	}

	private static void restoreReferences(ReferenceManager manager, Address from,
			Reference[] saved, boolean terminal, boolean isReturn) {
		for (Reference reference : saved) {
			if (reference.isMemoryReference()) {
				if (isReturn && reference.getReferenceType().isFlow()) continue;
				RefType type = terminal && reference.getReferenceType().isFlow()
					? RefType.COMPUTED_JUMP : reference.getReferenceType();
				manager.addMemoryReference(from, reference.getToAddress(), type,
					reference.getSource(), reference.getOperandIndex());
			}
		}
	}
}
