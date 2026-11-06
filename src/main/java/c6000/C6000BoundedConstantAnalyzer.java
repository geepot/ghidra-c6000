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

import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.lang.Register;
import ghidra.program.model.data.DataType;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Limit each symbolic-propagation walk while retaining Ghidra's reference
 * recovery. The generic analyzer can clone a rapidly growing saved-flow
 * state across C6000 firmware loops and exhaust even a large Java heap.
 */
public class C6000BoundedConstantAnalyzer extends ConstantPropagationAnalyzer {
	private static final long MAX_WINDOW_BYTES = 512;

	public C6000BoundedConstantAnalyzer() {
		super("C6000");
	}

	@Override
	public AddressSetView flowConstants(Program program, Address start, AddressSetView flowSet,
			SymbolicPropogator propagator, TaskMonitor monitor) throws CancelledException {
		long end = Math.min(start.getAddressSpace().getMaxAddress().getOffset(),
			start.getOffset() + MAX_WINDOW_BYTES - 1);
		AddressSet bounded = new AddressSet(flowSet).intersectRange(start,
			start.getNewAddress(end));
		ConstantPropagationContextEvaluator evaluator =
			new ConstantPropagationContextEvaluator(monitor) {
				@Override
				public boolean evaluateReference(VarnodeContext context, Instruction instruction,
						int pcodeop, Address target, int size, DataType type, RefType referenceType) {
					Long exact = referenceType.isComputed() && referenceType.isFlow()
						? adjacentConstantTarget(instruction) : null;
					if (exact != null && target.getOffset() != exact) return false;
					// A register call's target is the call analyzer's E1 proof, which adds its reference.
					if (exact == null && referenceType.isComputed() && referenceType.isCall() &&
						instruction.getRegister(0) != null) return false;
					return super.evaluateReference(context, instruction, pcodeop, target, size,
						type, referenceType);
				}
			};
		evaluator.setTrustWritableMemory(trustWriteMemOption)
			.setMinSpeculativeOffset(minSpeculativeRefAddress)
			.setMaxSpeculativeOffset(maxSpeculativeRefAddress)
			.setMinStoreLoadOffset(minStoreLoadRefAddress)
			.setCreateComplexDataFromPointers(createComplexDataFromPointers);
		return propagator.flowConstants(start, bounded, evaluator, true, monitor);
	}

	/**
	 * Prove only the adjacent, unpredicated MVK/MVKH/register-branch idiom.
	 * SPRUFE8B MVK/MVKL (pp. 381, 385), MVKH (pp. 383-384), and Table 4-11:
	 * MVK sign-extends; MVKH replaces the high half; the branch reads at E1,
	 * before its delay slots. Do not treat writes in the branch's execute
	 * packet, predicated writes, or a value crossing another entry as proof.
	 */
	static Long adjacentConstantTarget(Instruction branch) {
		String mnemonic = branch.getMnemonicString();
		if (!(mnemonic.equals("B.S2") || mnemonic.equals("BNOP.S2"))) return null;
		Register source = branch.getRegister(0);
		if (source == null) return null;
		Instruction high = previousAdjacent(branch);
		Instruction low = high == null ? null : previousAdjacent(high);
		if (low == null || low.getLength() != 4 || high.getLength() != 4 ||
			!(low.getMnemonicString().equals("MVK.S1") ||
				low.getMnemonicString().equals("MVK.S2") ||
				low.getMnemonicString().equals("MVKL.S1") ||
				low.getMnemonicString().equals("MVKL.S2")) ||
			!(high.getMnemonicString().equals("MVKH.S1") ||
				high.getMnemonicString().equals("MVKH.S2")) ||
			!source.equals(low.getRegister(1)) || !source.equals(high.getRegister(1))) return null;
		Program program = branch.getProgram();
		if (program.getSymbolTable().isExternalEntryPoint(high.getAddress()) ||
			program.getSymbolTable().isExternalEntryPoint(branch.getAddress()) ||
			program.getFunctionManager().getFunctionAt(high.getAddress()) != null ||
			program.getFunctionManager().getFunctionAt(branch.getAddress()) != null ||
			hasFlowEntry(high) || hasFlowEntry(branch)) return null;
		try {
			// A p-bit of one keeps the following operation in the same E1 cycle.
			if ((program.getMemory().getInt(low.getAddress()) & 1) != 0 ||
				(program.getMemory().getInt(high.getAddress()) & 1) != 0) return null;
		}
		catch (ghidra.program.model.mem.MemoryAccessException e) { return null; }
		Scalar l = low.getScalar(0), h = high.getScalar(0);
		if (l == null || h == null) return null;
		long target = ((h.getUnsignedValue() & 0xffffL) << 16) | (l.getUnsignedValue() & 0xffffL);
		// Register branches ignore low target bits according to the target's
		// fetch-packet form (SPRUFE8B B/BNOP register descriptions). Without
		// decoding that form, only an already word-aligned value is exact.
		return (target & 3) == 0 ? target : null;
	}

	private static Instruction previousAdjacent(Instruction instruction) {
		Instruction previous = instruction.getProgram().getListing()
			.getInstructionBefore(instruction.getAddress());
		if (previous == null || !previous.getMaxAddress().next().equals(instruction.getAddress())) return null;
		// A fetch header is metadata, not an execute packet or a register write.
		return previous.getMnemonicString().equals("CPKT") ? previousAdjacent(previous) : previous;
	}

	private static boolean hasFlowEntry(Instruction instruction) {
		var references = instruction.getProgram().getReferenceManager()
			.getReferencesTo(instruction.getAddress());
		while (references.hasNext()) {
			if (references.next().getReferenceType().isFlow()) return true;
		}
		return false;
	}
}
