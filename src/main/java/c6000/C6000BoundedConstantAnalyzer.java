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
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
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
		C6000CallAnalyzer.Walker walker = new C6000CallAnalyzer.Walker(program);
		ConstantPropagationContextEvaluator evaluator =
			new ConstantPropagationContextEvaluator(monitor) {
				@Override
				public Address evaluateConstant(VarnodeContext context, Instruction instruction,
						int pcodeop, Address constant, int size, DataType type, RefType referenceType) {
					// Ghidra tries the offset of an access from an unknown register as an address. An
					// offset from DP (B14, SPRUFE8B 3.9.3) is not one, even where code is loaded there.
					if ((referenceType.isRead() || referenceType.isWrite()) &&
						dpOffset(context, instruction, constant.getOffset())) return null;
					return super.evaluateConstant(context, instruction, pcodeop, constant, size, type, referenceType);
				}

				@Override
				public boolean evaluateReference(VarnodeContext context, Instruction instruction,
						int pcodeop, Address target, int size, DataType type, RefType referenceType) {
					// Where the look-back proves what the branch's register holds at E1, only that address
					// is its target: a write in its own execute packet, or one a known predicate skips,
					// has not happened yet (SPRUFE8B 3.5, Table 4-11). Register branches ignore low
					// target bits by the target's fetch-packet form, so only a word-aligned value is exact.
					// A latched branch transfers behind another instruction: only the target that branch
					// provably read as it issued is one, never a value its register holds in between.
					if (referenceType.isComputed() && referenceType.isFlow() && C6000PacketStagingAnalyzer.landing(instruction)) {
						var proven = walker.landingTargets(instruction);
						if (proven == null || !proven.contains(target.getOffset()) || (target.getOffset() & 3) != 0) return false;
						return super.evaluateReference(context, instruction, pcodeop, target, size, type, referenceType);
					}
					Long exact = referenceType.isComputed() && referenceType.isFlow()
						? walker.issueTarget(instruction) : null;
					if (exact != null && (exact & 3) != 0) exact = null;
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

	/** True when {@code instruction}, or its delay slots, access memory {@code offset} bytes from a DP whose value is unknown. */
	private static boolean dpOffset(VarnodeContext context, Instruction instruction, long offset) {
		for (PcodeOp op : instruction.getPcode(true)) {
			if (op.getOpcode() != PcodeOp.LOAD && op.getOpcode() != PcodeOp.STORE) continue;
			Varnode at = context.getValue(op.getInput(1), true, null);
			if (at != null && at.getOffset() == offset && context.isSymbolicSpace(at.getSpace()) &&
				at.getAddress().getAddressSpace().getName().equals("B14")) return true;
		}
		return false;
	}
}
