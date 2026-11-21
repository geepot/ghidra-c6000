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
				public boolean evaluateReference(VarnodeContext context, Instruction instruction,
						int pcodeop, Address target, int size, DataType type, RefType referenceType) {
					// Where the look-back proves what the branch's register holds at E1, only that address
					// is its target: a write in its own execute packet, or one a known predicate skips,
					// has not happened yet (SPRUFE8B 3.5, Table 4-11). Register branches ignore low
					// target bits by the target's fetch-packet form, so only a word-aligned value is exact.
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
}
