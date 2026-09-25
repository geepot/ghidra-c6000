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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.SymbolicPropogator;
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
		return super.flowConstants(program, start, bounded, propagator, monitor);
	}
}
