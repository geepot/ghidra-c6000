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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Revisit return branches after decompiler switch analysis discovers new code.
 * The early analyzers must still run before switch analysis to keep branch
 * thunks from merging into large fall-through functions.
 */
public class C6000LateBranchAnalyzer extends AbstractAnalyzer {
	public C6000LateBranchAnalyzer() {
		super("C6000 Late Branch Flow",
			"Corrects return branches in code discovered during switch analysis",
			AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.CODE_ANALYSIS.after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C6000PacketContext.isC6000(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		AddressSet all = new AddressSet(program.getMinAddress(), program.getMaxAddress());
		new C6000ReturnAnalyzer().added(program, all, monitor, log);
		new C6000RegisterBranchAnalyzer().added(program, all, monitor, log);
		return true;
	}
}
