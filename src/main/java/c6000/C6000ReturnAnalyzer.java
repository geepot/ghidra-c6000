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
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Classify branches through the C6000 ABI return register before switch analysis. */
public class C6000ReturnAnalyzer extends AbstractAnalyzer {
	public C6000ReturnAnalyzer() {
		super("C6000 Returns", "Classifies B/BNOP through B3 as returns",
			AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.CODE_ANALYSIS.before());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C6000PacketContext.isC6000(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		int recovered = 0;
		InstructionIterator instructions = program.getListing().getInstructions(set, true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();
			String name = instruction.getMnemonicString();
			if (!(name.endsWith("B.S1") || name.endsWith("B.S2") ||
				name.endsWith("BNOP.S1") || name.endsWith("BNOP.S2"))) continue;
			if (instruction.getFlowOverride() != FlowOverride.NONE ||
				!instruction.getFlowType().isComputed() || instruction.getNumOperands() == 0 ||
				!"B3".equals(instruction.getDefaultOperandRepresentation(0))) continue;
			instruction.setFlowOverride(FlowOverride.RETURN);
			recovered++;
		}
		if (recovered > 0) log.appendMsg(getName(), "recovered " + recovered + " return(s)");
		return true;
	}
}
