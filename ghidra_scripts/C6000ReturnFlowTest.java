// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check ABI returns in an auto-analysis import.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class C6000ReturnFlowTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		int candidates = 0;
		int recovered = 0;
		int predicated = 0;
		int predicatedFallthrough = 0;
		int unpredicatedFallthrough = 0;
		InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			String name = instruction.getMnemonicString();
			if (!(name.endsWith("B.S1") || name.endsWith("B.S2") ||
				name.endsWith("BNOP.S1") || name.endsWith("BNOP.S2")) ||
				instruction.getNumOperands() == 0 ||
				!"B3".equals(instruction.getDefaultOperandRepresentation(0))) continue;
			candidates++;
			if (name.startsWith("[")) {
				predicated++;
				if (instruction.getFlowType().hasFallthrough()) predicatedFallthrough++;
			}
			else if (instruction.getFlowType().hasFallthrough()) unpredicatedFallthrough++;
			if (instruction.getFlowOverride() == FlowOverride.RETURN &&
				instruction.getFlowType().isTerminal()) recovered++;
		}
		if (candidates == 0 || recovered != candidates ||
			predicatedFallthrough != predicated || unpredicatedFallthrough != 0) {
			throw new AssertionError("return recovery " + recovered + "/" + candidates +
				", predicated fallthrough " + predicatedFallthrough + "/" + predicated +
				", unpredicated fallthrough " + unpredicatedFallthrough);
		}
		println("C6000_RETURN_FLOW_OK cases=" + recovered + " predicated=" + predicated +
			" predicatedFallthrough=" + predicatedFallthrough +
			" unpredicatedFallthrough=" + unpredicatedFallthrough);
	}
}
