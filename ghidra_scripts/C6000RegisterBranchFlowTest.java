// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check terminal flow after the late register-branch analyzer.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import java.math.BigInteger;

public class C6000RegisterBranchFlowTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		int checked = 0;
		InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			String name = instruction.getMnemonicString();
			FlowOverride override = instruction.getFlowOverride();
			if (!(name.equals("B.S2") || name.equals("BNOP.S2")) ||
				(override != FlowOverride.NONE && override != FlowOverride.RETURN) ||
				instruction.getNumOperands() == 0 ||
				!instruction.getDefaultOperandRepresentation(0).matches("[AB]([0-9]|[12][0-9]|3[01])")) {
				continue;
			}
			if (!(override == FlowOverride.RETURN ? instruction.getFlowType().isTerminal() :
				instruction.getFlowType().isJump()) ||
				instruction.getFlowType().hasFallthrough() ||
				!BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(
					currentProgram.getRegister("c_branch_terminal"),
					instruction.getAddress(), false))) {
				throw new AssertionError("nonterminal register branch at " + instruction.getAddress());
			}
			checked++;
		}
		if (checked == 0) throw new AssertionError("no register branches checked");
		println("C6000_REGISTER_BRANCH_FLOW_OK cases=" + checked);
	}
}
