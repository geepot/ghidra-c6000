// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Regression checks for compact operands and execute-packet branch flow.

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;

public class C6000BugReport2Test extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String mode = getScriptArgs().length == 0 ? "stage1" : getScriptArgs()[0];
		if (mode.equals("stage1")) {
			check(0x11802624L, "B.S2 IRP");
			if (currentProgram.getListing().getInstructionAt(toAddr(0x11802624L))
				.getFlowType().hasFallthrough()) {
				throw new AssertionError("B IRP must be terminal");
			}
			check(0x11802640L, "MV.L1 B4,A20");
			check(0x118026a2L, "MV.S2 A4,B8");
			check(0x118026aeL, "MV.S1 A8,A3");
			check(0x118026baL, "MV.L2 A8,B4");
			checkExisting(0x1180284aL, "_MVK.L1 0x1,A4");
			checkExisting(0x1180284eL, "_MVK.L1 0x3,A4");
			check(0x118028e4L, "CALLP.S2 0x118027ec,B3");
			check(0x11802b68L, "MV.L2 A4,B20");
			check(0x11802b8cL, "LDW.D2 *B4[0x0],B22");
			check(0x11805ca8L, "[!A2]MPYI.M1 0x7,A19,A21");
			check(0x118076b4L, "MPYI.M1 -0x10,A8,A10");
			for (long addr : new long[] {0x11802848L, 0x1180284cL}) {
				Instruction branch = currentProgram.getListing().getInstructionAt(toAddr(addr));
				if (branch == null || branch.getDelaySlotDepth() != 1) {
					throw new AssertionError("parallel BNOP delay slot missing at " + toAddr(addr));
				}
			}
		}
		else if (mode.equals("stage2")) {
			check(0xc0003a6eL, "CMPEQ.L1 0x1,A0,A1");
			check(0xc0005946L, "CMPEQ.L2 0x1,B5,B1");
			check(0xc0009274L, "MV.L1 B16,A20");
			check(0xc000968aL, "STW.D1 B16,*A6[0x0]");
			check(0xc000a306L, "CMPLT.L1 0x0,A0,A1");
			check(0xc0013fe6L, "CMPLT.L2 0x0,B5,B1");
		}
		else throw new IllegalArgumentException("unknown mode: " + mode);
		println("C6000_BUGREPORT2_OK " + mode);
	}

	private void check(long addr, String expected) throws Exception {
		if (currentProgram.getListing().getInstructionAt(toAddr(addr)) == null) {
			currentProgram.getListing().clearCodeUnits(toAddr(addr), toAddr(addr).add(3), false);
			DisassembleCommand command = new DisassembleCommand(toAddr(addr),
				new AddressSet(toAddr(addr), toAddr(addr).add(3)), false);
			command.applyTo(currentProgram, monitor);
		}
		checkExisting(addr, expected);
	}

	private void checkExisting(long addr, String expected) {
		Instruction instruction = currentProgram.getListing().getInstructionAt(toAddr(addr));
		String actual = instruction == null ? "<missing>" : instruction.toString();
		if (!expected.equals(actual)) {
			throw new AssertionError(toAddr(addr) + " expected " + expected + " got " + actual);
		}
	}
}
