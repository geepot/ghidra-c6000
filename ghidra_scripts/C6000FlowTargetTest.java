// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Verify that direct branch and call targets enter the program address space.
// Usage: C6000FlowTargetTest.java <cases.tsv>

import java.io.BufferedReader;
import java.io.FileReader;

import c6000.C6000PacketContext;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class C6000FlowTargetTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 1) {
			throw new IllegalArgumentException("expected cases.tsv path");
		}
		C6000PacketContext.prime(currentProgram, monitor);
		int checked = 0;
		try (BufferedReader rows = new BufferedReader(new FileReader(args[0]))) {
			String row;
			while ((row = rows.readLine()) != null) {
				String[] fields = row.split("\\t");
				Address address = toAddr(Long.parseUnsignedLong(fields[0], 16));
				Address target = toAddr(Long.parseUnsignedLong(fields[2], 16));
				new DisassembleCommand(address, null, false).applyTo(currentProgram, monitor);
				Instruction instruction = currentProgram.getListing().getInstructionAt(address);
				if (instruction == null || !instruction.getMnemonicString().endsWith(fields[1])) {
					throw new AssertionError("decode at " + address + ": " + instruction +
						" mnemonic=" + (instruction == null ? "null" : instruction.getMnemonicString()) +
						" expected=" + fields[1]);
				}
				Address[] flows = instruction.getFlows();
				if (flows.length != 1 || !flows[0].equals(target)) {
					throw new AssertionError("flow at " + address + ": " +
						java.util.Arrays.toString(flows) + " expected " + target);
				}
				String kind = fields[3];
				boolean correct = switch (kind) {
					case "call" -> instruction.getFlowType().isCall();
					case "conditional" -> instruction.getFlowType().isConditional() &&
						instruction.getFlowType().isJump();
					case "jump" -> instruction.getFlowType().isJump() &&
						!instruction.getFlowType().isConditional();
					default -> throw new IllegalArgumentException("unknown flow kind " + kind);
				};
				if (!correct) {
					throw new AssertionError("flow type at " + address + ": " +
						instruction.getFlowType() + " expected " + kind);
				}
				checked++;
			}
		}
		println("C6000_FLOW_TARGET_OK cases=" + checked);
	}
}
