// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Decode compact-cross.py's instructions and check each mnemonic and unit, X included.
// Usage: C6000CompactCrossTest.java <cases.tsv>

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

import c6000.C6000PacketContext;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class C6000CompactCrossTest extends GhidraScript {
	private static final long BASE = 0x1000L;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 1) {
			throw new IllegalArgumentException("expected cases.tsv path");
		}
		int packets = C6000PacketContext.prime(currentProgram, monitor);
		List<String> failures = new ArrayList<>();
		int checked = 0;
		try (BufferedReader rows = new BufferedReader(new FileReader(args[0]))) {
			String row;
			while ((row = rows.readLine()) != null) {
				String[] fields = row.split("\\t");
				Address address = toAddr(BASE + 32L * Integer.parseInt(fields[0]));
				String expected = fields[1];
				Instruction insn = currentProgram.getListing().getInstructionAt(address);
				if (insn == null) {
					new DisassembleCommand(address, null, false).applyTo(currentProgram, monitor);
					insn = currentProgram.getListing().getInstructionAt(address);
				}
				if (insn == null || insn.getLength() != 2) {
					failures.add(expected + ": no compact instruction at " + address);
				}
				else if (!insn.toString().split("\\s+")[0].equals(expected)) {
					failures.add(expected + ": decoded as " + insn);
				}
				checked++;
			}
		}
		if (!failures.isEmpty()) {
			throw new AssertionError(failures.size() + "/" + checked + " wrong: " +
				String.join("; ", failures));
		}
		println("C6000_COMPACT_CROSS_OK cases=" + checked + " packets=" + packets);
	}
}
