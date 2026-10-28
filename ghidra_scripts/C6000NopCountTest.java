// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Check nop-count.py's compact NOP counts and its NOP 4 loop length.
// Usage: C6000NopCountTest.java <cases.tsv>

import java.io.BufferedReader;
import java.io.FileReader;

import c6000.C6000LoopBuffer;
import c6000.C6000PacketContext;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;

public class C6000NopCountTest extends GhidraScript {
	private static final long BASE = 0x1000L;

	private Instruction decode(long offset) {
		Address address = toAddr(offset);
		Instruction insn = currentProgram.getListing().getInstructionAt(address);
		if (insn == null) {
			new DisassembleCommand(address, null, false).applyTo(currentProgram, monitor);
			insn = currentProgram.getListing().getInstructionAt(address);
		}
		return insn;
	}

	private void checkCount(String name, Instruction insn, long expected) {
		if (insn == null || !insn.getMnemonicString().equals("NOP")) {
			throw new AssertionError(name + ": decoded as " + insn);
		}
		Scalar count = insn.getScalar(0);
		if (count == null || count.getUnsignedValue() != expected) {
			throw new AssertionError(name + ": " + insn + " expected count " + expected);
		}
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 1) {
			throw new IllegalArgumentException("expected cases.tsv path");
		}
		int packets = C6000PacketContext.prime(currentProgram, monitor);
		for (long offset = 0; offset < 32; offset += 4) decode(BASE + offset);
		checkCount("NOP-32", decode(BASE + 8), 4);
		C6000LoopBuffer loop = C6000LoopBuffer.fromProgram(currentProgram,
			decode(BASE), decode(BASE + 0x10));
		if (loop.dynamicLength() != 7 || loop.sourcePackets() != 4) {
			throw new AssertionError("loop: dynamic length " + loop.dynamicLength() +
				" over " + loop.sourcePackets() + " packets, expected 7 over 4");
		}
		int checked = 0;
		try (BufferedReader rows = new BufferedReader(new FileReader(args[0]))) {
			String row;
			while ((row = rows.readLine()) != null) {
				String[] fields = row.split("\\t");
				Instruction insn = decode(BASE + 32L * Integer.parseInt(fields[0]));
				if (insn != null && insn.getLength() != 2) {
					throw new AssertionError(fields[1] + ": not compact: " + insn);
				}
				checkCount(fields[1], insn, Long.parseLong(fields[2]));
				checked++;
			}
		}
		println("C6000_NOP_COUNT_OK cases=" + checked + " loop=7 packets=" + packets);
	}
}
