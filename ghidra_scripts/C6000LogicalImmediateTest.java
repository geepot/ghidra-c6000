// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Execute operand-source cases from logical-immediate.py or bitfield-local.py
// at base 0x1000.
// Usage: C6000LogicalImmediateTest.java <cases.tsv>

import java.io.BufferedReader;
import java.io.FileReader;
import java.math.BigInteger;

import c6000.C6000PacketContext;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;

public class C6000LogicalImmediateTest extends GhidraScript {
	private static final long BASE = 0x1000L;
	private static final long MASK32 = 0xffffffffL;

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
				long offset = BASE + 32L * Integer.parseInt(fields[0]);
				Address address = toAddr(offset);
				new DisassembleCommand(address, null, false).applyTo(currentProgram, monitor);
				Instruction instruction = currentProgram.getListing().getInstructionAt(address);
				if (instruction == null || instruction.getLength() != 4 ||
					!instruction.getMnemonicString().equals(fields[1])) {
					throw new AssertionError("wrong decode at " + address + ": " + instruction);
				}
				EmulatorHelper emulator = new EmulatorHelper(currentProgram);
				try {
					emulator.writeRegister(fields[2], Long.parseUnsignedLong(fields[5], 16));
					emulator.writeRegister(fields[3], 0);
					// The register that a misdecoded operand would read must differ.
					emulator.writeRegister(fields[4], 0xCAFEBABEL);
					Register context = currentProgram.getRegister("contextreg");
					BigInteger value = currentProgram.getProgramContext().getValue(context, address, false);
					if (value != null) {
						emulator.setContextRegister(context, value);
					}
					emulator.getEmulator().setExecuteAddress(offset);
					if (!emulator.step(monitor)) {
						throw new AssertionError("emulator: " + emulator.getLastError());
					}
					long actual = emulator.readRegister(fields[3]).longValue() & MASK32;
					long expected = Long.parseUnsignedLong(fields[6], 16);
					if (actual != expected) {
						throw new AssertionError(fields[1] + " at " + address + " result=0x" +
							Long.toHexString(actual) + " expected=0x" + Long.toHexString(expected));
					}
				} finally {
					emulator.dispose();
				}
				checked++;
			}
		}
		println("C6000_LOGICAL_IMMEDIATE_OK cases=" + checked);
	}
}
