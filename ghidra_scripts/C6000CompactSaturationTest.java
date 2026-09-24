// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Execute compact saturating instructions from compact-saturation.py's raw
// fetch packets.  Usage: C6000CompactSaturationTest.java <cases.tsv>

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
import ghidra.program.model.pcode.PcodeOp;

public class C6000CompactSaturationTest extends GhidraScript {
	private static final long BASE = 0x1000L;
	private static final long MASK32 = 0xffffffffL;

	private static long hex(String value) {
		return Long.parseUnsignedLong(value, 16);
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 1) {
			throw new IllegalArgumentException("expected cases.tsv path");
		}
		int packets = C6000PacketContext.prime(currentProgram, monitor);
		int checked = 0;
		try (BufferedReader rows = new BufferedReader(new FileReader(args[0]))) {
			String row;
			while ((row = rows.readLine()) != null) {
				String[] fields = row.split("\\t");
				long offset = BASE + 32L * Integer.parseInt(fields[0]);
				Address address = toAddr(offset);
				String name = fields[1];
				Instruction insn = currentProgram.getListing().getInstructionAt(address);
				if (insn == null) {
					new DisassembleCommand(address, null, false).applyTo(currentProgram, monitor);
					insn = currentProgram.getListing().getInstructionAt(address);
				}
				if (insn == null || insn.getLength() != 2) {
					throw new AssertionError(name + ": no compact instruction at " + address);
				}
				String expectedMnemonic = name.split("-")[0];
				if (!insn.getMnemonicString().startsWith(expectedMnemonic + ".")) {
					throw new AssertionError(name + ": decoded as " + insn);
				}
				for (PcodeOp op : insn.getPcode()) {
					if (op.getOpcode() == PcodeOp.CALLOTHER) {
						throw new AssertionError(name + ": unimplemented p-code: " + op);
					}
				}
				EmulatorHelper emulator = new EmulatorHelper(currentProgram);
				try {
					emulator.writeRegister("A1", hex(fields[2]));
					emulator.writeRegister("A2", hex(fields[3]));
					emulator.writeRegister("CSR", 0);
					Register context = currentProgram.getRegister("contextreg");
					BigInteger value = currentProgram.getProgramContext().getValue(context, address, false);
					if (value != null) {
						emulator.setContextRegister(context, value);
					}
					emulator.getEmulator().setExecuteAddress(offset);
					if (!emulator.step(monitor)) {
						throw new AssertionError(name + ": emulator: " + emulator.getLastError());
					}
					long result = emulator.readRegister(fields[4]).longValue() & MASK32;
					long expected = hex(fields[5]);
					long csr = emulator.readRegister("CSR").longValue() & 0x200;
					long expectedSat = Integer.parseInt(fields[6]) != 0 ? 0x200 : 0;
					if (result != expected || csr != expectedSat) {
						throw new AssertionError(name + ": result=0x" + Long.toHexString(result) +
							" CSR.SAT=0x" + Long.toHexString(csr) + " expected=0x" +
							Long.toHexString(expected) + "/0x" + Long.toHexString(expectedSat));
					}
				} finally {
					emulator.dispose();
				}
				checked++;
			}
		}
		println("C6000_COMPACT_SAT_OK cases=" + checked + " packets=" + packets);
	}
}
