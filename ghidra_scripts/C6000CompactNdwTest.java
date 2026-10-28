// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Execute compact-ndw.py's LDNDW/STNDW/LDDW/STDW and check the byte offset each accesses.
// Usage: C6000CompactNdwTest.java <cases.tsv>

import java.io.BufferedReader;
import java.io.FileReader;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import c6000.C6000PacketContext;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class C6000CompactNdwTest extends GhidraScript {
	private static final long BASE = 0x1000L;
	private static final long STORED = 0x8877665544332211L;

	private long value(byte[] bytes, boolean bigEndian) {
		long v = 0;
		for (int i = 0; i < 8; i++) {
			int b = bytes[bigEndian ? i : 7 - i] & 0xff;
			v = (v << 8) | b;
		}
		return v;
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 1) {
			throw new IllegalArgumentException("expected cases.tsv path");
		}
		int packets = C6000PacketContext.prime(currentProgram, monitor);
		boolean bigEndian = currentProgram.getLanguage().isBigEndian();
		List<String[]> rowsList = new ArrayList<>();
		try (BufferedReader rows = new BufferedReader(new FileReader(args[0]))) {
			String row;
			while ((row = rows.readLine()) != null) {
				rowsList.add(row.split("\\t"));
			}
		}
		long data = BASE + 32L * rowsList.size();
		int checked = 0;
		for (String[] fields : rowsList) {
			long offset = BASE + 32L * Integer.parseInt(fields[0]);
			Address address = toAddr(offset);
			String name = fields[1];
			boolean load = Integer.parseInt(fields[2]) != 0;
			long expectedOffset = Long.parseLong(fields[3]);
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
				emulator.writeRegister("A4", data);
				emulator.writeRegister("A2", 3);
				emulator.writeRegister("A0", STORED & 0xffffffffL);
				emulator.writeRegister("A1", STORED >>> 32);
				Register context = currentProgram.getRegister("contextreg");
				BigInteger contextValue = currentProgram.getProgramContext().getValue(context, address, false);
				if (contextValue != null) {
					emulator.setContextRegister(context, contextValue);
				}
				emulator.getEmulator().setExecuteAddress(offset);
				if (!emulator.step(monitor)) {
					throw new AssertionError(name + ": emulator: " + emulator.getLastError());
				}
				long actual;
				long expected;
				if (load) {
					actual = (emulator.readRegister("A1").longValue() << 32) |
						(emulator.readRegister("A0").longValue() & 0xffffffffL);
					expected = value(emulator.readMemory(toAddr(data + expectedOffset), 8), bigEndian);
				} else {
					actual = value(emulator.readMemory(toAddr(data + expectedOffset), 8), bigEndian);
					expected = STORED;
				}
				if (actual != expected) {
					throw new AssertionError(name + ": at A4+" + expectedOffset + " got 0x" +
						Long.toHexString(actual) + " expected 0x" + Long.toHexString(expected));
				}
			} finally {
				emulator.dispose();
			}
			checked++;
		}
		println("C6000_COMPACT_NDW_OK cases=" + checked + " packets=" + packets);
	}
}
