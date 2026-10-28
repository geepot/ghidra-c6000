// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Execute compact-dstk.py's STW/LDW *B15[ucst5] and check operands and stack word.
// Usage: C6000CompactDstkTest.java <cases.tsv>

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

public class C6000CompactDstkTest extends GhidraScript {
	private static final long BASE = 0x1000L;
	private static final long STORED = 0xc0de0000L;

	private long word(byte[] bytes, boolean bigEndian) {
		long v = 0;
		for (int i = 0; i < 4; i++) {
			v = (v << 8) | (bytes[bigEndian ? i : 3 - i] & 0xff);
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
			String reg = fields[3];
			int ucst5 = Integer.parseInt(fields[4]);
			Instruction insn = currentProgram.getListing().getInstructionAt(address);
			if (insn == null) {
				new DisassembleCommand(address, null, false).applyTo(currentProgram, monitor);
				insn = currentProgram.getListing().getInstructionAt(address);
			}
			if (insn == null || insn.getLength() != 2) {
				throw new AssertionError(name + ": no compact instruction at " + address);
			}
			String mnemonic = (load ? "LDW" : "STW") + ".D2";
			if (!insn.getMnemonicString().equals(mnemonic) || insn.getNumOperands() != 2) {
				throw new AssertionError(name + ": decoded as [" + insn.getMnemonicString() +
					"] with " + insn.getNumOperands() + " operands");
			}
			String memory = "*B15[0x" + Integer.toHexString(ucst5) + "]";
			String expectedText = mnemonic + " " + (load ? memory + "," + reg : reg + "," + memory);
			if (!insn.toString().equals(expectedText)) {
				throw new AssertionError(name + ": " + insn + " expected " + expectedText);
			}
			EmulatorHelper emulator = new EmulatorHelper(currentProgram);
			try {
				emulator.writeRegister("B15", data);
				emulator.writeRegister(reg, STORED | ucst5);
				Register context = currentProgram.getRegister("contextreg");
				BigInteger contextValue = currentProgram.getProgramContext().getValue(context, address, false);
				if (contextValue != null) {
					emulator.setContextRegister(context, contextValue);
				}
				emulator.getEmulator().setExecuteAddress(offset);
				if (!emulator.step(monitor)) {
					throw new AssertionError(name + ": emulator: " + emulator.getLastError());
				}
				long slot = word(emulator.readMemory(toAddr(data + 4L * ucst5), 4), bigEndian);
				long actual = load ? emulator.readRegister(reg).longValue() & 0xffffffffL : slot;
				long expected = load ? 0x10000000L + ucst5 : STORED | ucst5;
				if (actual != expected) {
					throw new AssertionError(name + ": " + (load ? reg : "B15+" + 4 * ucst5) +
						" = 0x" + Long.toHexString(actual) + " expected 0x" + Long.toHexString(expected));
				}
			} finally {
				emulator.dispose();
			}
			checked++;
		}
		println("C6000_COMPACT_DSTK_OK cases=" + checked + " packets=" + packets);
	}
}
