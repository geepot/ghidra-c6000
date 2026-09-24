// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Execute SPINT/SPTRUNC cases from fp-int.py. Usage: <cases.tsv>.

import java.io.BufferedReader;
import java.io.FileReader;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class C6000FpConvertTest extends GhidraScript {
	private static final long BASE = 0x1000L;
	private static final long MASK32 = 0xffffffffL;

	private static long hex(String text) {
		return Long.parseUnsignedLong(text, 16);
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 1) {
			throw new IllegalArgumentException("expected cases.tsv path");
		}
		int checked = 0;
		try (BufferedReader rows = new BufferedReader(new FileReader(args[0]))) {
			String row;
			while ((row = rows.readLine()) != null) {
				String[] f = row.split("\t");
				int index = Integer.parseInt(f[0]);
				long offset = BASE + 32L * index;
				Address address = toAddr(offset);
				Instruction insn = currentProgram.getListing().getInstructionAt(address);
				if (insn == null) {
					new DisassembleCommand(address, null, false).applyTo(currentProgram, monitor);
					insn = currentProgram.getListing().getInstructionAt(address);
				}
				String side = f[3].equals("0") ? "1" : "2";
				if (insn == null || insn.getLength() != 4 ||
					!insn.getMnemonicString().equals(f[2] + ".L" + side)) {
					throw new AssertionError(f[1] + ": decoded as " + insn);
				}
				for (PcodeOp op : insn.getPcode()) {
					if (op.getOpcode() == PcodeOp.CALLOTHER) {
						throw new AssertionError(f[1] + ": placeholder " + op);
					}
				}
				EmulatorHelper emulator = new EmulatorHelper(currentProgram);
				try {
					String src = side.equals("1") ? "A1" : "B1";
					String dst = side.equals("1") ? "A2" : "B2";
					emulator.writeRegister(src, hex(f[4]));
					emulator.writeRegister("FADCR", hex(f[5]));
					emulator.getEmulator().setExecuteAddress(offset);
					if (!emulator.step(monitor)) {
						throw new AssertionError(f[1] + ": " + emulator.getLastError());
					}
					long result = emulator.readRegister(dst).longValue() & MASK32;
					long fadcr = emulator.readRegister("FADCR").longValue() & MASK32;
					if (result != hex(f[6]) || fadcr != hex(f[7])) {
						throw new AssertionError(f[1] + ": result/FADCR=0x" +
							Long.toHexString(result) + "/0x" + Long.toHexString(fadcr) +
							" expected=0x" + f[6] + "/0x" + f[7]);
					}
				} finally {
					emulator.dispose();
				}
				checked++;
			}
		}
		println("C6000_FP_INT_OK cases=" + checked);
	}
}
