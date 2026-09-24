// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Execute the 32-bit NORM and SUBU fixtures from long-arith.py.

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class C6000LongArithmeticTest extends GhidraScript {
	private static final long BASE = 0x1000L;
	private static final String[] NAMES = {
		"NORM", "NORM", "NORM", "NORM", "NORM", "SUBU", "SUBU"
	};
	private static final long[] A0 = {0, 0, 7, 0xffffffffL, 0, 0, 0};
	private static final long[] A1 = {
		0x02a3469fL, 0xfffff25aL, 0, 0xff, 0x80, 100, 0x325a
	};
	private static final long[] A2 = {0, 0, 0, 0, 0, 25, 0xffffff12L};
	private static final long[] EXPECTED = {5, 19, 36, 39, 0, 75, 0xff00003348L};

	@Override
	protected void run() throws Exception {
		for (int i = 0; i < NAMES.length; i++) {
			long offset = BASE + 32L * i;
			Address address = toAddr(offset);
			Instruction insn = currentProgram.getListing().getInstructionAt(address);
			if (insn == null) {
				new DisassembleCommand(address, null, false).applyTo(currentProgram, monitor);
				insn = currentProgram.getListing().getInstructionAt(address);
			}
			if (insn == null || insn.getLength() != 4 ||
				!insn.getMnemonicString().startsWith(NAMES[i] + ".")) {
				throw new AssertionError("fixture " + i + " decoded as " + insn);
			}
			if (i >= 2 && i <= 4 && !insn.toString().contains("A1:A0")) {
				throw new AssertionError("40-bit NORM source is not a pair: " + insn);
			}
			if (i >= 5 && !insn.toString().contains("A5:A4")) {
				throw new AssertionError("SUBU destination is not a pair: " + insn);
			}
			for (PcodeOp op : insn.getPcode()) {
				if (op.getOpcode() == PcodeOp.CALLOTHER) {
					throw new AssertionError("fixture " + i + " has placeholder p-code");
				}
			}
			EmulatorHelper emulator = new EmulatorHelper(currentProgram);
			try {
				emulator.writeRegister("A0", A0[i]);
				emulator.writeRegister("A1", A1[i]);
				emulator.writeRegister("A2", A2[i]);
				emulator.getEmulator().setExecuteAddress(offset);
				if (!emulator.step(monitor)) {
					throw new AssertionError("fixture " + i + ": " + emulator.getLastError());
				}
				String dst = i < 2 ? "A2" : (i < 5 ? "A3" : "A5_A4");
				long actual = emulator.readRegister(dst).longValue();
				if (actual != EXPECTED[i]) {
				for (PcodeOp op : insn.getPcode()) {
					println("C6000_LONG_ARITH_PCODE " + op);
				}
					throw new AssertionError("fixture " + i + ": " + dst + "=0x" +
						Long.toHexString(actual) + " expected=0x" +
						Long.toHexString(EXPECTED[i]));
				}
			} finally {
				emulator.dispose();
			}
		}
		println("C6000_LONG_ARITH_OK cases=" + NAMES.length);
	}
}
