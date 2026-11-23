// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check nonaligned transfers in a tests/fixtures/analysis-nonaligned.py image: the analysis
// languages lift each as one access of its whole width, the exact languages byte by byte, and
// with AMR zero every language moves the same bytes in the program's byte order.

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import java.io.BufferedReader;
import java.io.FileReader;
import java.math.BigInteger;
import java.util.Set;

public class C6000AnalysisNonalignedTest extends GhidraScript {
	private static final long BASE = 0x2001L;		// odd, so no transfer is aligned
	private static final long STORE_BASE = 0x2101L;

	@Override
	protected void run() throws Exception {
		String variant = currentProgram.getLanguage().getLanguageDescription().getVariant();
		boolean analysis = Set.of("analysis", "c67x-analysis").contains(variant);
		boolean big = currentProgram.getLanguage().isBigEndian();
		int checked = 0;
		try (BufferedReader rows = new BufferedReader(new FileReader(getScriptArgs()[0]))) {
			String row;
			while ((row = rows.readLine()) != null) {
				String[] f = row.split("\t");
				Address pc = toAddr(0x1000L + 32L * Integer.parseInt(f[0]));
				new DisassembleCommand(pc, null, false).applyTo(currentProgram, monitor);
				Instruction insn = getInstructionAt(pc);
				if (insn == null || !insn.getMnemonicString().equals(f[1])) {
					throw new AssertionError(f[0] + ": decoded as " + insn);
				}
				int width = Integer.parseInt(f[3]);
				boolean store = f[1].startsWith("ST");
				checkPcode(insn, store, width, analysis);
				checkValue(pc, insn, f[2], store, width, big);
				checked++;
			}
		}
		if (checked != 4) throw new AssertionError("checked " + checked + " transfers");
		println("C6000_ANALYSIS_NONALIGNED_OK");
	}

	/** One LOAD/STORE of the whole width in the analysis languages, one per byte otherwise. */
	private void checkPcode(Instruction insn, boolean store, int width, boolean analysis) {
		int whole = 0, bytes = 0;
		for (PcodeOp op : insn.getPcode()) {
			int size;
			if (!store && op.getOpcode() == PcodeOp.LOAD) size = op.getOutput().getSize();
			else if (store && op.getOpcode() == PcodeOp.STORE) size = op.getInput(2).getSize();
			else continue;
			if (size == width) whole++;
			else if (size == 1) bytes++;
			else throw new AssertionError(insn + ": a " + size + "-byte access");
		}
		boolean ok = analysis ? whole == 1 && bytes == 0 : whole == 0 && bytes == width;
		if (!ok) {
			throw new AssertionError(insn + ": " + whole + " whole and " + bytes +
				" byte accesses in the " + (analysis ? "analysis" : "exact") + " language");
		}
	}

	/** Run the transfer with AMR zero and compare with the bytes in program order. */
	private void checkValue(Address pc, Instruction insn, String register, boolean store,
			int width, boolean big) throws Exception {
		EmulatorHelper emulator = new EmulatorHelper(currentProgram);
		try {
			emulator.writeRegister("AMR", 0);
			byte[] bytes = new byte[width];
			for (int i = 0; i < width; i++) bytes[i] = (byte) (0x11 * (i + 1));
			BigInteger expected = BigInteger.ZERO;
			for (int i = 0; i < width; i++) {
				int shift = 8 * (big ? width - 1 - i : i);
				expected = expected.or(BigInteger.valueOf(bytes[i] & 0xff).shiftLeft(shift));
			}
			if (store) {
				emulator.writeRegister("A4", STORE_BASE);
				emulator.writeRegister(register, expected);
			}
			else {
				emulator.writeRegister("A4", BASE);
				emulator.writeMemory(toAddr(BASE), bytes);
			}
			emulator.getEmulator().setExecuteAddress(pc.getOffset());
			if (!emulator.step(monitor)) throw new AssertionError(insn + ": " + emulator.getLastError());
			if (store) {
				byte[] written = emulator.readMemory(toAddr(STORE_BASE), width);
				for (int i = 0; i < width; i++) {
					if (written[i] != bytes[i]) {
						throw new AssertionError(insn + ": byte " + i + " is " + written[i] +
							", expected " + bytes[i]);
					}
				}
				return;
			}
			// the loaded data lands in E5
			for (int k = 0; k < 6 && emulator.readRegister(register).signum() == 0; k++) {
				emulator.step(monitor);
			}
			BigInteger loaded = emulator.readRegister(register);
			if (!loaded.equals(expected)) {
				throw new AssertionError(insn + ": loaded " + loaded.toString(16) + ", expected " +
					expected.toString(16));
			}
		}
		finally {
			emulator.dispose();
		}
	}
}
