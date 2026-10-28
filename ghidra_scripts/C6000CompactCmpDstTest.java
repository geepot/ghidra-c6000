// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Execute compact-cmpdst.py's L2c/Lx3c/Lx1c and check dst is A0/A1 whatever RS says.
// Usage: C6000CompactCmpDstTest.java <cases.tsv>

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

public class C6000CompactCmpDstTest extends GhidraScript {
	private static final long BASE = 0x1000L;
	private static final long MASK32 = 0xffffffffL;
	private static final String[] REGS = { "A0", "A1", "A16", "A17" };
	private static final long[] INITIAL = { 0xdead, 0xdead, 5, 5 };

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
				String dst = fields[2];
				long expected = Long.parseUnsignedLong(fields[3], 16);
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
					for (int i = 0; i < REGS.length; i++) {
						emulator.writeRegister(REGS[i], INITIAL[i]);
					}
					Register context = currentProgram.getRegister("contextreg");
					BigInteger value = currentProgram.getProgramContext().getValue(context, address, false);
					if (value != null) {
						emulator.setContextRegister(context, value);
					}
					emulator.getEmulator().setExecuteAddress(offset);
					if (!emulator.step(monitor)) {
						throw new AssertionError(name + ": emulator: " + emulator.getLastError());
					}
					for (int i = 0; i < REGS.length; i++) {
						long want = REGS[i].equals(dst) ? expected : INITIAL[i];
						long got = emulator.readRegister(REGS[i]).longValue() & MASK32;
						if (got != want) {
							throw new AssertionError(name + ": " + insn + " left " + REGS[i] + "=0x" +
								Long.toHexString(got) + " expected 0x" + Long.toHexString(want));
						}
					}
				} finally {
					emulator.dispose();
				}
				checked++;
			}
		}
		println("C6000_COMPACT_CMPDST_OK cases=" + checked + " packets=" + packets);
	}
}
