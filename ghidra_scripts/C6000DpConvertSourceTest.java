// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check DPINT/DPTRUNC/DPSP src1-field decoding from dp-convert-src1.py. Usage: <cases.tsv>.

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;

public class C6000DpConvertSourceTest extends GhidraScript {
	private static final long BASE = 0x1000L;
	private static final long MASK32 = 0xffffffffL;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 1) {
			throw new IllegalArgumentException("expected cases.tsv path");
		}
		int decoded = 0;
		int rejected = 0;
		List<String> failures = new ArrayList<>();
		try (BufferedReader rows = new BufferedReader(new FileReader(args[0]))) {
			String row;
			while ((row = rows.readLine()) != null) {
				String[] f = row.split("\t");
				Address address = toAddr(BASE + 32L * Integer.parseInt(f[0]));
				new DisassembleCommand(address, new AddressSet(address, address.add(3)), false)
					.applyTo(currentProgram, monitor);
				Instruction insn = currentProgram.getListing().getInstructionAt(address);
				int low = Integer.parseInt(f[5]);
				if (low < 0) {
					if (insn != null) {
						failures.add(f[1] + " (" + f[4] + "): expected undefined, decoded as " + insn);
					}
					rejected++;
					continue;
				}
				String side = f[3].equals("0") ? "1" : "2";
				String file = side.equals("1") ? "A" : "B";
				String pair = file + (low + 1) + ":" + file + low;
				if (insn == null || !insn.getMnemonicString().equals(f[2] + ".L" + side) ||
					!insn.toString().contains(pair + "," + file + "3")) {
					failures.add(f[1] + " (" + f[4] + "): expected " + pair + ", decoded as " + insn);
					continue;
				}
				EmulatorHelper emulator = new EmulatorHelper(currentProgram);
				try {
					for (int r = 0; r < 32; r++) {
						emulator.writeRegister("A" + r, 0);
						emulator.writeRegister("B" + r, 0);
					}
					long raw = Long.parseUnsignedLong(f[6], 16);
					emulator.writeRegister(file + low, raw & MASK32);
					emulator.writeRegister(file + (low + 1), raw >>> 32);
					emulator.getEmulator().setExecuteAddress(address.getOffset());
					if (!emulator.step(monitor)) {
						throw new AssertionError(f[1] + ": " + emulator.getLastError());
					}
					long result = emulator.readRegister(file + "3").longValue() & MASK32;
					if (result != Long.parseUnsignedLong(f[7], 16)) {
						failures.add(f[1] + ": result 0x" + Long.toHexString(result) + " expected 0x" + f[7]);
					}
				} finally {
					emulator.dispose();
				}
				decoded++;
			}
		}
		if (!failures.isEmpty()) {
			throw new AssertionError(failures.size() + " rows failed: " + String.join("; ", failures));
		}
		println("C6000_DP_CONVERT_SOURCE_OK decoded=" + decoded + " undefined=" + rejected);
	}
}
