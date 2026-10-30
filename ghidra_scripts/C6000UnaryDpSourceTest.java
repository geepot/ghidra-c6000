// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check ABSDP/RCPDP/RSQRDP src1-field decoding from unary-dp-src1.py. Usage: <cases.tsv>.

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;

public class C6000UnaryDpSourceTest extends GhidraScript {
	private static final long BASE = 0x1000L;
	private static final long MASK32 = 0xffffffffL;
	private static final int DST = 10;
	private static final Map<String, Long> INIT = Map.of("A", 0x10000000L, "B", 0x20000000L);

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 1) {
			throw new IllegalArgumentException("expected cases.tsv path");
		}
		List<String[]> rows = new ArrayList<>();
		try (BufferedReader in = new BufferedReader(new FileReader(args[0]))) {
			for (String row; (row = in.readLine()) != null;) rows.add(row.split("\t"));
		}
		Map<String, long[]> reference = new HashMap<>();
		Map<String[], long[]> results = new HashMap<>();
		int rejected = 0;
		int guarded = 0;
		List<String> failures = new ArrayList<>();
		for (String[] f : rows) {
			Address address = toAddr(BASE + 32L * Integer.parseInt(f[0]));
			new DisassembleCommand(address, new AddressSet(address, address.add(3)), false).applyTo(currentProgram, monitor);
			Instruction insn = currentProgram.getListing().getInstructionAt(address);
			int low = Integer.parseInt(f[5]);
			if (low < 0) {
				if (insn != null) failures.add(f[1] + " (" + f[4] + "): expected undefined, decoded as " + insn);
				rejected++;
				continue;
			}
			String side = f[3].equals("0") ? "1" : "2";
			String file = side.equals("1") ? "A" : "B";
			String pair = file + (low + 1) + ":" + file + low;
			String guard = f[8].equals("-") ? "" : "[" + f[8] + "]";
			if (insn == null || !insn.getMnemonicString().equals(guard + f[2] + ".S" + side) || !insn.toString().contains(pair + ",")) {
				failures.add(f[1] + " (" + f[4] + "): expected " + pair + ", decoded as " + insn);
				continue;
			}
			long raw = Long.parseUnsignedLong(f[6], 16);
			if (!f[8].equals("-")) {
				// [A1] executes when A1 != 0, [!A1] when A1 == 0; the skipped run must leave dst and FAUCR untouched.
				boolean negated = f[8].startsWith("!");
				long[] taken = execute(address, file, low, raw, negated ? 0 : 1);
				long[] skipped = execute(address, file, low, raw, negated ? 1 : 0);
				long untouched = ((INIT.get(file) + 0x01010101L * (DST + 1)) << 32) | (INIT.get(file) + 0x01010101L * DST);
				if (skipped[0] != untouched || skipped[1] != 0) {
					failures.add(f[1] + ": predicate false wrote dst 0x" + Long.toHexString(skipped[0]) + " FAUCR 0x" + Long.toHexString(skipped[1]));
				}
				results.put(f, taken);
				guarded++;
				continue;
			}
			long[] result = execute(address, file, low, raw, -1);
			results.put(f, result);
			if (f[7].startsWith("even-")) reference.put(f[2] + side + low + f[6], result);
			if (f[2].equals("ABSDP") && !f[7].endsWith("-snan") && result[0] != (raw & Long.MAX_VALUE)) {
				failures.add(f[1] + ": result 0x" + Long.toHexString(result[0]) + " is not |src2|");
			}
			if (f[7].endsWith("-snan") && result[1] == 0) failures.add(f[1] + ": SNaN set no FAUCR bit");
		}
		for (var e : results.entrySet()) {
			String[] f = e.getKey();
			long[] expected = reference.get(f[2] + (f[3].equals("0") ? "1" : "2") + f[5] + f[6]);
			if (expected == null || expected[0] != e.getValue()[0] || expected[1] != e.getValue()[1]) {
				failures.add(f[1] + ": result 0x" + Long.toHexString(e.getValue()[0]) + " FAUCR 0x" + Long.toHexString(e.getValue()[1]) +
					" differs from the even form's " + (expected == null ? "null" : "0x" + Long.toHexString(expected[0]) + " FAUCR 0x" + Long.toHexString(expected[1])));
			}
		}
		if (!failures.isEmpty()) {
			throw new AssertionError(failures.size() + " rows failed: " + String.join("; ", failures));
		}
		println("C6000_UNARY_DP_SOURCE_OK decoded=" + results.size() + " guarded=" + guarded + " undefined=" + rejected);
	}

	private long[] execute(Address address, String file, int low, long raw, int a1) throws Exception {
		EmulatorHelper emulator = new EmulatorHelper(currentProgram);
		try {
			for (int r = 0; r < 32; r++) {
				emulator.writeRegister("A" + r, INIT.get("A") + 0x01010101L * r);
				emulator.writeRegister("B" + r, INIT.get("B") + 0x01010101L * r);
			}
			emulator.writeRegister("FAUCR", 0);
			if (a1 >= 0) emulator.writeRegister("A1", a1);
			emulator.writeRegister(file + low, raw & MASK32);
			emulator.writeRegister(file + (low + 1), raw >>> 32);
			emulator.getEmulator().setExecuteAddress(address.getOffset());
			if (!emulator.step(monitor)) throw new AssertionError(address + ": " + emulator.getLastError());
			long dst = (emulator.readRegister(file + (DST + 1)).longValue() << 32) | (emulator.readRegister(file + DST).longValue() & MASK32);
			return new long[] { dst, emulator.readRegister("FAUCR").longValue() & MASK32 };
		} finally {
			emulator.dispose();
		}
	}
}
