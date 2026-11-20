// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check double-precision, conversion and compare forms in all language variants:
// analysis-float.py cases.json.

import com.google.gson.JsonParser;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

public class C6000AnalysisFloatTest extends GhidraScript {
	private static final Set<Integer> FLOAT_OPS = Set.of(PcodeOp.FLOAT_ADD, PcodeOp.FLOAT_SUB,
		PcodeOp.FLOAT_MULT, PcodeOp.FLOAT_ABS, PcodeOp.FLOAT_EQUAL, PcodeOp.FLOAT_LESS,
		PcodeOp.FLOAT_FLOAT2FLOAT, PcodeOp.FLOAT_TRUNC, PcodeOp.FLOAT_ROUND);

	@Override
	protected void run() throws Exception {
		boolean analysis = Set.of("analysis", "c67x-analysis").contains(
			currentProgram.getLanguage().getLanguageDescription().getVariant());
		int checked = 0;
		for (var element : JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonArray()) {
			var row = element.getAsJsonObject();
			String name = row.get("mnemonic").getAsString();
			long at = 0x1000L + 32L * row.get("index").getAsInt();
			new DisassembleCommand(toAddr(at), null, false).applyTo(currentProgram, monitor);
			Instruction insn = getInstructionAt(toAddr(at));
			if (insn == null || !insn.getMnemonicString().startsWith(name + ".")) {
				throw new AssertionError(name + ": decoded as " + insn);
			}
			if (analysis) {
				// A reading aid: the operation itself, as the decompiler can show it.
				boolean floating = false;
				for (PcodeOp op : insn.getPcode()) {
					if (op.getOpcode() == PcodeOp.CALLOTHER) throw new AssertionError(name + ": userop " + op);
					floating |= FLOAT_OPS.contains(op.getOpcode());
				}
				if (!floating) throw new AssertionError(name + ": no floating-point p-code in " + insn);
			}
			EmulatorHelper emulator = new EmulatorHelper(currentProgram);
			try {
				for (var input : row.getAsJsonObject("input").entrySet()) {
					emulator.writeRegister(input.getKey(), input.getValue().getAsLong());
				}
				emulator.getEmulator().setExecuteAddress(at);
				if (!emulator.step(monitor)) throw new AssertionError(name + ": " + emulator.getLastError());
				for (var output : row.getAsJsonObject("expected").entrySet()) {
					long actual = emulator.readRegister(output.getKey()).longValue() & 0xffffffffL;
					if (actual != output.getValue().getAsLong()) {
						throw new AssertionError(name + " " + output.getKey() + "=" + Long.toHexString(actual) +
							" expected=" + Long.toHexString(output.getValue().getAsLong()));
					}
				}
			}
			finally {
				emulator.dispose();
			}
			checked++;
		}
		if (checked != 16) throw new AssertionError("incomplete float matrix");
		println("C6000_ANALYSIS_FLOAT_OK cases=" + checked);
	}
}
