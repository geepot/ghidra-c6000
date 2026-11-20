// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check double-precision, conversion and compare forms in all language variants:
// analysis-float.py cases.json. The analysis variants use plain floating-point p-code with
// the c6000_fp_status userop for status.

import c6000.C6000PipelineCompiler;
import com.google.gson.JsonParser;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
import java.util.Arrays;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
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
				// A reading aid: the operation itself, as the decompiler can show it, and one
				// opaque status update, as for the single-precision arithmetic.
				boolean floating = false;
				int status = 0;
				for (PcodeOp op : insn.getPcode()) {
					if (op.getOpcode() == PcodeOp.CALLOTHER) {
						String userop = currentProgram.getLanguage().getUserDefinedOpName((int) op.getInput(0).getOffset());
						if (!userop.equals("c6000_fp_status") || op.getOutput() == null) {
							throw new AssertionError(name + ": userop " + op);
						}
						status++;
					}
					floating |= FLOAT_OPS.contains(op.getOpcode());
				}
				if (!floating || status != 1) {
					throw new AssertionError(name + ": floating=" + floating + " status=" + status + " in " + insn);
				}
			}
			EmulatorHelper emulator = new EmulatorHelper(currentProgram);
			// the analysis languages' opaque status update: no event bits
			if (analysis) emulator.registerCallOtherCallback("c6000_fp_status", new BreakCallBack() {
				@Override
				public boolean pcodeCallback(PcodeOpRaw op) {
					emulator.getEmulator().getMemState().setValue(op.getOutput(), 0);
					return true;
				}
			});
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
			// the same instruction through its exact schedule, the status update included
			var function = currentProgram.getFunctionManager().createFunction(name, toAddr(at),
				new AddressSet(toAddr(at), toAddr(at + 31)), SourceType.USER_DEFINED);
			new DisassembleCommand(toAddr(at), new AddressSet(toAddr(at), toAddr(at + 31)), false).applyTo(currentProgram, monitor);
			var schedule = new C6000PipelineCompiler(currentProgram, function).compile();
			var language = (SleighLanguage) currentProgram.getLanguage();
			var arithmetic = BytesPcodeArithmetic.forLanguage(language);
			var state = new BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE);
			for (var register : language.getRegisters()) {
				if (!register.isProcessorContext() && register.getMinimumByteSize() == 4) state.setVar(register, arithmetic.fromConst(0, 4));
			}
			state.setVar(currentProgram.getRegister("B3"), arithmetic.fromConst(0x9000, 4));
			for (var input : row.getAsJsonObject("input").entrySet()) {
				state.setVar(currentProgram.getRegister(input.getKey()), arithmetic.fromConst(input.getValue().getAsLong(), 4));
			}
			var executor = new PcodeExecutor<byte[]>(language, arithmetic, state, PcodeExecutorStatePiece.Reason.EXECUTE_READ);
			var library = new StatusLibrary();
			var frame = executor.begin(new PcodeProgram(language, Arrays.asList(schedule.code()), library.getSymbols(language)) {});
			for (int steps = 0; !frame.isFinished() && steps < 100000; steps++) executor.step(frame, library);
			if (!frame.isFinished()) throw new AssertionError(name + ": schedule step bound");
			for (var output : row.getAsJsonObject("expected").entrySet()) {
				long actual = arithmetic.toLong(state.getVar(currentProgram.getRegister(output.getKey()),
					PcodeExecutorStatePiece.Reason.INSPECT), PcodeArithmetic.Purpose.INSPECT) & 0xffffffffL;
				if (actual != output.getValue().getAsLong()) {
					throw new AssertionError(name + " schedule " + output.getKey() + "=" + Long.toHexString(actual));
				}
			}
			checked++;
		}
		if (checked != 18) throw new AssertionError("incomplete float matrix");
		println("C6000_ANALYSIS_FLOAT_OK cases=" + checked);
	}

	/** The analysis languages' opaque status update: no event bits. */
	public static class StatusLibrary extends AnnotatedPcodeUseropLibrary<byte[]> {
		@PcodeUserop(variadic = true)
		public byte[] c6000_fp_status(byte[][] inputs) {
			return new byte[4];
		}
	}
}
