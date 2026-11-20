// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Compile and run the exact schedule of a function that reads TSCL and TSCH, in a
// tests/fixtures/pipeline-tsc.py image.

import c6000.C6000PipelineCompiler;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
import java.util.Arrays;

public class C6000PipelineTscTest extends GhidraScript {
	/** The counter reads answer fixed values; starting the counter does nothing here. */
	public static class Counter extends AnnotatedPcodeUseropLibrary<byte[]> {
		private final BytesPcodeArithmetic arithmetic;
		Counter(BytesPcodeArithmetic arithmetic) { this.arithmetic = arithmetic; }
		@PcodeUserop public byte[] c6000_tscl_read() { return arithmetic.fromConst(0x1111, 4); }
		@PcodeUserop public byte[] c6000_tsch_read() { return arithmetic.fromConst(0x2222, 4); }
		@PcodeUserop public void c6000_tsc_start() {}
	}

	@Override
	protected void run() throws Exception {
		var body = new AddressSet(toAddr(0x1000L), toAddr(0x101fL));
		new DisassembleCommand(toAddr(0x1000L), body, false).applyTo(currentProgram, monitor);
		var f = currentProgram.getFunctionManager().createFunction("clock", toAddr(0x1000L), body, SourceType.USER_DEFINED);
		var schedule = new C6000PipelineCompiler(currentProgram, f).compile();
		var language = (SleighLanguage) currentProgram.getLanguage();
		var arithmetic = BytesPcodeArithmetic.forLanguage(language);
		var state = new BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE);
		for (var register : language.getRegisters()) {
			if (!register.isProcessorContext() && register.getMinimumByteSize() == 4) state.setVar(register, arithmetic.fromConst(0, 4));
		}
		state.setVar(currentProgram.getRegister("B3"), arithmetic.fromConst(0x9000, 4));
		var executor = new PcodeExecutor<byte[]>(language, arithmetic, state, PcodeExecutorStatePiece.Reason.EXECUTE_READ);
		var library = new Counter(arithmetic);
		var frame = executor.begin(new PcodeProgram(language, Arrays.asList(schedule.code()), library.getSymbols(language)) {});
		for (int steps = 0; !frame.isFinished() && steps < 100000; steps++) executor.step(frame, library);
		long a4 = value(arithmetic, state, "A4"), a5 = value(arithmetic, state, "A5"), pc = value(arithmetic, state, "PC");
		if (!frame.isFinished() || a4 != 0x1111 || a5 != 0x2222 || pc != 0x9000) {
			throw new AssertionError("schedule ran to A4=" + Long.toHexString(a4) + " A5=" + Long.toHexString(a5) + " PC=" + Long.toHexString(pc));
		}
		println("C6000_PIPELINE_TSC_OK");
	}

	private long value(BytesPcodeArithmetic arithmetic, BytesPcodeExecutorState state, String register) {
		return arithmetic.toLong(state.getVar(currentProgram.getRegister(register), PcodeExecutorStatePiece.Reason.INSPECT),
			PcodeArithmetic.Purpose.INSPECT);
	}
}
