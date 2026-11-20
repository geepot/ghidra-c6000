// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Enable an exact schedule whose entry jump has compact delay slots, in an auto-analysed
// tests/fixtures/compact-entry-window.py image, and run it.

import c6000.C6000PipelineCompiler;
import c6000.C6000PipelineSchedules;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import java.util.Arrays;
import java.util.Set;

public class C6000CompactEntryWindowTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		// 1040 is this function's tail, not a callee: analysis takes the jump for a tail call and
		// 1000 for its thunk, so the function is declared again with both parts
		for (long at : new long[] { 0x1000L, 0x1040L }) {
			Function old = getFunctionAt(toAddr(at));
			if (old != null) removeFunction(old);
		}
		var body = new AddressSet(toAddr(0x1000L), toAddr(0x101fL));
		body.add(toAddr(0x1040L), toAddr(0x1047L));
		Function f = currentProgram.getFunctionManager().createFunction("entry_jump", toAddr(0x1000L), body,
			ghidra.program.model.symbol.SourceType.USER_DEFINED);
		Instruction jump = getInstructionAt(toAddr(0x1000L));
		Instruction slot = getInstructionAt(toAddr(0x1004L));
		// The shape: a native window of 8 bytes whose first slot is a 16-bit instruction. Ghidra's
		// delay-slot depth doesn't count these slots (it reads 0 here).
		if (f == null || jump == null || jump.getPrototype().getDelaySlotByteCount() != 8 ||
			slot == null || slot.getLength() != 2 ||
			!slot.isInDelaySlot()) {
			throw new AssertionError("fixture shape changed: " + jump + " window " +
				(jump == null ? -1 : jump.getPrototype().getDelaySlotByteCount()) + " bytes, slot " + slot +
				", function " + (f == null ? null : f.getBody()));
		}
		C6000PipelineSchedules.enable(currentProgram, f, "fixture entry: drained pipeline", Set.of(), monitor);
		var schedule = new C6000PipelineCompiler(currentProgram, f).compile();
		var language = (SleighLanguage) currentProgram.getLanguage();
		var arithmetic = BytesPcodeArithmetic.forLanguage(language);
		var state = new BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE);
		for (var register : language.getRegisters()) {
			if (!register.isProcessorContext() && register.getMinimumByteSize() == 4) state.setVar(register, arithmetic.fromConst(0, 4));
		}
		state.setVar(currentProgram.getRegister("B3"), arithmetic.fromConst(0x9000, 4));
		state.setVar(currentProgram.getRegister("A0"), arithmetic.fromConst(0x1234, 4));
		var executor = new PcodeExecutor<byte[]>(language, arithmetic, state, PcodeExecutorStatePiece.Reason.EXECUTE_READ);
		var library = PcodeUseropLibrary.<byte[]>nil();
		var frame = executor.begin(new PcodeProgram(language, Arrays.asList(schedule.code()), library.getSymbols(language)) {});
		for (int steps = 0; !frame.isFinished() && steps < 100000; steps++) executor.step(frame, library);
		long a4 = arithmetic.toLong(state.getVar(currentProgram.getRegister("A4"), PcodeExecutorStatePiece.Reason.INSPECT), PcodeArithmetic.Purpose.INSPECT);
		long pc = arithmetic.toLong(state.getVar(currentProgram.getRegister("PC"), PcodeExecutorStatePiece.Reason.INSPECT), PcodeArithmetic.Purpose.INSPECT);
		if (!frame.isFinished() || a4 != 0x1234 || pc != 0x9000) {
			throw new AssertionError("schedule ran to A4=" + Long.toHexString(a4) + " PC=" + Long.toHexString(pc));
		}
		C6000PipelineSchedules.disable(currentProgram, f, monitor);
		println("C6000_COMPACT_ENTRY_WINDOW_OK");
	}
}
