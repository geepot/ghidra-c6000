// SPDX-License-Identifier: Apache-2.0
// @category C6000
// A software-pipelined countdown loop whose [A1] SUB A1 cannot revive a zero A1, so a fallen-through
// loop branch is followed by another; in a tests/fixtures/pipeline-selfguard-loop.py image.

import c6000.C6000PacketContext;
import c6000.C6000PipelineCompiler;
import c6000.C6000PipelineContracts;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.util.*;

public class C6000SelfGuardLoopTest extends GhidraScript {
	private static final String EVIDENCE = "fixture entry: drained pipeline";
	private static final String REFUSAL = "potential simultaneous memory/register writes";
	private static final long DATA = 0x8000, WORD = 0x1234;

	private static final class Case {
		String name;
		long at;
		long body_end;
		long kernel;
		int[] kernel_truths;
		boolean accepted;
	}

	@Override
	protected void run() throws Exception {
		var cases = new com.google.gson.Gson().fromJson(Files.readString(Paths.get(getScriptArgs()[0])), Case[].class);
		C6000PacketContext.prime(currentProgram, monitor);
		int accepted = 0, refused = 0, executions = 0;
		for (var item : cases) {
			Function function = prepare(item);
			kernelTruths(item, function);
			C6000PipelineContracts.Review review;
			try {
				review = review(function);
			}
			catch (IllegalArgumentException error) {
				println((item.accepted ? "UNEXPECTED_REFUSAL " : "EXPECTED_REFUSAL ") + item.name + ": " + error.getMessage());
				if (item.accepted || !error.getMessage().contains(REFUSAL))
					throw new AssertionError(item.name + ": " + error.getMessage(), error);
				refused++;
				continue;
			}
			if (!item.accepted) throw new AssertionError("accepted " + item.name);
			C6000PipelineContracts.record(currentProgram, function, review, monitor);
			var schedule = C6000PipelineContracts.activate(currentProgram, function, monitor);
			println("SUPPORTED " + item.name + " states=" + schedule.states());
			for (long n : new long[] {0, 1, 2, 3, 7}) {
				execute(item, schedule, n);
				executions++;
			}
			accepted++;
		}
		println("C6000_SELFGUARD_LOOP_OK accepted=" + accepted + " refused=" + refused + " executions=" + executions);
	}

	private Function prepare(Case item) throws Exception {
		var body = new AddressSet(toAddr(item.at), toAddr(item.body_end));
		if (!new DisassembleCommand(toAddr(item.at), body, false).applyTo(currentProgram, monitor))
			throw new IllegalStateException("Could not disassemble " + item.name);
		return currentProgram.getFunctionManager().createFunction(item.name, toAddr(item.at), body, SourceType.USER_DEFINED);
	}

	private C6000PipelineContracts.Review review(Function function) throws Exception {
		long start = function.getEntryPoint().getOffset();
		var source = new C6000PipelineContracts.SourceWindow(start, 64, C6000PipelineContracts.sha256(getBytes(toAddr(start), 64)));
		return C6000PipelineContracts.review(currentProgram, function, EVIDENCE, Set.of(), List.of(source), monitor);
	}

	/** The A1 truths of the compile's states at the kernel: zero only where the decrement is [A1] (SPRUFE8B 3.5). */
	private void kernelTruths(Case item, Function function) throws Exception {
		var compiler = new C6000PipelineCompiler(currentProgram, function);
		try {
			compiler.compile();
		}
		catch (IllegalArgumentException error) {
			// The refusal is checked by review; the states explored so far are kept.
		}
		var field = C6000PipelineCompiler.class.getDeclaredField("states");
		field.setAccessible(true);
		Set<Integer> truths = new TreeSet<>();
		for (Object state : ((Map<?, ?>) field.get(compiler)).keySet()) {
			if (((Number) component(state, "pc")).longValue() != item.kernel) continue;
			var values = (List<?>) component(component(state, "facts"), "values");
			truths.add(((Number) component(values.get(1), "truth")).intValue());
		}
		Set<Integer> expected = new TreeSet<>();
		for (int truth : item.kernel_truths) expected.add(truth);
		if (!truths.equals(expected)) throw new AssertionError(item.name + ": A1 truths at the kernel " + truths + ", want " + expected);
	}

	private static Object component(Object target, String name) throws Exception {
		var method = target.getClass().getDeclaredMethod(name);
		method.setAccessible(true);
		return method.invoke(target);
	}

	/** n = A4: the kernel runs max(n, 1) + 1 times (the entry branch lands once); A4 = *B4 + passes, no call. */
	private void execute(Case item, C6000PipelineCompiler.Result schedule, long n) throws Exception {
		var language = (SleighLanguage) currentProgram.getLanguage();
		var arithmetic = BytesPcodeArithmetic.forLanguage(language);
		var state = new BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE);
		for (var register : language.getRegisters())
			if (!register.isProcessorContext() && register.getMinimumByteSize() == 4) state.setVar(register, arithmetic.fromConst(0, 4));
		state.setVar(currentProgram.getRegister("B3"), arithmetic.fromConst(0x9000, 4));
		state.setVar(currentProgram.getRegister("B4"), arithmetic.fromConst(DATA, 4));
		state.setVar(currentProgram.getRegister("A4"), arithmetic.fromConst(n, 4));
		state.setVar(toAddr(DATA), 4, false, arithmetic.fromConst(WORD, 4));
		var reason = PcodeExecutorStatePiece.Reason.INSPECT;
		var purpose = PcodeArithmetic.Purpose.INSPECT;
		int[] calls = {0};
		var executor = new PcodeExecutor<byte[]>(language, arithmetic, state, PcodeExecutorStatePiece.Reason.EXECUTE_READ) {
			@Override
			public void executeCall(PcodeOp op, PcodeFrame frame, PcodeUseropLibrary<byte[]> library) {
				calls[0]++;
			}
		};
		var library = PcodeUseropLibrary.<byte[]>nil();
		var frame = executor.begin(new PcodeProgram(language, Arrays.asList(schedule.code()), library.getSymbols(language)) {});
		int steps = 0;
		while (!frame.isFinished() && steps++ < 200000) executor.step(frame, library);
		if (!frame.isFinished()) throw new AssertionError(item.name + " n=" + n + " exceeded step bound");
		long pc = arithmetic.toLong(state.getVar(currentProgram.getRegister("PC"), reason), purpose);
		long a1 = arithmetic.toLong(state.getVar(currentProgram.getRegister("A1"), reason), purpose);
		long a4 = arithmetic.toLong(state.getVar(currentProgram.getRegister("A4"), reason), purpose);
		if (calls[0] != 0 || pc != 0x9000 || a1 != 0 || a4 != WORD + Math.max(n, 1) + 1)
			throw new AssertionError(item.name + " n=" + n + ": calls=" + calls[0] + " PC=" + Long.toHexString(pc) + " A1=" + a1 + " A4=" + a4);
	}
}
