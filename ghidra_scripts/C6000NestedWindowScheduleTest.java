// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Exact-schedule review of a nested delay window in a tests/fixtures/nested-window-schedule.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import c6000.C6000PipelineContracts;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import java.util.List;
import java.util.Set;

public class C6000NestedWindowScheduleTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x10c0L, 0x1000L, 0x1040L, 0x1080L, 0x10e0L, 0x1120L, 0x112cL };
	private static final String[] NAMES = { "callee", "retjump", "ifcall", "ifcall2", "ifcall3", "neighbour", "absorber" };
	private int checks;

	interface Action { void run() throws Exception; }

	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x1000L));
			C6000PacketContext.prime(currentProgram, monitor);
			for (int i = 0; i < ENTRIES.length; i++) {
				disassemble(toAddr(ENTRIES[i]));
				createFunction(toAddr(ENTRIES[i]), NAMES[i]);
			}
			return;
		}
		Function retjump = getFunctionAt(toAddr(0x1000L));
		// The shape: B tail1's window holds the return, so natively it has none and its slots stay unowned.
		Instruction jump = getInstructionAt(toAddr(0x1004L));
		if (jump == null || jump.getDelaySlotDepth() != 0 || retjump.getBody().contains(toAddr(0x1010L)) ||
			getFunctionContaining(toAddr(0x1010L)) != null) {
			throw new AssertionError("fixture shape changed: B tail1 " + jump + " depth " +
				(jump == null ? -1 : jump.getDelaySlotDepth()) + ", body " + retjump.getBody());
		}
		// Known-bad: covered code whose predecessor the body does not own (tail1 cut out of the body).
		AddressSet body = new AddressSet(retjump.getBody());
		retjump.setBody(body.subtract(new AddressSet(toAddr(0x101cL), toAddr(0x103fL))));
		refuses(() -> review(retjump), "complete function ownership");
		retjump.setBody(body);
		// Known-bad: covered code another function owns (the compiler refuses it before review).
		disassemble(toAddr(0x1008L));
		Function intruder = createFunction(toAddr(0x1008L), "intruder");
		if (intruder == null) throw new AssertionError("cannot declare intruder");
		refuses(() -> review(retjump), "flow enters another function at 00001008");
		removeFunction(intruder);
		retjump.setBody(body);
		// Known-good: the refused window's slots continue the body and no function owns them.
		var review = review(retjump);
		C6000PipelineContracts.record(currentProgram, retjump, review, monitor);
		C6000PipelineContracts.activate(currentProgram, retjump, monitor);
		if (!retjump.getBody().contains(new AddressSet(toAddr(0x1008L), toAddr(0x1013L)))) {
			throw new AssertionError("activation did not absorb the window: " + retjump.getBody());
		}
		String c = decompile(retjump);
		if (!c.contains("return 0x16;") && !c.contains("return 22;")) throw new AssertionError("retjump must return 22:\n" + c);
		checks++;
		println("C6000_NESTED_WINDOW_SCHEDULE_OK checks=" + checks);
	}

	private C6000PipelineContracts.Review review(Function f) throws Exception {
		long start = f.getEntryPoint().getOffset() & ~31L;
		byte[] bytes = getBytes(toAddr(start), 32);
		var source = new C6000PipelineContracts.SourceWindow(start, 32, C6000PipelineContracts.sha256(bytes));
		return C6000PipelineContracts.review(currentProgram, f, "fixture entry: drained pipeline", Set.of(),
			List.of(source), monitor);
	}

	private void refuses(Action action, String reason) throws Exception {
		try {
			action.run();
		}
		catch (Exception error) {
			if (!error.toString().contains(reason)) throw new AssertionError("wrong refusal: " + error, error);
			checks++;
			return;
		}
		throw new AssertionError("accepted: " + reason);
	}

	private String decompile(Function f) {
		var decompiler = new DecompInterface();
		try {
			decompiler.openProgram(currentProgram);
			var result = decompiler.decompileFunction(f, 60, monitor);
			if (result == null || result.getDecompiledFunction() == null) {
				throw new AssertionError("decompile failed: " + (result == null ? "null" : result.getErrorMessage()));
			}
			return result.getDecompiledFunction().getC();
		}
		finally {
			decompiler.dispose();
		}
	}
}
