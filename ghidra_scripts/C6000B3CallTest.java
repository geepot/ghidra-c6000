// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check B B3 calls in a tests/fixtures/b3-call.py image (issue #39).
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000PacketContext;
import c6000.C6000PipelineCompiler;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;

public class C6000B3CallTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x1000L, 0x102cL, 0x105cL, 0x1068L };
	private static final String[] NAMES = { "viaptr", "direct", "callee", "selfjmp" };

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
		// Known-good: a B B3 whose slots set B3 past the window is a call that returns
		// there, with the slots in the caller and the B3 write before the CALLIND.
		call(0x1008L, 0x1000L, 0x1018L, null);
		call(0x1038L, 0x102cL, 0x1048L, 0x105cL);
		// Known-bad: an ordinary return, and a B B3 whose B3 already held the address past
		// the window when the B read it (a computed jump to the fall-through).
		for (long at : new long[] { 0x1060L, 0x1070L }) {
			Instruction b = getInstructionAt(toAddr(at));
			if (b == null || b.getFlowOverride() == FlowOverride.CALL || b.getFlowType().isCall()) {
				throw new AssertionError("B B3 at " + toAddr(at) + " became a call: " + describe(b));
			}
		}
		expect(0x1000L, "+ 1");
		expect(0x102cL, "callee()");
		// An exact schedule cannot return through a B3 that holds a new link: it refuses the
		// call unless a closed-call contract describes it, and still schedules a plain return.
		refuses(0x1000L);
		refuses(0x102cL);
		new C6000PipelineCompiler(currentProgram, getFunctionAt(toAddr(0x105cL))).compile();
		println("C6000_B3_CALL_OK checks=9");
	}

	/** A returning call at at, owned by caller, returning to ret, calling callee when known. */
	private void call(long at, long caller, long ret, Long callee) {
		Instruction b = getInstructionAt(toAddr(at));
		if (b == null || b.getFlowOverride() != FlowOverride.CALL || !b.getFlowType().isCall() ||
			b.getFlowType().isTerminal() || !toAddr(ret).equals(b.getFallThrough()) ||
			(callee != null && !calls(b, callee))) {
			throw new AssertionError("call at " + toAddr(at) + ": " + describe(b));
		}
		for (Address slot = b.getMaxAddress().next(); slot.compareTo(toAddr(ret)) < 0; slot = slot.add(4)) {
			Instruction s = getInstructionAt(slot);
			Function f = getFunctionContaining(slot);
			if (s == null || !s.isInDelaySlot() || f == null || !f.getEntryPoint().equals(toAddr(caller))) {
				throw new AssertionError("slot " + slot + " of " + toAddr(at) + ": " + s + " in " + f);
			}
		}
		Function f = getFunctionContaining(toAddr(ret));
		if (f == null || !f.getEntryPoint().equals(toAddr(caller))) {
			throw new AssertionError("return point " + toAddr(ret) + " not in " + toAddr(caller) + ": " + f);
		}
		PcodeOp[] ops = b.getPcode(true);
		int callAt = -1, b3At = -1;
		long b3 = currentProgram.getRegister("B3").getOffset();
		for (int i = 0; i < ops.length; i++) {
			if (ops[i].getOpcode() == PcodeOp.CALLIND) callAt = i;
			Varnode out = ops[i].getOutput();
			if (out != null && out.isRegister() && out.getOffset() == b3) b3At = i;
		}
		if (callAt < 0 || b3At < 0 || b3At > callAt) {
			throw new AssertionError("B3 link of " + toAddr(at) + " not written before the call: " + describe(b));
		}
	}

	private void refuses(long entry) {
		try {
			new C6000PipelineCompiler(currentProgram, getFunctionAt(toAddr(entry))).compile();
		}
		catch (Exception expected) {
			return;
		}
		throw new AssertionError("exact schedule of " + toAddr(entry) + " returned through a call's B3");
	}

	private void expect(long entry, String text) throws Exception {
		DecompInterface decompiler = new DecompInterface();
		decompiler.setOptions(new DecompileOptions());
		decompiler.openProgram(currentProgram);
		try {
			var result = decompiler.decompileFunction(getFunctionAt(toAddr(entry)), 30, monitor);
			if (result == null || !result.decompileCompleted()) {
				throw new AssertionError("decompile " + toAddr(entry) + ": " + (result == null ? null : result.getErrorMessage()));
			}
			String c = result.getDecompiledFunction().getC();
			if (!c.contains(text)) throw new AssertionError(toAddr(entry) + " lacks " + text + ":\n" + c);
		}
		finally {
			decompiler.dispose();
		}
	}

	private boolean calls(Instruction b, long target) {
		for (Reference r : b.getReferencesFrom()) {
			if (r.getReferenceType().isCall() && r.getToAddress().equals(toAddr(target))) return true;
		}
		return false;
	}

	private static String describe(Instruction i) {
		if (i == null) return "null";
		StringBuilder refs = new StringBuilder();
		for (Reference r : i.getReferencesFrom()) refs.append(' ').append(r.getReferenceType()).append(':').append(r.getToAddress());
		return i + " flow=" + i.getFlowType() + " override=" + i.getFlowOverride() + " fallthrough=" +
			i.getFallThrough() + " depth=" + i.getDelaySlotDepth() + " refs=" + refs;
	}
}
