// SPDX-License-Identifier: Apache-2.0
// @category C6000
// A function entered by a delayed call is no thunk, in a tests/fixtures/entry-call.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class C6000EntryCallTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			c6000.C6000PacketContext.prime(currentProgram, monitor);
			for (long[] f : new long[][] { { 0x1000 }, { 0x1040 }, { 0x1080 } }) disassemble(toAddr(f[0]));
			createFunction(toAddr(0x1000L), "leaf");
			createFunction(toAddr(0x1040L), "entrycall");
			createFunction(toAddr(0x1080L), "jumper");
			// Known-bad shape: created while B is a jump, entrycall starts as Ghidra's thunk of leaf.
			if (!getFunctionAt(toAddr(0x1040L)).isThunk()) throw new AssertionError("fixture shape changed: entrycall is no thunk before analysis");
			return;
		}
		Function call = getFunctionAt(toAddr(0x1040L)), jump = getFunctionAt(toAddr(0x1080L));
		StringBuilder bad = new StringBuilder();
		// It calls leaf and comes back to ret1: its body reaches the code after the call.
		if (call.isThunk()) bad.append(" entrycall is a thunk of " + call.getThunkedFunction(false));
		if (!call.getBody().contains(toAddr(0x1058L))) bad.append(" entrycall body " + call.getBody() + " lacks ret1");
		// Known-good: a lone jump stays a thunk.
		if (!jump.isThunk() || !jump.getThunkedFunction(false).getEntryPoint().equals(toAddr(0x1000L))) bad.append(" jumper is no thunk of leaf");
		if (bad.length() > 0) throw new AssertionError("entry-call:" + bad);
		println("C6000_ENTRY_CALL_OK");
	}
}
