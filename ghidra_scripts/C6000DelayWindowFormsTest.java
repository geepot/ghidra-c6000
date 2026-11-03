// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check an auto-analysed tests/fixtures/delay-window-forms.py image (issue #34).

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;

public class C6000DelayWindowFormsTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		if (getScriptArgs()[0].equals("prepare")) {
			for (long entry : new long[] {0x1000, 0x1030}) {
				currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(entry));
				new DisassembleCommand(toAddr(entry), null, true).applyTo(currentProgram, monitor);
				createFunction(toAddr(entry), null);
			}
			return;
		}
		List<String> failures = new ArrayList<>();
		var delay = currentProgram.getRegister("c_flow_delay");
		// SPRUFE8B 4.2.6: five delay cycles, here five slot instructions or MVK + ADD + NOP 3.
		long[][] windows = {{0x1004, 20}, {0x1034, 12}};
		for (long[] w : windows) {
			var value = currentProgram.getProgramContext().getValue(delay, toAddr(w[0]), false);
			if (value == null || value.intValue() != w[1]) failures.add(toAddr(w[0]) + " c_flow_delay=" + value + " expected " + w[1]);
		}
		var call = getInstructionAt(toAddr(0x1004));
		if (call == null || call.getFlowOverride() != FlowOverride.CALL) failures.add("B sink is not a call: " + call);
		else if (!toAddr(0x101c).equals(call.getFallThrough())) failures.add("B sink returns to " + call.getFallThrough());
		DecompInterface decompiler = new DecompInterface();
		decompiler.setOptions(new DecompileOptions());
		decompiler.openProgram(currentProgram);
		try {
			// The slot work happens before the transfer: sink (FUN_00001050) receives msg2 and 2, and
			// the 5 is added on both paths of the predicated branch.
			String[][] expect = {{"1000", "FUN_00001050(", ",2)", "+ 1"}, {"1030", "+ 5"}};
			for (String[] e : expect) {
				Function function = getFunctionAt(toAddr(Long.parseLong(e[0], 16)));
				var result = function == null ? null : decompiler.decompileFunction(function, 30, monitor);
				String c = result == null ? "no function" : result.getDecompiledFunction() == null ? result.getErrorMessage() : result.getDecompiledFunction().getC().replace(", ", ",");
				for (int k = 1; k < e.length; k++) {
					if (!c.contains(e[k].replace(", ", ","))) failures.add(e[0] + " lacks " + e[k] + ": " + c);
				}
			}
		}
		finally {
			decompiler.dispose();
		}
		if (!failures.isEmpty()) throw new AssertionError(String.join("; ", failures));
		println("C6000_DELAY_WINDOW_FORMS_OK");
	}
}
