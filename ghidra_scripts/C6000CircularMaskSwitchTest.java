// SPDX-License-Identifier: Apache-2.0
// @category C6000
// The switch in a circular-mask-switch.py image: decompiled with its twelve cases and the default.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class C6000CircularMaskSwitchTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		disassemble(toAddr(0x1000L));
		Function function = createFunction(toAddr(0x1000L), "sw");
		if (function == null) throw new AssertionError("no function at 0x1000");
		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
		decompiler.dispose();
		if (!result.decompileCompleted()) throw new AssertionError("decompile failed: " + result.getErrorMessage());
		var high = result.getHighFunction();
		String c = result.getDecompiledFunction().getC();
		if (high.getJumpTables().length != 1) throw new AssertionError("no switch recovered at 0x1020:\n" + c);
		int cases = high.getJumpTables()[0].getCases().length;
		// twelve table entries and the default
		if (cases != 13) throw new AssertionError(cases + " cases, not 12 and the default:\n" + c);
		println("C6000_CIRCULAR_MASK_SWITCH_OK cases=" + cases);
	}
}
