// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check that a recovered function's conditional branch decompiles as control flow.
// Usage: C6000DecompilerFlowTest.java <functionAddress>

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.File;

public class C6000DecompilerFlowTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 1) throw new IllegalArgumentException("expected function address");
		Function function = currentProgram.getFunctionManager().getFunctionAt(
			toAddr(Long.parseUnsignedLong(args[0], 16)));
		if (function == null) throw new AssertionError("function not recovered");
		DecompInterface decompiler = new DecompInterface();
		try {
			decompiler.setOptions(new DecompileOptions());
			decompiler.openProgram(currentProgram);
			String debug = System.getenv("C6000_DECOMP_DEBUG");
			if (debug != null) decompiler.enableDebug(new File(debug));
			DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
			if (!result.decompileCompleted()) {
				throw new AssertionError("decompiler: " + result.getErrorMessage());
			}
			String code = result.getDecompiledFunction().getC();
			if (!code.contains("if (")) {
				throw new AssertionError("no structured conditional in " + function.getEntryPoint());
			}
			println("C6000_DECOMPILER_FLOW_OK function=" + function.getEntryPoint() +
				" chars=" + code.length());
		}
		finally {
			decompiler.dispose();
		}
	}
}
