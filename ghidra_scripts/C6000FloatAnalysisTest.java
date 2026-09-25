// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Compare the C6000 floating-point language variants on a firmware function.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class C6000FloatAnalysisTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		Address start = toAddr(0xc0008c44L);
		Function function = currentProgram.getFunctionManager().getFunctionAt(start);
		if (function == null) throw new AssertionError("float function was not recovered");
		DecompInterface decompiler = new DecompInterface();
		try {
			decompiler.setOptions(new DecompileOptions());
			decompiler.openProgram(currentProgram);
			DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
			if (!result.decompileCompleted()) {
				throw new AssertionError(result.getErrorMessage());
			}
			String code = result.getDecompiledFunction().getC();
			long lines = code.lines().count();
			if (currentProgram.getLanguageID().toString().endsWith(":analysis") &&
				(lines > 80 || !code.contains("< 1.0"))) {
				throw new AssertionError("float analysis lost the compact polynomial branch " +
					"or expanded to " + lines + " lines");
			}
			println("C6000_FLOAT_ANALYSIS variant=" + currentProgram.getLanguageID() +
				" lines=" + lines + " chars=" + code.length() +
				" bodyBytes=" + function.getBody().getNumAddresses());
			if (getScriptArgs().length > 0 && getScriptArgs()[0].equals("dump")) {
				for (String line : code.split("\n")) println("C6000_FLOAT_C " + line);
			}
		}
		finally { decompiler.dispose(); }
	}
}
