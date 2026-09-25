// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Audit every recovered function for decompiler completion.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class C6000DecompilerAudit extends GhidraScript {
	@Override
	protected void run() throws Exception {
		DecompInterface decompiler = new DecompInterface();
		int checked = 0;
		int completed = 0;
		int failed = 0;
		try {
			decompiler.setOptions(new DecompileOptions());
			decompiler.openProgram(currentProgram);
			FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
			while (functions.hasNext()) {
				monitor.checkCancelled();
				Function function = functions.next();
				if (function.isExternal()) continue;
				long started = System.nanoTime();
				DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
				long seconds = (System.nanoTime() - started) / 1_000_000_000L;
				checked++;
				if (result.decompileCompleted()) completed++;
				else {
					failed++;
					println("C6000_DECOMPILER_FAIL function=" + function.getEntryPoint() +
						" error=" + result.getErrorMessage().replace('\n', ' '));
				}
				if (seconds >= 10) println("C6000_DECOMPILER_SLOW function=" +
					function.getEntryPoint() + " seconds=" + seconds);
				decompiler.flushCache();
			}
			println("C6000_DECOMPILER_AUDIT checked=" + checked + " completed=" + completed +
				" failed=" + failed);
		}
		finally { decompiler.dispose(); }
	}
}
