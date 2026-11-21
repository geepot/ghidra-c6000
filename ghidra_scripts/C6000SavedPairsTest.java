// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check that a callee-saved pair stored by STDW around a call is not an input, in a
// tests/fixtures/saved-pairs.py image. Run as preScript with "prepare", then as postScript.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import java.util.ArrayList;
import java.util.List;

public class C6000SavedPairsTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x1000L));
			disassemble(toAddr(0x1000L));
			createFunction(toAddr(0x1000L), "twice");
			return;
		}
		Function f = getFunctionAt(toAddr(0x1000L));
		if (f == null || getFunctionAt(toAddr(0x1040L)) == null) {
			throw new AssertionError("the function and its callee were not recovered");
		}
		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		try {
			DecompileResults r = decompiler.decompileFunction(f, 30, monitor);
			if (!r.decompileCompleted()) throw new AssertionError(r.getErrorMessage());
			HighFunction high = r.getHighFunction();
			// The saved pair is neither a parameter nor an unaffected input: only A4 is read.
			List<String> inputs = new ArrayList<>();
			for (int i = 0; i < high.getLocalSymbolMap().getNumParams(); i++) {
				HighSymbol p = high.getLocalSymbolMap().getParamSymbol(i);
				inputs.add(p.getStorage().toString());
			}
			String c = r.getDecompiledFunction().getC();
			if (!inputs.equals(List.of("A4:4")) || c.contains("A11") || c.contains("A10")) {
				throw new AssertionError("saved pair taken as an input " + inputs + ":\n" + c);
			}
		}
		finally {
			decompiler.dispose();
		}
		println("C6000_SAVED_PAIRS_OK");
	}
}
