// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check the return points of delayed calls in a tests/fixtures/lost-fallthrough.py image.
// Run as preScript with "prepare CASES.json", then as postScript with CASES.json.

import c6000.C6000PacketContext;
import ghidra.app.script.GhidraScript;
import java.nio.file.*;

public class C6000LostFallthroughTest extends GhidraScript {
	private static final class Case {
		String name;
		long entry, h;
		long[] returns;
		String[] c;
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		boolean prepare = args.length == 2 && args[0].equals("prepare");
		if (!prepare && args.length != 1) throw new IllegalArgumentException("Expected [prepare] CASES.json");
		var cases = new com.google.gson.Gson().fromJson(Files.readString(Paths.get(args[args.length - 1])), Case[].class);
		if (prepare) {
			C6000PacketContext.prime(currentProgram, monitor);
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(cases[0].entry));
			for (var item : cases) {
				for (long at : new long[] { item.entry, item.h }) {
					disassemble(toAddr(at));
					createFunction(toAddr(at), at == item.entry ? item.name : item.name + "_h");
				}
			}
			return;
		}
		StringBuilder failures = new StringBuilder();
		for (var item : cases) {
			var f = getFunctionAt(toAddr(item.entry));
			if (f == null) { failures.append(item.name + ": no function\n"); continue; }
			for (long at : item.returns) {
				var insn = getInstructionAt(toAddr(at));
				if (insn == null) failures.append(item.name + ": return point " + toAddr(at) + " is not decoded\n");
				else if (!f.getBody().contains(toAddr(at))) failures.append(item.name + ": return point " + toAddr(at) + " is outside " + f.getBody() + "\n");
			}
			var decompiler = new ghidra.app.decompiler.DecompInterface();
			decompiler.openProgram(currentProgram);
			var result = decompiler.decompileFunction(f, 60, monitor);
			String c = result.decompileCompleted() ? result.getDecompiledFunction().getC() : String.valueOf(result.getErrorMessage());
			decompiler.dispose();
			println(item.name + " body=" + f.getBody() + " C:\n" + c);
			for (String text : item.c)
				if (!c.contains(text)) { failures.append(item.name + ": C lacks \"" + text + "\"\n"); break; }
			// A return lifted from undecoded bytes ends in the caller's own B B3, read as a jump table.
			if (c.contains("UNRECOVERED_JUMPTABLE")) failures.append(item.name + ": C has an unrecovered jump\n");
		}
		if (failures.length() > 0) throw new AssertionError(failures.toString());
		println("C6000_LOST_FALLTHROUGH_OK cases=" + cases.length);
	}
}
