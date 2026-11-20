// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check predicated register jumps in a tests/fixtures/predicated-register-jump.py image (issue #70).
// Run as preScript with "prepare CASES.json", then as postScript with CASES.json.

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import java.nio.file.*;

public class C6000PredicatedRegisterJumpTest extends GhidraScript {
	private static final class Case {
		String name;
		long entry, slot;
		boolean first;
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
				disassemble(toAddr(item.entry));
				createFunction(toAddr(item.entry), item.name);
			}
			return;
		}
		var decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		int both = 0, fallThrough = 0;
		for (var item : cases) {
			Instruction slot = getInstructionAt(toAddr(item.slot));
			Function function = getFunctionAt(toAddr(item.entry));
			if (slot == null || function == null) throw new AssertionError(item.name + ": slot=" + slot + " function=" + function);
			var result = decompiler.decompileFunction(function, 60, monitor);
			if (!result.decompileCompleted()) throw new AssertionError(item.name + ": " + result.getErrorMessage());
			String c = result.getDecompiledFunction().getC();
			int store = c.indexOf("= 5;"), condition = c.indexOf("if (");
			println(item.name + ": slot " + slot + " inDelaySlot=" + slot.isInDelaySlot() + "\n" + c);
			if (store < 0 || condition < 0 || c.indexOf("= 5;", store + 1) >= 0)
				throw new AssertionError(item.name + ": expected one store and a condition in\n" + c);
			// Slot work runs on both paths, before the condition; work after the window, on one.
			if (item.first != store < condition || item.first != slot.isInDelaySlot())
				throw new AssertionError(item.name + ": expected the store " + (item.first ? "before" : "after") +
					" the condition, slot inDelaySlot=" + slot.isInDelaySlot() + ", in\n" + c);
			if (item.first) both++;
			else fallThrough++;
		}
		decompiler.dispose();
		println("C6000_PREDICATED_REGISTER_JUMP_OK both=" + both + " fallthrough=" + fallThrough);
	}
}
