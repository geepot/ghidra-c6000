// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check BNOP calls in a tests/fixtures/bnop-call.py image (issue #69).
// Run as preScript with "prepare CASES.json", then as postScript with CASES.json.

import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import java.nio.file.*;

public class C6000BnopCallTest extends GhidraScript {
	private static final class Case {
		String name;
		long entry, callee, ret, branch;
		boolean call;
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
				for (long at : new long[] { item.entry, item.callee }) {
					disassemble(toAddr(at));
					createFunction(toAddr(at), at == item.entry ? item.name : item.name + "_f");
				}
			}
			return;
		}
		var decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		int calls = 0, others = 0;
		for (var item : cases) {
			Instruction branch = getInstructionAt(toAddr(item.branch));
			if (branch == null) throw new AssertionError(item.name + ": no BNOP at " + toAddr(item.branch));
			String state = branch + " flow=" + branch.getFlowType() + " override=" + branch.getFlowOverride() +
				" fallthrough=" + branch.getFallThrough();
			println(item.name + ": " + state);
			if (!item.call) {
				// Known-bad: no return point after the window, so a jump or a tail call.
				if (branch.getFlowOverride() == FlowOverride.CALL || branch.getFallThrough() != null)
					throw new AssertionError(item.name + ": not a call, got " + state);
				others++;
				continue;
			}
			// Known-good: a call to the callee that returns past its window into the caller.
			boolean target = false;
			for (Reference ref : branch.getReferencesFrom())
				if (ref.getReferenceType().isCall() && ref.getToAddress().equals(toAddr(item.callee))) target = true;
			Function caller = getFunctionAt(toAddr(item.entry));
			Instruction ret = getInstructionAt(toAddr(item.ret));
			if (branch.getFlowOverride() != FlowOverride.CALL || branch.getFlowType().isTerminal() || !target ||
				!toAddr(item.ret).equals(branch.getFallThrough()) || ret == null || caller == null ||
				!caller.getBody().contains(toAddr(item.ret)))
				throw new AssertionError(item.name + ": expected a call to " + toAddr(item.callee) + " returning to " +
					toAddr(item.ret) + ", got " + state + " ret=" + ret + " caller=" + caller);
			var result = decompiler.decompileFunction(caller, 60, monitor);
			if (!result.decompileCompleted()) throw new AssertionError(item.name + ": " + result.getErrorMessage());
			String c = result.getDecompiledFunction().getC();
			if (!c.contains(item.name + "_f(")) throw new AssertionError(item.name + ": no call in\n" + c);
			calls++;
		}
		decompiler.dispose();
		println("C6000_BNOP_CALL_OK calls=" + calls + " others=" + others);
	}
}
