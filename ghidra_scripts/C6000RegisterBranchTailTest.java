// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check an auto-analysed tests/fixtures/register-branch-tail.py image (issue #32).

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class C6000RegisterBranchTailTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		if (getScriptArgs()[0].equals("prepare")) {
			// Ghidra's entry-point analyzer defers several unvalidated raw entries;
			// mark these as the issue does, with a decoded entry and a function each.
			for (long entry : new long[] {0x1000, 0x1040, 0x1080}) {
				currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(entry));
				new DisassembleCommand(toAddr(entry), null, true).applyTo(currentProgram, monitor);
				createFunction(toAddr(entry), null);
			}
			return;
		}
		List<String> failures = new ArrayList<>();
		// Delay slots and the branches themselves stay.
		for (long at : new long[] {0x1000, 0x1004, 0x1010, 0x1014, 0x1040, 0x1044, 0x1080}) {
			if (getInstructionAt(toAddr(at)) == null) failures.add("missing instruction at " + toAddr(at));
		}
		for (long entry : new long[] {0x1040, 0x1080}) {
			Function owner = getFunctionContaining(toAddr(entry));
			if (owner != null && !owner.getEntryPoint().equals(toAddr(entry))) failures.add(toAddr(entry) + " is inside " + owner);
		}
		// Past each delay window: never reached, so in no function body. A decoded
		// tail may stay: in a raw image it is usually the next function.
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			for (long at : new long[] {0x1018, 0x1020, 0x1048, 0x1084}) {
				if (f.getBody().contains(toAddr(at))) failures.add(f + " body " + f.getBody() + " keeps " + toAddr(at));
			}
		}
		if (!failures.isEmpty()) throw new AssertionError(String.join("; ", failures));
		println("C6000_REGISTER_BRANCH_TAIL_OK");
	}
}
