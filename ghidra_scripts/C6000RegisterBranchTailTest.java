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
		// Past each delay window: never reached, so never decoded.
		for (long at : new long[] {0x1008, 0x100c, 0x1018, 0x101c, 0x1020, 0x103c, 0x1048, 0x104c, 0x1084, 0x1088}) {
			if (getInstructionAt(toAddr(at)) != null) failures.add("decoded past a delay window: " + getInstructionAt(toAddr(at)) + " at " + toAddr(at));
		}
		// Delay slots and the branches themselves stay.
		for (long at : new long[] {0x1000, 0x1004, 0x1010, 0x1014, 0x1040, 0x1044, 0x1080}) {
			if (getInstructionAt(toAddr(at)) == null) failures.add("missing instruction at " + toAddr(at));
		}
		for (long entry : new long[] {0x1040, 0x1080}) {
			Function owner = getFunctionContaining(toAddr(entry));
			if (owner != null && !owner.getEntryPoint().equals(toAddr(entry))) failures.add(toAddr(entry) + " is inside " + owner);
		}
		Function q1 = getFunctionAt(toAddr(0x1000));
		if (q1 == null || q1.getBody().contains(toAddr(0x1018)) || q1.getBody().contains(toAddr(0x1040)))
			failures.add("q1 body " + (q1 == null ? null : q1.getBody()));
		if (!failures.isEmpty()) throw new AssertionError(String.join("; ", failures));
		println("C6000_REGISTER_BRANCH_TAIL_OK");
	}
}
