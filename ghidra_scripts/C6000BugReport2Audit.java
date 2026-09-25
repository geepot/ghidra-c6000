// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Inspect the residual flow errors and function merge reported for stage 2.

import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class C6000BugReport2Audit extends GhidraScript {
	@Override
	protected void run() throws Exception {
		Iterator<Bookmark> errors = currentProgram.getBookmarkManager().getBookmarksIterator("Error");
		while (errors.hasNext()) {
			Bookmark bookmark = errors.next();
			println("C6000_ERROR " + bookmark.getAddress() + " " + bookmark.getComment());
		}
		for (long addr : new long[] {0xc001dd80L, 0xc001d1f4L, 0xc001d1f6L,
			0xc0032be8L, 0xc0032beaL, 0xc0005890L, 0xc0005892L}) {
			Instruction instruction = currentProgram.getListing().getInstructionAt(toAddr(addr));
			Function function = currentProgram.getFunctionManager().getFunctionContaining(toAddr(addr));
			println("C6000_AT " + toAddr(addr) + " instruction=" + instruction +
				" function=" + (function == null ? "<none>" : function.getEntryPoint()));
		}
		for (long addr : new long[] {0xc001dd80L, 0xc003cb80L, 0xc0008c44L}) {
			Function function = currentProgram.getFunctionManager().getFunctionAt(toAddr(addr));
			if (function != null) {
				println("C6000_FUNCTION_SIZE " + function.getEntryPoint() +
					" addresses=" + function.getBody().getNumAddresses() +
					" ranges=" + function.getBody().getNumAddressRanges());
				InstructionIterator instructions = currentProgram.getListing().getInstructions(
					function.getBody(), true);
				while (instructions.hasNext() && addr == 0xc003cb80L) {
					Instruction instruction = instructions.next();
					println("C6000_FUNCTION_INSN " + instruction.getAddress() + " " + instruction +
						" flow=" + instruction.getFlowType() + " override=" +
						instruction.getFlowOverride() + " delay=" + instruction.getDelaySlotDepth() +
						" pcode=" + instruction.getPcode().length);
				}
			}
		}
	}
}
