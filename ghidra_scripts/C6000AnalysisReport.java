// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Report auto-analysis flow recovery without changing the program.

import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class C6000AnalysisReport extends GhidraScript {
	@Override
	protected void run() throws Exception {
		int instructions = 0;
		InstructionIterator iterator = currentProgram.getListing().getInstructions(true);
		while (iterator.hasNext()) {
			iterator.next();
			instructions++;
		}
		int constFlowErrors = 0;
		int errors = 0;
		Iterator<Bookmark> bookmarks =
			currentProgram.getBookmarkManager().getBookmarksIterator("Error");
		while (bookmarks.hasNext()) {
			Bookmark bookmark = bookmarks.next();
			errors++;
			if (bookmark.getComment().contains("non-existing memory at const:")) {
				constFlowErrors++;
			}
		}
		println("C6000_ANALYSIS instructions=" + instructions +
			" functions=" + currentProgram.getFunctionManager().getFunctionCount() +
			" errors=" + errors + " constFlowErrors=" + constFlowErrors);
		for (long offset : new long[] {0x11804280L, 0x118048a0L, 0x11804360L,
				0xc00052b8L, 0xc0012720L, 0xc0036d34L, 0xc0047758L}) {
			Instruction insn = currentProgram.getListing().getInstructionAt(toAddr(offset));
			println("C6000_ANALYSIS_AT " + toAddr(offset) + " function=" +
				currentProgram.getFunctionManager().getFunctionAt(toAddr(offset)) +
				" instruction=" + insn);
		}
	}
}
