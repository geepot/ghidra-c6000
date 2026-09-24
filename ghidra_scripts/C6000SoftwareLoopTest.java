// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Run after disassembly to verify software-loop pairing and inspect examples.

import c6000.C6000SoftwareLoops;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class C6000SoftwareLoopTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		int existing = 0;
		InstructionIterator before = currentProgram.getListing().getInstructions(true);
		while (before.hasNext()) {
			Instruction insn = before.next();
			if (!insn.getMnemonicString().contains("SPLOOP")) continue;
			for (Bookmark bookmark : currentProgram.getBookmarkManager().getBookmarks(
					insn.getMinAddress())) {
				if (bookmark.getCategory().equals("C6000 Software Loop")) existing++;
			}
		}
		println("C6000_LOOPS_PREEXISTING " + existing);
		C6000SoftwareLoops.Result result = C6000SoftwareLoops.annotate(
			currentProgram, currentProgram.getMemory(), monitor);
		println("C6000_LOOPS paired=" + result.paired + " masks=" + result.masked +
			" unmatched=" + result.unmatched);
		int shown = 0;
		int unpairedShown = 0;
		InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
		while (instructions.hasNext()) {
			Instruction insn = instructions.next();
			String mnemonic = insn.getMnemonicString();
			if (!mnemonic.contains("SPLOOP") && !mnemonic.contains("SPKERNEL")) {
				continue;
			}
			boolean paired = false;
			for (Bookmark bookmark : currentProgram.getBookmarkManager().getBookmarks(
					insn.getMinAddress())) {
				if (bookmark.getCategory().equals("C6000 Software Loop")) {
					paired = true;
					if (mnemonic.contains("SPLOOP") && shown < 8) {
						println("C6000_LOOP_EXAMPLE " + insn.getMinAddress() + " " +
							insn + " => " + bookmark.getComment());
						shown++;
					}
				}
			}
			if (!paired && unpairedShown++ < 40) {
				StringBuilder gaps = new StringBuilder();
				if (mnemonic.contains("SPLOOP")) {
					Instruction previous = insn;
					for (Instruction next = currentProgram.getListing().getInstructionAfter(
							insn.getMinAddress()); next != null &&
							next.getMinAddress().subtract(insn.getMinAddress()) < 1024;
							next = currentProgram.getListing().getInstructionAfter(next.getMinAddress())) {
						long gap = next.getMinAddress().subtract(previous.getMaxAddress()) - 1;
						if (gap > 0) gaps.append(" ").append(previous.getMaxAddress()).append("+").append(gap);
						if (next.getMnemonicString().contains("SPKERNEL")) break;
						previous = next;
					}
				}
				println("C6000_LOOP_UNPAIRED " + insn.getMinAddress() + " " + insn + " gaps=" + gaps);
			}
		}
	}
}
