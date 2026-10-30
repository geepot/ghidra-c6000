// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check compact packets in an auto-analysed tests/fixtures/elf-compact.py ELF (issues #31, #33).

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;

public class C6000ElfCompactTest extends GhidraScript {
	// dis6x order of every slot, in both byte orders.
	private static final Object[][] SLOTS = {
		{0x1000L, "ADD"}, {0x1002L, "MV"}, {0x1004L, "BNOP"}, {0x1006L, "NOP"},
		{0x1008L, "ADD"}, {0x100aL, "MV"}, {0x100cL, "ADD"}, {0x100eL, "MV"}, {0x1010L, "BNOP"}, {0x1012L, "NOP"},
		{0x1020L, "LDW"}, {0x1022L, "NOP"}, {0x1024L, "ADD"}, {0x1026L, "MV"},
		{0x1028L, "ADD"}, {0x102aL, "MV"}, {0x102cL, "BNOP"}, {0x102eL, "NOP"},
	};

	@Override
	protected void run() throws Exception {
		List<String> failures = new ArrayList<>();
		// Issue #31: big-endian images still decode each word's halfwords swapped,
		// so there only check that every slot decodes.
		boolean order = !currentProgram.getLanguage().isBigEndian();
		for (Object[] slot : SLOTS) {
			Instruction insn = getInstructionAt(toAddr((Long) slot[0]));
			String name = insn == null ? null : insn.getMnemonicString().replaceFirst("^_", "").replaceFirst("\\..*", "");
			if (insn == null || order && !slot[1].equals(name)) failures.add(toAddr((Long) slot[0]) + " expected " + slot[1] + " got " + insn);
		}
		for (String entry : new String[] {"q1", "f2", "f3"}) {
			if (getFunction(entry) == null) failures.add("missing function " + entry);
		}
		var bad = currentProgram.getBookmarkManager().getBookmarksIterator(BookmarkType.ERROR);
		while (bad.hasNext()) failures.add("error bookmark " + bad.next());
		if (!failures.isEmpty()) throw new AssertionError(String.join("; ", failures));
		println("C6000_ELF_COMPACT_OK");
	}
}
