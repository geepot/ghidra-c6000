// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check delay windows entered from outside in a tests/fixtures/entered-window.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000DelaySlots;
import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class C6000EnteredWindowTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x1000L, 0x1040L, 0x1074L, 0x10acL, 0x10b8L };
	private static final String[] NAMES = { "rentry", "dentry", "rplain", "sink", "dmany" };
	private static final long[] MANY = { 0x10c8L, 0x10e8L, 0x1108L, 0x1128L, 0x1148L };

	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x1000L));
			C6000PacketContext.prime(currentProgram, monitor);
			for (int i = 0; i < ENTRIES.length; i++) {
				disassemble(toAddr(ENTRIES[i]));
				createFunction(toAddr(ENTRIES[i]), NAMES[i]);
			}
			return;
		}
		// Known-good: one entered window is re-read with a warning and decompiles correctly,
		// so it keeps its window (issue #52). rentry is a ? a + 1 : sink(6); dentry is
		// a ? a + 20 : b ? 15 : 21 (SPRUFE8B 3.5, 4.2.6).
		windowed(0x1018L);
		windowed(0x1050L);
		windowed(0x1084L);
		expect(0x1000L, "sink(6)");
		expect(0x1040L, "0xf");
		// Five entered windows in one function: Ghidra 12.2 counts each overlap as bad data
		// and abandons the function after four, so exactly one window is released there.
		// Earlier versions only warn, and nothing is released.
		boolean counted = countsOverlaps();
		int released = 0;
		for (long at : MANY) {
			if (isReleased(at)) {
				released++;
				Instruction b = getInstructionAt(toAddr(at));
				if (b == null || b.getDelaySlotDepth() != 0 || !jumpsTo(b, at + 0x18)) {
					throw new AssertionError("released window at " + toAddr(at) + ": " + describe(b));
				}
			}
			else windowed(at);
		}
		if (released != (counted ? 1 : 0)) {
			throw new AssertionError("released " + released + " of dmany's windows; decompiler counts overlaps: " + counted);
		}
		expect(0x10b8L, "");
		// Stable: nothing more to release, and recovery does not lay a released window again.
		if (C6000DelaySlots.relieveOverlaps(currentProgram, currentProgram.getMemory(), monitor) != 0) {
			throw new AssertionError("second release pass changed a window");
		}
		C6000DelaySlots.recover(currentProgram, monitor, new MessageLog());
		for (long at : MANY) {
			Instruction b = getInstructionAt(toAddr(at));
			if (isReleased(at) && b.getDelaySlotDepth() != 0) throw new AssertionError("re-laid " + describe(b));
		}
		println("C6000_ENTERED_WINDOW_OK checks=" + (12 + released) + " counted=" + counted);
	}

	/** Ghidra 12.2 added the bad-data limit that overlaps count toward (GP-6945). */
	private static boolean countsOverlaps() {
		try {
			DecompileOptions.class.getMethod("getMaxBadData");
			return true;
		}
		catch (NoSuchMethodException e) {
			return false;
		}
	}

	private boolean isReleased(long at) {
		return currentProgram.getBookmarkManager().getBookmark(toAddr(at), BookmarkType.ANALYSIS,
			C6000DelaySlots.RELEASED) != null;
	}

	/** The branch keeps its five-slot native window. */
	private void windowed(long at) {
		Instruction b = getInstructionAt(toAddr(at));
		if (b == null || b.getDelaySlotDepth() != 5 || isReleased(at)) {
			throw new AssertionError("window at " + toAddr(at) + ": " + describe(b));
		}
	}

	/** The function decompiles and its C contains text. */
	private void expect(long entry, String text) throws Exception {
		DecompInterface decompiler = new DecompInterface();
		decompiler.setOptions(new DecompileOptions());
		decompiler.openProgram(currentProgram);
		try {
			var result = decompiler.decompileFunction(getFunctionAt(toAddr(entry)), 30, monitor);
			if (result == null || !result.decompileCompleted()) {
				throw new AssertionError("decompile " + toAddr(entry) + ": " + (result == null ? null : result.getErrorMessage()));
			}
			String c = result.getDecompiledFunction().getC();
			if (!c.contains(text)) throw new AssertionError(toAddr(entry) + " lacks " + text + ":\n" + c);
		}
		finally {
			decompiler.dispose();
		}
	}

	private boolean jumpsTo(Instruction b, long target) {
		for (Reference r : b.getReferencesFrom()) {
			if (r.getReferenceType().isJump() && r.getToAddress().equals(toAddr(target))) return true;
		}
		return false;
	}

	private static String describe(Instruction i) {
		if (i == null) return "null";
		StringBuilder refs = new StringBuilder();
		for (Reference r : i.getReferencesFrom()) refs.append(' ').append(r.getReferenceType()).append(':').append(r.getToAddress());
		return i + " flow=" + i.getFlowType() + " override=" + i.getFlowOverride() + " fallthrough=" +
			i.getFallThrough() + " depth=" + i.getDelaySlotDepth() + " refs=" + refs;
	}
}
