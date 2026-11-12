// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check delay windows entered only at their NOP slots in a tests/fixtures/entered-idle-tail.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import c6000.C6000DelaySlots;
import c6000.C6000PacketContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;

public class C6000EnteredIdleTailTest extends GhidraScript {
	// Four [A2] B s and one B B3, each with slots ADD, ADD, ADD, NOP 2; the NOP 2 is entered.
	private static final long[] WINDOWS = { 0x1010L, 0x102cL, 0x1048L, 0x1064L, 0x1080L };
	// busy's five [A2] B t, each with slots ADD, NOP, ADD, ADD, ADD; the NOP is entered, so ADDs follow it.
	private static final long[] BUSY = { 0x10d0L, 0x10f0L, 0x1110L, 0x1130L, 0x1150L };

	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x1000L));
			C6000PacketContext.prime(currentProgram, monitor);
			disassemble(toAddr(0x1000L));
			createFunction(toAddr(0x1000L), "idle");
			disassemble(toAddr(0x10c0L));
			createFunction(toAddr(0x10c0L), "busy");
			return;
		}
		// Ghidra 12.2 abandons idle on its fifth overlap: issue #52 must give up one window's
		// entered NOP slots, never its ADDs. Earlier versions only warn, and nothing changes.
		boolean counted = countsOverlaps();
		// idle(a, b, c) is b ? a : a + 15 whatever c: a released window would drop
		// its ADDs on one path (a + 12, or a test of c).
		String c = decompile();
		String body = c.substring(c.indexOf('{'));
		if (!c.contains("0xf") || c.contains("0xc") || body.contains("param_3")) {
			throw new AssertionError("idle is not b ? a : a + 15:\n" + c);
		}
		int ended = 0;
		for (long at : WINDOWS) {
			Instruction b = getInstructionAt(toAddr(at));
			if (b == null) throw new AssertionError("no branch at " + toAddr(at));
			if (isMarked(at)) {
				ended++;
				if (b.getDelaySlotDepth() != 3 || getInstructionAt(toAddr(at + 16)) == null ||
					getInstructionAt(toAddr(at + 16)).isInDelaySlot()) {
					throw new AssertionError("window at " + toAddr(at) + " must end before its NOP 2: " + b +
						" depth=" + b.getDelaySlotDepth());
				}
			}
			else if (b.getDelaySlotDepth() != 4) {
				throw new AssertionError("window at " + toAddr(at) + ": " + b + " depth=" + b.getDelaySlotDepth());
			}
		}
		if (ended != (counted ? 1 : 0)) {
			throw new AssertionError("ended " + ended + " windows early; decompiler counts overlaps: " + counted);
		}
		// A window whose entered NOP has other slots after it is released whole, as before.
		int released = 0;
		for (long at : BUSY) {
			Instruction b = getInstructionAt(toAddr(at));
			if (b == null) throw new AssertionError("no branch at " + toAddr(at));
			int depth = isMarked(at) ? 0 : 5;
			if (isMarked(at)) released++;
			if (b.getDelaySlotDepth() != depth) {
				throw new AssertionError("busy window at " + toAddr(at) + ": " + b + " depth=" + b.getDelaySlotDepth() +
					" expected=" + depth);
			}
		}
		if (released != (counted ? 1 : 0)) {
			throw new AssertionError("released " + released + " of busy's windows; decompiler counts overlaps: " + counted);
		}
		// Stable: nothing more to change, and recovery keeps the shorter window.
		if (C6000DelaySlots.relieveOverlaps(currentProgram, currentProgram.getMemory(), monitor) != 0) {
			throw new AssertionError("second relief pass changed a window");
		}
		C6000DelaySlots.recover(currentProgram, monitor, new MessageLog());
		for (long at : WINDOWS) {
			if (isMarked(at) && getInstructionAt(toAddr(at)).getDelaySlotDepth() != 3) {
				throw new AssertionError("re-laid " + getInstructionAt(toAddr(at)));
			}
		}
		println("C6000_ENTERED_IDLE_TAIL_OK checks=" + (WINDOWS.length + BUSY.length + 4) + " ended=" + ended +
			" released=" + released);
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

	private boolean isMarked(long at) {
		return currentProgram.getBookmarkManager().getBookmark(toAddr(at), BookmarkType.ANALYSIS,
			C6000DelaySlots.RELEASED) != null;
	}

	private String decompile() throws Exception {
		DecompInterface decompiler = new DecompInterface();
		decompiler.setOptions(new DecompileOptions());
		decompiler.openProgram(currentProgram);
		try {
			var result = decompiler.decompileFunction(getFunctionAt(toAddr(0x1000L)), 30, monitor);
			if (result == null || !result.decompileCompleted()) {
				throw new AssertionError("decompile idle: " + (result == null ? null : result.getErrorMessage()));
			}
			return result.getDecompiledFunction().getC();
		}
		finally {
			decompiler.dispose();
		}
	}
}
