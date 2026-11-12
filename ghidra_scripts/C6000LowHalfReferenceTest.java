// SPDX-License-Identifier: Apache-2.0
// @category C6000
// MVK low-half references in a low-half-reference.py image: preScript "prepare", then postScript with no arguments.

import c6000.C6000PacketContext;
import ghidra.app.script.GhidraScript;

public class C6000LowHalfReferenceTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x1000L, 0x1024L, 0x1068L, 0x1080L, 0x10a0L };
	private static final String[] NAMES = { "f", "h", "g", "k", "m" };

	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(0x1000L));
			C6000PacketContext.prime(currentProgram, monitor);
			for (int i = 0; i < ENTRIES.length; i++) {
				disassemble(toAddr(ENTRIES[i]));
				createFunction(toAddr(ENTRIES[i]), NAMES[i]);
			}
			// The MVKHs past h's second jump and k's BNOP, and m's NOP 5 and MVKH, as code before analysis.
			disassemble(toAddr(0x1040L));
			disassemble(toAddr(0x1088L));
			disassemble(toAddr(0x10a8L));
			return;
		}
		// Known-good: completed to another address, in straight code and in a call's slots.
		expect(0x1000L, false);
		expect(0x1028L, false);
		// Known-bad: completed to the same address, read before the MVKH, a B or BNOP landing first, MVKH in cycle 6.
		expect(0x1008L, true);
		expect(0x1010L, true);
		expect(0x1040L, true);
		expect(0x1080L, true);
		expect(0x10a0L, true);
		println("C6000_LOW_HALF_REFERENCE_OK checks=7");
	}

	private void expect(long at, boolean kept) {
		if (getInstructionAt(toAddr(at)) == null) throw new AssertionError("no MVK at " + toAddr(at));
		boolean has = false;
		for (var r : getReferencesFrom(toAddr(at))) has |= r.getToAddress().equals(toAddr(0x1068L));
		if (has != kept) throw new AssertionError("MVK at " + toAddr(at) + (kept ? " lost" : " keeps") +
			" its reference to 00001068");
	}
}
