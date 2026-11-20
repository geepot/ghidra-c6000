// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check both arms of an if/else call pair to two functions in an auto-analysed
// tests/fixtures/far-call-pair.py image. Run as preScript with "prepare", then as postScript.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class C6000FarCallPairTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			// The callees are known entries, as symbols would make them.
			for (long entry : new long[] { 0x1100L, 0x1200L, 0x1000L }) {
				currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(entry));
				disassemble(toAddr(entry));
				createFunction(toAddr(entry), null);
			}
			return;
		}
		for (long[] arm : new long[][] { { 0x1008L, 0x1100L }, { 0x100cL, 0x1200L } }) {
			Instruction branch = getInstructionAt(toAddr(arm[0]));
			if (branch == null || !branch.getFlowType().isCall() || !calls(branch, arm[1])) {
				throw new AssertionError("arm at " + toAddr(arm[0]) + ": " + branch +
					(branch == null ? "" : " flow=" + branch.getFlowType()));
			}
		}
		println("C6000_FAR_CALL_PAIR_OK");
	}

	private boolean calls(Instruction branch, long target) {
		for (Reference ref : branch.getReferencesFrom()) {
			if (ref.getReferenceType().isCall() && ref.getToAddress().getOffset() == target) return true;
		}
		return false;
	}
}
