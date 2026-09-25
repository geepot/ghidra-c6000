// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check B-with-B3 calls in an auto-analysed tests/fixtures/delayed-call.py image.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class C6000DelayedCallTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		for (long site : new long[] { 0x1008L, 0x1018L }) {
			Instruction call = getInstructionAt(toAddr(site));
			if (call == null || !call.getFlowType().isCall() ||
				!toAddr(site + 4).equals(call.getFallThrough())) {
				throw new AssertionError("call at " + toAddr(site) + ": " + call +
					(call == null ? "" : " flow=" + call.getFlowType() +
						" fallthrough=" + call.getFallThrough()));
			}
			boolean ref = false;
			for (Reference r : call.getReferencesFrom()) {
				ref |= r.getReferenceType().isCall() && r.getToAddress().equals(toAddr(0x1100L));
			}
			if (!ref) throw new AssertionError("no call reference to 0x1100 from " + toAddr(site));
		}
		for (long slot : new long[] { 0x100cL, 0x101cL, 0x1020L }) {
			if (getFunctionContaining(toAddr(slot)) == null ||
				!getFunctionContaining(toAddr(slot)).getEntryPoint().equals(toAddr(0x1000L))) {
				throw new AssertionError(toAddr(slot) + " is not in the caller");
			}
		}
		if (getFunctionAt(toAddr(0x1100L)) == null) {
			throw new AssertionError("callee 0x1100 is not a function");
		}
		println("C6000_DELAYED_CALL_OK");
	}
}
