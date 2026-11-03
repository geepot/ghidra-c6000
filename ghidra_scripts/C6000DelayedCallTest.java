// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check B-with-B3 calls in an auto-analysed tests/fixtures/delayed-call.py image.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class C6000DelayedCallTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		// The if/else pair is its own routine; the entry never reaches it.
		for (long entry : new long[] { 0x1040L, 0x1060L, 0x10a0L, 0x1140L, 0x1200L, 0x1280L,
			0x1300L, 0x1380L, 0x1400L, 0x1480L, 0x1500L, 0x1580L, 0x1600L, 0x1680L, 0x1700L,
			0x1780L, 0x1800L, 0x1880L, 0x1c00L, 0x1c40L, 0x1d00L, 0x1d80L, 0x1e00L, 0x1e80L, 0x1f00L, 0x1f80L,
			0x2000L, 0x2080L, 0x2100L }) {
			disassemble(toAddr(entry));
			createFunction(toAddr(entry), null);
		}
		analyzeChanges(currentProgram);
		// The near arm of a call-or-jump pair stays a jump.
		Instruction jump = getInstructionAt(toAddr(0x1068L));
		if (jump == null || jump.getFlowType().isCall() || !jump.getFlowType().isConditional() ||
			getFunctionAt(toAddr(0x1080L)) != null) {
			throw new AssertionError("jump arm at 0x1068: " + jump +
				(jump == null ? "" : " flow=" + jump.getFlowType()) +
				" function at 0x1080=" + getFunctionAt(toAddr(0x1080L)));
		}
		// A B3 set in a jump's delay slots for the call after it belongs to that call.
		for (long[] jt : new long[][] { { 0x10a0L, 0x10e0L }, { 0x1148L, 0x1180L }, { 0x120cL, 0x1240L },
			{ 0x1288L, 0x12c0L } }) {
			Instruction owner = getInstructionAt(toAddr(jt[0]));
			if (owner == null || owner.getFlowType().isCall() || !owner.getFlowType().isConditional() ||
				getFunctionAt(toAddr(jt[1])) != null) {
				throw new AssertionError("jump at " + toAddr(jt[0]) + ": " + owner +
					(owner == null ? "" : " flow=" + owner.getFlowType()) +
					" function at " + toAddr(jt[1]) + "=" + getFunctionAt(toAddr(jt[1])));
			}
		}
		// B3 past a B's window end is not its return address.
		Instruction slack = getInstructionAt(toAddr(0x1290L));
		if (slack == null || slack.getFlowType().isCall() || getFunctionAt(toAddr(0x12e0L)) != null) {
			throw new AssertionError("jump at 0x1290: " + slack +
				(slack == null ? "" : " flow=" + slack.getFlowType()) +
				" function at 0x12e0=" + getFunctionAt(toAddr(0x12e0L)));
		}
		// A window ending at a compact header returns to the next fetch packet.
		Instruction header = getInstructionAt(toAddr(0x1888L));
		if (header == null || !header.getFlowType().isCall() || !toAddr(0x188cL).equals(header.getFallThrough()) ||
			!calls(header, 0x1100L)) {
			throw new AssertionError("call at 0x1888: " + header +
				(header == null ? "" : " flow=" + header.getFlowType() + " fallthrough=" + header.getFallThrough()));
		}
		// B3 set before a conditional jump survives its fall-through to the call after it.
		// Its proven window ends at NOP 5, so it returns to B3 = 0x1158 (issue #34).
		Instruction after = getInstructionAt(toAddr(0x1150L));
		Function owner2 = getFunctionContaining(toAddr(0x1158L));
		if (after == null || !after.getFlowType().isCall() || !toAddr(0x1158L).equals(after.getFallThrough()) ||
			getFunctionAt(toAddr(0x11c0L)) == null || owner2 == null ||
			!owner2.getEntryPoint().equals(toAddr(0x1140L))) {
			throw new AssertionError("call at 0x1150: " + after +
				(after == null ? "" : " flow=" + after.getFlowType() + " fallthrough=" + after.getFallThrough()) +
				" callee 0x11c0=" + getFunctionAt(toAddr(0x11c0L)) + " 0x1158 in " + owner2);
		}
		// The generic SLEIGH predicate guard also gives unpredicated register
		// branches a conditional flow type. Require it for predicated calls only.
		// A displacement call with a proven window returns after it, at B3 (issue #34).
		// Register calls, and arms whose fifth slot holds another transfer, keep site+4.
		long[][] returns = { { 0x1008L, 0x100cL }, { 0x1018L, 0x1020L }, { 0x1048L, 0x104cL },
			{ 0x104cL, 0x1050L }, { 0x106cL, 0x1070L }, { 0x10b8L, 0x10bcL } };
		for (long[] pair : returns) {
			long site = pair[0];
			Instruction call = getInstructionAt(toAddr(site));
			if (call == null || !call.getFlowType().isCall() ||
				(site >= 0x1048L && site <= 0x106cL && !call.getFlowType().isConditional()) ||
				!toAddr(pair[1]).equals(call.getFallThrough())) {
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
		// A call nothing falls into gets its B3 through the one jump reaching it.
		for (long[] c : new long[][] { { 0x1308L, 0x1300L, 0x1348L }, { 0x1388L, 0x1380L, 0x13c8L },
			{ 0x1408L, 0x1400L, 0x1440L }, { 0x1488L, 0x1480L, 0x14c0L } }) {
			Instruction call = getInstructionAt(toAddr(c[0]));
			if (call == null || !call.getFlowType().isCall() || call.getFlowType().isTerminal() ||
				!returnPoint(call).equals(call.getFallThrough()) || !calls(call, 0x1100L)) {
				throw new AssertionError("call at " + toAddr(c[0]) + ": " + call +
					(call == null ? "" : " flow=" + call.getFlowType() + " fallthrough=" + call.getFallThrough()));
			}
			for (int i = 1; i < c.length; i++) {
				Instruction j = getInstructionAt(toAddr(c[i]));
				if (j == null || j.getFlowOverride() == FlowOverride.CALL) {
					throw new AssertionError("jump at " + toAddr(c[i]) + ": " + j +
						(j == null ? "" : " flow=" + j.getFlowType()));
				}
			}
		}
		// A slot under a fallen-through jump's own predicate does not run.
		Instruction viaFall = getInstructionAt(toAddr(0x1798L));
		if (viaFall == null || !viaFall.getFlowType().isCall() || viaFall.getFlowType().isTerminal() ||
			!calls(viaFall, 0x1100L)) {
			throw new AssertionError("call at 0x1798: " + viaFall +
				(viaFall == null ? "" : " flow=" + viaFall.getFlowType()));
		}
		Instruction unpredicated = getInstructionAt(toAddr(0x1818L));
		if (unpredicated == null || unpredicated.getFlowType().isCall()) {
			throw new AssertionError("not a call at 0x1818: " + unpredicated +
				(unpredicated == null ? "" : " flow=" + unpredicated.getFlowType()));
		}
		// Not when fallen into, reached twice, a return point, or reached by BNOP.
		Instruction control = getInstructionAt(toAddr(0x1690L));
		if (control == null || !control.getFlowType().isCall() || !calls(control, 0x1100L)) {
			throw new AssertionError("call at 0x1690: " + control);
		}
		for (long site : new long[] { 0x1508L, 0x158cL, 0x1608L, 0x1698L, 0x1708L }) {
			Instruction b = getInstructionAt(toAddr(site));
			if (b == null || b.getFlowOverride() == FlowOverride.CALL) {
				throw new AssertionError("not a call at " + toAddr(site) + ": " + b +
					(b == null ? "" : " flow=" + b.getFlowType() + " fallthrough=" + b.getFallThrough()));
			}
		}
		// Both arms of an if/else call pair return at the later arm's window end.
		for (long site : new long[] { 0x1c00L, 0x1c08L, 0x1c4cL, 0x1c58L }) {
			Instruction arm = getInstructionAt(toAddr(site));
			if (arm == null || !arm.getFlowType().isCall() || !returnPoint(arm).equals(arm.getFallThrough()) ||
				!calls(arm, 0x1100L)) {
				throw new AssertionError("pair arm at " + toAddr(site) + ": " + arm +
					(arm == null ? "" : " flow=" + arm.getFlowType() + " fallthrough=" + arm.getFallThrough()));
			}
		}
		// A write that keeps the call's predicate true leaves its slots straight-line.
		for (long site : new long[] { 0x1d08L, 0x1d88L, 0x1e08L, 0x1f08L, 0x2008L }) {
			Instruction call = getInstructionAt(toAddr(site));
			// Falls through to its parallel follower or to the next execute packet.
			if (call == null || !call.getFlowType().isCall() || call.getFlowType().isTerminal() ||
				!(returnPoint(call).equals(call.getFallThrough()) || toAddr(site + 8).equals(call.getFallThrough())) ||
				!calls(call, 0x1100L)) {
				throw new AssertionError("nullify call at " + toAddr(site) + ": " + call +
					(call == null ? "" : " flow=" + call.getFlowType() + " fallthrough=" + call.getFallThrough()));
			}
		}
		// Not calls: a nullified jump at another call's return, writes that may change the call's predicate.
		for (long site : new long[] { 0x1e14L, 0x1e88L, 0x1f88L, 0x2088L, 0x210cL }) {
			Instruction b = getInstructionAt(toAddr(site));
			if (b == null || b.getFlowOverride() == FlowOverride.CALL) {
				throw new AssertionError("not a call at " + toAddr(site) + ": " + b +
					(b == null ? "" : " flow=" + b.getFlowType() + " fallthrough=" + b.getFallThrough()));
			}
		}
		if (getFunctionAt(toAddr(0x1100L)) == null) {
			throw new AssertionError("callee 0x1100 is not a function");
		}
		println("C6000_DELAYED_CALL_OK");
	}

	/** The next instruction, or the end of a proven delay window (issue #34). */
	private Address returnPoint(Instruction call) {
		var delay = currentProgram.getProgramContext().getValue(
			currentProgram.getRegister("c_flow_delay"), call.getAddress(), false);
		return call.getMaxAddress().next().add(delay == null ? 0 : delay.longValue());
	}

	private static boolean calls(Instruction insn, long target) {
		for (Reference r : insn.getReferencesFrom()) {
			if (r.getReferenceType().isCall() && r.getToAddress().getOffset() == target) return true;
		}
		return false;
	}
}
