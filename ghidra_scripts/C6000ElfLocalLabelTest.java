// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check TI local labels in an auto-analysed tests/fixtures/elf-local-label.py ELF.

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class C6000ElfLocalLabelTest extends GhidraScript {
	private final List<String> failures = new ArrayList<>();

	@Override
	protected void run() throws Exception {
		jump(0x1004L);
		label(0x1020L, "$C$L1", 0x1000L);
		label(0x1028L, "$C$RL1", 0x1000L);
		label(0x1030L, "$C$RL2", 0x1000L);
		if (getInstructionAt(toAddr(0x1010L)) == null) failures.add("unreached label $C$RL3 at 0x1010 is not decoded");
		label(0x1010L, "$C$RL3", -1);
		function(0x10c0L, "h");
		function(0x10e0L, "$Tramp$S$$g");
		function(0x11e0L, "$C$L");
		function(0x1200L, "$C$L1a");
		call(0x1020L, 0x1100L, "g");
		call(0x1028L, 0x1140L, "$C$L2");
		if (!failures.isEmpty()) throw new AssertionError(String.join("; ", failures));
		println("C6000_ELF_LOCAL_LABEL_OK");
	}

	private void jump(long at) {
		Instruction jump = getInstructionAt(toAddr(at));
		if (jump == null || jump.getFlowType().isCall() || jump.getFlowOverride() != FlowOverride.NONE) {
			failures.add("jump at " + toAddr(at) + ": " + jump +
				(jump == null ? "" : " flow=" + jump.getFlowType() + " override=" + jump.getFlowOverride()));
		}
	}

	// owner < 0: only require that no function starts at the label
	private void label(long at, String name, long owner) {
		Function f = getFunctionContaining(toAddr(at));
		if (getFunctionAt(toAddr(at)) != null ||
			owner >= 0 && (f == null || !f.getEntryPoint().equals(toAddr(owner)))) {
			failures.add("label " + name + " at " + toAddr(at) +
				(owner < 0 ? " starts a function: " : " is not inside " + toAddr(owner) + ": ") + f);
		}
		boolean named = false;
		for (Symbol s : currentProgram.getSymbolTable().getSymbols(toAddr(at))) named |= s.getName().equals(name);
		if (!named) failures.add("label at " + toAddr(at) + " is not named " + name + ": " + getSymbolAt(toAddr(at)));
	}

	private void function(long at, String name) {
		Function f = getFunctionAt(toAddr(at));
		if (f == null || !f.getName().equals(name)) failures.add(name + " at " + toAddr(at) + " is not a function: " + f);
	}

	private void call(long at, long to, String name) {
		Instruction call = getInstructionAt(toAddr(at));
		boolean ref = false;
		for (Reference r : call == null ? new Reference[0] : call.getReferencesFrom()) {
			ref |= r.getReferenceType().isCall() && r.getToAddress().equals(toAddr(to));
		}
		if (!ref) failures.add("call at " + toAddr(at) + ": " + call + (call == null ? "" : " flow=" + call.getFlowType()));
		function(to, name);
	}
}
