// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check hand-written TI assembly labels in an auto-analysed tests/fixtures/elf-asm-label.py ELF.

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class C6000ElfAsmLabelTest extends GhidraScript {
	private final List<String> failures = new ArrayList<>();

	@Override
	protected void run() throws Exception {
		label(0x1014L, "a_else", 0x1000L);
		label(0x1018L, "a_join", 0x1000L);
		jump(0x100cL);
		label(0x1044L, "b_loop", 0x1040L);
		function(0x10a0L, "c_tail");
		call(0x10c8L, 0x1100L, "d_help");
		label(0x10d0L, "d_ret", 0x10c0L);
		function(0x1140L, "e_static");
		if (!failures.isEmpty()) throw new AssertionError(String.join("; ", failures));
		println("C6000_ELF_ASM_LABEL_OK");
	}

	private void jump(long at) {
		Instruction jump = getInstructionAt(toAddr(at));
		if (jump == null || jump.getFlowType().isCall() || jump.getFlowOverride() != FlowOverride.NONE) {
			failures.add("jump at " + toAddr(at) + ": " + jump +
				(jump == null ? "" : " flow=" + jump.getFlowType() + " override=" + jump.getFlowOverride()));
		}
	}

	private void label(long at, String name, long owner) {
		Function f = getFunctionContaining(toAddr(at));
		if (getFunctionAt(toAddr(at)) != null || f == null || !f.getEntryPoint().equals(toAddr(owner))) {
			failures.add("label " + name + " at " + toAddr(at) + " is not inside " + toAddr(owner) + ": " + f);
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
