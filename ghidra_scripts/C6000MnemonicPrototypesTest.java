// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Decode the image from tests/fixtures/mnemonic-prototypes.py at 0x1000 and check that a
// mnemonic depends only on its instruction's prototype. C6000CallAnalyzer.mnemonic() keeps one
// mnemonic per prototype; a constructor that prints operand text in its mnemonic would make the
// first instruction asked answer for all the others, and analysis results depend on the order of
// the questions.

import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.TreeMap;

import c6000.C6000PacketContext;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.listing.Instruction;

public class C6000MnemonicPrototypesTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		C6000PacketContext.prime(currentProgram, monitor);
		AddressSetView memory = currentProgram.getMemory().getLoadedAndInitializedAddressSet();
		Address cursor = memory.getMinAddress(), end = memory.getMaxAddress();
		while (cursor != null && cursor.compareTo(end) <= 0) {
			monitor.checkCancelled();
			Instruction insn = currentProgram.getListing().getInstructionAt(cursor);
			if (insn == null) {
				new DisassembleCommand(cursor, memory, false).applyTo(currentProgram, monitor);
				insn = currentProgram.getListing().getInstructionAt(cursor);
			}
			int step = insn != null ? insn.getLength() :
				BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(
					currentProgram.getRegister("c_is16"), cursor, false)) ? 2 : 4;
			cursor = cursor.addNoWrap(step);
			if (cursor.getOffset() == 0) break;
		}

		Method cached = Class.forName("c6000.C6000CallAnalyzer").getDeclaredMethod("mnemonic", Instruction.class);
		cached.setAccessible(true);
		Map<InstructionPrototype, Instruction> first = new IdentityHashMap<>();
		Map<InstructionPrototype, String> printed = new IdentityHashMap<>();
		Map<String, String> failures = new TreeMap<>();
		int instructions = 0, compact = 0;
		for (Instruction insn : currentProgram.getListing().getInstructions(true)) {
			String text = insn.getMnemonicString();
			if (text.equals("BAD-Instruction")) continue;
			instructions++;
			if (insn.getLength() == 2) compact++;
			String at = insn.getMinAddress() + " " + insn;
			if (text.indexOf(' ') >= 0 || text.indexOf(',') >= 0)
				failures.putIfAbsent("operand text in mnemonic '" + text + "'", at);
			Instruction seen = first.putIfAbsent(insn.getPrototype(), insn);
			String before = printed.putIfAbsent(insn.getPrototype(), text);
			if (seen != null && !before.equals(text))
				failures.putIfAbsent("one prototype prints '" + before + "' and '" + text + "'",
					seen.getMinAddress() + " " + seen + " / " + at);
			// The cached answer, asked in listing order, must be the instruction's own.
			String answer = (String) cached.invoke(null, insn);
			if (!answer.equals(text))
				failures.putIfAbsent("mnemonic() answers '" + answer + "' for '" + text + "'", at);
		}
		if (compact < 50_000)
			throw new AssertionError("only " + compact + " compact instructions decoded");
		if (instructions - compact < 20_000)
			throw new AssertionError("only " + (instructions - compact) + " 32-bit instructions decoded");
		if (!failures.isEmpty()) {
			StringBuilder report = new StringBuilder(failures.size() + " mnemonic failure(s):");
			// The first 40 in text order; one broken constructor gives a failure per operand value.
			failures.entrySet().stream().limit(40)
				.forEach(e -> report.append("\n  ").append(e.getKey()).append(" at ").append(e.getValue()));
			throw new AssertionError(report.toString());
		}
		println("C6000_MNEMONIC_PROTOTYPES_OK " + instructions + " instructions, " + compact + " compact, " +
			first.size() + " prototypes");
	}
}
