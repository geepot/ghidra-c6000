// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// A change 2 KB from a branch that still changes its delay window: the pass right after the
// change must lay the window, not leave it to the confirming pass at the end of analysis.
// See tests/fixtures/far-entry.py.
// Usage: C6000FarEntryTest.java <cases.json>

import java.nio.file.Files;
import java.nio.file.Paths;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import c6000.C6000DelaySlots;
import c6000.C6000PacketContext;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

public class C6000FarEntryTest extends GhidraScript {
	private Address at(ProgramDB program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private void check(boolean condition, String message) {
		if (!condition) throw new AssertionError(message);
	}

	private void disassemble(ProgramDB program, long from, long to) {
		Address start = at(program, from);
		new DisassembleCommand(start, new AddressSet(start, at(program, to)), true).applyTo(program, TaskMonitor.DUMMY);
	}

	/** The delay-slot bytes laid behind the branch; -1 when it is gone. */
	private int window(ProgramDB program, Address branch) {
		Instruction insn = program.getListing().getInstructionAt(branch);
		return insn == null ? -1 : insn.getPrototype().getDelaySlotByteCount();
	}

	@Override
	protected void run() throws Exception {
		JsonObject row = JsonParser.parseString(Files.readString(Paths.get(getScriptArgs()[0]))).getAsJsonObject();
		var block = currentProgram.getMemory().getBlock(toAddr(0x1000));
		byte[] image = new byte[(int) block.getSize()];
		block.getBytes(block.getStart(), image);

		// A fresh program, so change tracking and read sets start with it.
		var program = new ProgramDB("far-entry", currentProgram.getLanguage(),
			currentProgram.getLanguage().getDefaultCompilerSpec(), this);
		try {
			int transaction = program.startTransaction("Import");
			var ram = program.getMemory().createInitializedBlock("ram", at(program, 0x1000), image.length, (byte) 0,
				monitor, false);
			program.getMemory().setBytes(ram.getStart(), image);
			C6000PacketContext.prime(program, monitor);
			program.endTransaction(transaction, true);

			transaction = program.startTransaction("Auto Analysis");
			for (var range : row.getAsJsonArray("code"))
				disassemble(program, range.getAsJsonArray().get(0).getAsLong(), range.getAsJsonArray().get(1).getAsLong());
			Address branch = at(program, row.get("branch").getAsLong()), label = at(program, row.get("label").getAsLong());
			Address jump = at(program, row.get("jump").getAsLong());
			Instruction b = program.getListing().getInstructionAt(branch);
			check(b != null && b.getMnemonicString().startsWith("B"), "no B at " + branch + ": " + b);
			boolean enters = false;
			for (Reference ref : program.getReferenceManager().getReferencesFrom(jump))
				enters |= ref.getToAddress().equals(label) && ref.getReferenceType().isJump();
			check(enters, "the jump at " + jump + " does not enter " + label);
			// As if an analyzer took it for a tail call: lay() refuses the window while B3 is set.
			b.setFlowOverride(FlowOverride.CALL_RETURN);

			// Recover until a pass changes nothing, so the next pass sees only the change below: the first
			// pass's own windows (the callee's, at 1000) lie near the B and would select it anyway.
			var log = new MessageLog();
			int passes = 0;
			while (passes < 8) {
				long before = program.getModificationNumber();
				passes++;
				if (C6000DelaySlots.recover(program, TaskMonitor.DUMMY, log).isEmpty() && program.getModificationNumber() == before) break;
			}
			check(passes < 8, "recovery did not settle in 8 passes");
			int first = window(program, branch);
			check(first == 0, "the first pass laid " + first + " byte(s) behind " + branch +
				", though B3 holds the link on both ways into " + label);

			// The far jump's link changes: B3 is no longer known when the B lands.
			long[] patch = { row.getAsJsonArray("patch").get(0).getAsLong(), row.getAsJsonArray("patch").get(1).getAsLong() };
			Address patched = at(program, patch[0]);
			program.getListing().clearCodeUnits(patched, patched.add(3), false);
			program.getMemory().setInt(patched, (int) patch[1]);
			disassemble(program, patch[0], patch[0] + 3);
			check(program.getListing().getInstructionAt(patched) != null, "no instruction at " + patched + " after the change");

			C6000DelaySlots.recover(program, TaskMonitor.DUMMY, log);
			int next = window(program, branch);
			C6000DelaySlots.confirm(program, TaskMonitor.DUMMY, log);
			int confirmed = window(program, branch);
			program.endTransaction(transaction, true);

			println("CASE far-entry passes=" + passes + " first=" + first + " next=" + next + " confirmed=" + confirmed);
			check(confirmed > 0, "no window behind " + branch + " even after the confirming pass");
			check(next > 0, "the pass after the change at " + patched + " left the window behind " + branch +
				" to the confirming pass: it did not re-prove the branch whose look-back the jump at " + jump + " enters");
			println("C6000_FAR_ENTRY_OK window=" + next + " byte(s), laid by the pass after the change");
		}
		finally {
			program.release(this);
		}
	}
}
