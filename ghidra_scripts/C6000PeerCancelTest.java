// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Cancel the packet-tail analyzer at each of its cancellation checks in turn. The
// enclosing transaction stands in for auto-analysis and must keep its earlier work.
// Usage: C6000PeerCancelTest.java <cases.json>

import java.nio.file.Files;
import java.nio.file.Paths;

import com.google.gson.JsonArray;
import com.google.gson.JsonParser;

import c6000.C6000CompactPacketTailAnalyzer;
import c6000.C6000PacketContext;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

public class C6000PeerCancelTest extends GhidraScript {
	private static final String PRIOR = "prior_analysis";

	/** Cancels on its n-th check; n = 0 never cancels. */
	private static final class CancelAt extends TaskMonitorAdapter {
		private final int target;
		private int checks;

		CancelAt(int target) {
			super(true);
			this.target = target;
		}

		@Override
		public void checkCancelled() throws CancelledException {
			if (++checks == target) cancel();
			super.checkCancelled();
		}
	}

	private Address at(ProgramDB program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private ProgramDB load(byte[] image) throws Exception {
		var program = new ProgramDB("peer-cancel", currentProgram.getLanguage(),
			currentProgram.getLanguage().getDefaultCompilerSpec(), this);
		int transaction = program.startTransaction("Import");
		var block = program.getMemory().createInitializedBlock("ram", at(program, 0x1000),
			image.length, (byte) 0, monitor, false);
		program.getMemory().setBytes(block.getStart(), image);
		C6000PacketContext.prime(program, monitor);
		program.endTransaction(transaction, true);
		return program;
	}

	private void disassemble(ProgramDB program, long offset) throws Exception {
		Address address = at(program, offset);
		var context = new ProcessorContextImpl(program.getLanguage());
		var value = program.getProgramContext().getRegisterValue(
			program.getLanguage().getContextBaseRegister(), address);
		if (value != null) context.setRegisterValue(value);
		var memory = new DumbMemBufferImpl(program.getMemory(), address);
		program.getListing().createInstruction(address,
			program.getLanguage().parse(memory, context, false), memory, context, 0);
	}

	private void check(boolean condition, String message) {
		if (!condition) throw new AssertionError(message);
	}

	@Override
	protected void run() throws Exception {
		JsonArray cases = JsonParser.parseString(
			Files.readString(Paths.get(getScriptArgs()[0]))).getAsJsonArray();
		var block = currentProgram.getMemory().getBlock(toAddr(0x1000));
		byte[] image = new byte[(int) block.getSize()];
		block.getBytes(block.getStart(), image);
		var analyzer = new C6000CompactPacketTailAnalyzer();
		int points = 0;
		for (var element : cases) {
			var row = element.getAsJsonObject();
			String name = row.get("name").getAsString();
			long anchor = row.get("anchor").getAsLong();
			var peers = row.getAsJsonArray("peers");
			int checks = -1;
			// Run 0 counts the checks of an uncancelled run; run n cancels at check n.
			for (int target = 0; target == 0 || target <= checks; target++) {
				ProgramDB program = load(image);
				try {
					int analysis = program.startTransaction("Auto Analysis");
					disassemble(program, anchor);
					program.getSymbolTable().createLabel(at(program, anchor), PRIOR, SourceType.ANALYSIS);
					var monitor = new CancelAt(target);
					boolean cancelled = false;
					try {
						analyzer.added(program, new AddressSet(at(program, anchor)), monitor, new MessageLog());
					}
					catch (CancelledException expected) {
						cancelled = true;
					}
					var status = program.getCurrentTransactionInfo().getStatus().toString();
					program.endTransaction(analysis, true);
					String where = name + " cancel at check " + target + "/" + checks;
					check(!status.contains("ABORTED"), where + ": analyzer aborted the enclosing transaction");
					check(program.getListing().getInstructionAt(at(program, anchor)) != null,
						where + ": earlier analysis lost its instruction");
					check(!program.getSymbolTable().getGlobalSymbols(PRIOR).isEmpty(),
						where + ": earlier analysis lost its label");
					check(cancelled == (target > 0), where + ": cancellation " +
						(cancelled ? "raised without a cancel" : "not propagated"));
					int created = 0;
					for (var peer : peers) {
						var instruction = program.getListing().getInstructionAt(
							at(program, peer.getAsJsonArray().get(0).getAsLong()));
						if (instruction == null) continue;
						check(instruction.getLength() == peer.getAsJsonArray().get(1).getAsInt(),
							where + ": peer width " + instruction);
						created++;
					}
					if (target == 0) {
						check(created == peers.size(), name + ": recovered " + created + " of " + peers.size() + " peers");
						checks = monitor.checks;
						check(checks > 0, name + ": analyzer never checked for cancellation");
					}
					else {
						points++;
					}
				}
				finally {
					program.release(this);
				}
			}
		}
		println("C6000_PEER_CANCEL_OK cases=" + cases.size() + " cancellation_points=" + points);
	}
}
