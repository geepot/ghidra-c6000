// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Cancel delay-window recovery and release at each monitor check in turn. The enclosing
// transaction stands in for auto-analysis and must keep its earlier work; every window
// must be either as before or as after an uncancelled run.
// Usage: C6000DelayCancelTest.java <cases.json>

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import c6000.C6000DelaySlots;
import c6000.C6000PacketContext;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class C6000DelayCancelTest extends GhidraScript {
	private static final String PRIOR = "prior_analysis";

	/** Cancels on its n-th poll, checkCancelled or isCancelled; n = 0 never cancels. */
	private static final class CancelAt extends TaskMonitorAdapter {
		private final int target;
		private int checks;

		CancelAt(int target) {
			super(true);
			this.target = target;
		}

		@Override
		public boolean isCancelled() {
			if (++checks == target) cancel();
			return super.isCancelled();
		}

		@Override
		public void checkCancelled() throws CancelledException {
			if (isCancelled()) throw new CancelledException();
		}
	}

	private Address at(ProgramDB program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private ProgramDB load(byte[] image) throws Exception {
		var program = new ProgramDB("delay-cancel", currentProgram.getLanguage(),
			currentProgram.getLanguage().getDefaultCompilerSpec(), this);
		int transaction = program.startTransaction("Import");
		var block = program.getMemory().createInitializedBlock("ram", at(program, 0x1000),
			image.length, (byte) 0, monitor, false);
		program.getMemory().setBytes(block.getStart(), image);
		C6000PacketContext.prime(program, monitor);
		program.endTransaction(transaction, true);
		return program;
	}

	/** Earlier analysis: code, functions and a label, inside the open transaction. */
	private void prepare(ProgramDB program, JsonObject row) throws Exception {
		for (var range : row.getAsJsonArray("code")) {
			var r = range.getAsJsonArray();
			Address start = at(program, r.get(0).getAsLong());
			new DisassembleCommand(start, new AddressSet(start, at(program, r.get(1).getAsLong())), true)
				.applyTo(program, TaskMonitor.DUMMY);
		}
		for (var function : row.getAsJsonArray("functions")) {
			var f = function.getAsJsonArray();
			Address entry = at(program, f.get(1).getAsLong());
			long lo = f.get(2).getAsLong(), hi = f.get(3).getAsLong();
			if (hi == 0) {
				new CreateFunctionCmd(f.get(0).getAsString(), entry, null, SourceType.USER_DEFINED)
					.applyTo(program, TaskMonitor.DUMMY);
			}
			else {
				program.getFunctionManager().createFunction(f.get(0).getAsString(), entry,
					new AddressSet(at(program, lo), at(program, hi)), SourceType.USER_DEFINED);
			}
		}
		program.getSymbolTable().createLabel(first(program, row), PRIOR, SourceType.ANALYSIS);
		if (row.get("prepare").getAsBoolean()) C6000DelaySlots.recover(program, TaskMonitor.DUMMY, new MessageLog());
	}

	private Address first(ProgramDB program, JsonObject row) {
		return at(program, row.getAsJsonArray("code").get(0).getAsJsonArray().get(0).getAsLong());
	}

	/** Each window's instructions: extent, slot flag, native window, overrides and references. */
	private List<String> windows(ProgramDB program, JsonObject row) {
		List<String> result = new ArrayList<>();
		for (var window : row.getAsJsonArray("windows")) {
			var w = window.getAsJsonArray();
			var set = new AddressSet(at(program, w.get(0).getAsLong()), at(program, w.get(1).getAsLong()));
			StringBuilder text = new StringBuilder();
			for (Instruction i : program.getListing().getInstructions(set, true)) {
				text.append(i.getAddress()).append(' ').append(i).append(" len=").append(i.getLength())
					.append(" slot=").append(i.isInDelaySlot())
					.append(" delay=").append(i.getPrototype().getDelaySlotByteCount())
					.append(" override=").append(i.getFlowOverride());
				if (i.isFallThroughOverridden()) text.append(" fallthrough=").append(i.getFallThrough());
				for (Reference r : i.getReferencesFrom()) text.append(" ref=").append(r.getReferenceType())
					.append(':').append(r.getToAddress());
				text.append("; ");
			}
			result.add(text.toString());
		}
		return result;
	}

	private void check(boolean condition, String message) {
		if (!condition) throw new AssertionError(message);
	}

	/** Ghidra 12.2 added the bad-data limit that entered windows count toward (GP-6945). */
	private static boolean countsOverlaps() {
		try {
			DecompileOptions.class.getMethod("getMaxBadData");
			return true;
		}
		catch (NoSuchMethodException e) {
			return false;
		}
	}

	@Override
	protected void run() throws Exception {
		JsonArray cases = JsonParser.parseString(
			Files.readString(Paths.get(getScriptArgs()[0]))).getAsJsonArray();
		var block = currentProgram.getMemory().getBlock(toAddr(0x1000));
		byte[] image = new byte[(int) block.getSize()];
		block.getBytes(block.getStart(), image);
		int points = 0;
		for (var element : cases) {
			var row = element.getAsJsonObject();
			String name = row.get("name").getAsString(), change = row.get("change").getAsString();
			boolean fails = change.equals("fails");
			int checks = -1;
			List<String> before = null, after = null;
			// Run 0 counts the checks of an uncancelled run; run n cancels at check n.
			for (int target = 0; target == 0 || target <= checks; target++) {
				ProgramDB program = load(image);
				try {
					int analysis = program.startTransaction("Auto Analysis");
					prepare(program, row);
					var start = windows(program, row);
					if (before == null) before = start;
					check(start.equals(before), name + ": earlier analysis is not reproducible");
					var monitor = new CancelAt(target);
					Exception raised = null;
					try {
						if (row.get("run").getAsString().equals("recover")) {
							C6000DelaySlots.recover(program, monitor, new MessageLog());
						}
						else {
							C6000DelaySlots.relieveOverlaps(program, program.getMemory(), monitor);
						}
					}
					catch (Exception e) {
						raised = e;
					}
					var status = program.getCurrentTransactionInfo().getStatus().toString();
					program.endTransaction(analysis, true);
					String where = name + " cancel at check " + target + "/" + checks;
					check(!status.contains("ABORTED"), where + ": analyzer aborted the enclosing transaction");
					check(program.getListing().getInstructionAt(first(program, row)) != null,
						where + ": earlier analysis lost its instruction");
					check(!program.getSymbolTable().getGlobalSymbols(PRIOR).isEmpty(),
						where + ": earlier analysis lost its label");
					boolean cancelled = raised instanceof CancelledException;
					if (target > 0) {
						check(cancelled, where + ": cancellation not propagated" +
							(raised == null ? "" : " (" + raised + ")"));
					}
					else {
						check(!cancelled, where + ": cancellation raised without a cancel");
						check(fails == (raised != null), where + (fails ? ": failed write not reported" :
							": " + raised));
					}
					var now = windows(program, row);
					if (target == 0) {
						after = now;
						checks = monitor.checks;
						check(checks > 0, name + ": analyzer never checked for cancellation");
						int changed = 0;
						for (int i = 0; i < now.size(); i++) {
							if (!now.get(i).equals(before.get(i))) changed++;
						}
						int expected = change.equals("all") ? now.size() :
							change.equals("counted") ? (countsOverlaps() ? 1 : 0) : 0;
						for (int i = 0; fails && i < now.size(); i++) {
							check(now.get(i).equals(before.get(i)), name + ": failed write left window " + i +
								" changed (" + raised + "):\n before " + before.get(i) + "\n now    " + now.get(i));
						}
						check(changed == expected, name + ": changed " + changed + " of " + now.size() +
							" windows, expected " + expected);
						println("CASE " + name + " checks=" + checks + " changed=" + changed +
							(raised == null ? "" : " raised=" + raised));
					}
					else {
						for (int i = 0; i < now.size(); i++) {
							check(now.get(i).equals(before.get(i)) || now.get(i).equals(after.get(i)),
								where + ": window " + i + " half written:\n before " + before.get(i) +
									"\n after  " + after.get(i) + "\n now    " + now.get(i));
						}
						points++;
					}
				}
				finally {
					program.release(this);
				}
			}
		}
		println("C6000_DELAY_CANCEL_OK cases=" + cases.size() + " cancellation_points=" + points);
	}
}
