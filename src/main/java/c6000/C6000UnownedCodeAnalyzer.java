/* ###
 * Copyright 2026 ghidra-c6000 contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package c6000;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Decoded code that no function owns is never decompiled and never checked by the analyzers that
 * walk functions. Where nothing in the program calls it, jumps to it or names its address, nothing
 * says where a function starts in it either, so none is made: each run of such code gets a note at
 * its first instruction that is not padding, and making a function there is left to the user.
 */
public final class C6000UnownedCodeAnalyzer extends AbstractAnalyzer {
	public static final String CATEGORY = "C6000 Unowned Code";

	public C6000UnownedCodeAnalyzer() {
		super("C6000 Unowned Code", "Notes decoded code that belongs to no function",
			AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		// After C6000 Code Pointers has made the functions something names.
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C6000PacketContext.isC6000(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		var bookmarks = program.getBookmarkManager();
		var functions = program.getFunctionManager();
		bookmarks.removeBookmarks(BookmarkType.INFO, CATEGORY, monitor);
		Address start = null;
		Function into = null;
		Instruction last = null;
		boolean inRun = false;
		int count = 0, runs = 0;
		long bytes = 0;
		for (Instruction insn : program.getListing().getInstructions(true)) {
			monitor.checkCancelled();
			boolean owned = functions.getFunctionContaining(insn.getMinAddress()) != null;
			boolean follows = last != null && last.getMaxAddress().next().equals(insn.getMinAddress());
			if (inRun && (owned || !follows)) {
				if (start != null) { note(program, start, count, bytes, into); runs++; }
				inRun = false;
			}
			if (!owned) {
				if (!inRun) {
					inRun = true;
					start = null;
					count = 0;
					bytes = 0;
					// Who falls into it, if anyone.
					into = follows && last.getFlowType().hasFallthrough() ? functions.getFunctionContaining(last.getMinAddress()) : null;
				}
				// Padding and fetch-packet headers before the first real instruction are not counted.
				String name = C6000CallAnalyzer.baseName(insn);
				if (start == null && !name.startsWith("NOP") && !name.startsWith("CPKT")) start = insn.getMinAddress();
				if (start != null) {
					count++;
					bytes += insn.getLength();
				}
			}
			last = insn;
		}
		if (inRun && start != null) { note(program, start, count, bytes, into); runs++; }
		if (runs > 0) Msg.info(this, getName() + "> " + runs + " run(s) of code in no function");
		return true;
	}

	private static void note(Program program, Address at, int count, long bytes, Function into) {
		program.getBookmarkManager().setBookmark(at, BookmarkType.INFO, CATEGORY,
			count + " instruction(s), " + bytes + " bytes of decoded code from here on belong to no function" +
			(into != null ? ": code of " + into.getName() + " falls into it, though its body ends before" :
				": nothing in the program calls, jumps to or names this address") +
			". It is not decompiled or checked until a function is made");
	}
}
