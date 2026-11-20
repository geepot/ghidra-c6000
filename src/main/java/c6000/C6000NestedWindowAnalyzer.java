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
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Issues #64-#66: warn where native lifting cannot place a transfer, so a function's C may be wrong. */
public final class C6000NestedWindowAnalyzer extends AbstractAnalyzer {
	public static final String CATEGORY = "C6000 Nested Delay Window";

	public C6000NestedWindowAnalyzer() {
		super("C6000 Nested Delay Windows",
			"Warns where a branch is issued in another branch's delay window, or a predicated call returns to earlier code: native lifting gives wrong C there",
			AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		// After the windows, function bodies and issue #52 releases are final.
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after().after().after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C6000PacketContext.isC6000(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		var bookmarks = program.getBookmarkManager();
		var walker = new C6000CallAnalyzer.Walker(program);
		int warned = 0;
		for (Function function : program.getFunctionManager().getFunctions(set, true)) {
			monitor.checkCancelled();
			bookmarks.removeBookmarks(function.getBody(), BookmarkType.WARNING, CATEGORY, monitor);
			// An active reviewed schedule lifts every transfer in flight.
			if (C6000ProgramActions.hasActiveReview(program, function)) continue;
			for (Instruction branch : program.getListing().getInstructions(function.getBody(), true)) {
				monitor.checkCancelled();
				String op = C6000CallAnalyzer.baseName(branch);
				if (!op.startsWith("B") || op.startsWith("BITC") || op.startsWith("BITR") || continued(branch)) continue;
				// A continued jump's preempting return has a window cut where the jump lands.
				var preemption = walker.preempting(branch);
				if (preemption != null && continued(preemption.jump())) continue;
				Instruction inner = walker.nestedTransfer(branch);
				if (inner != null) {
					Address at = program.getListing().getInstructionAt(inner.getMinAddress()) != null ?
						inner.getMinAddress() : branch.getMinAddress();
					bookmarks.setBookmark(at, BookmarkType.WARNING, CATEGORY, inner + " at " + inner.getMinAddress() +
						" issues in the delay window of " + branch + " at " + branch.getMinAddress() +
						" and lands after it: native lifting cannot place it, so " + function.getName() +
						" may decompile wrongly (issue #64)");
					warned++;
				}
				Address back = walker.predicatedBackwardCall(branch);
				if (back != null) {
					bookmarks.setBookmark(branch.getMinAddress(), BookmarkType.WARNING, CATEGORY, branch +
						" is a predicated call that returns to " + back + ", at or before it: native lifting cannot give it" +
						" both that return and its not-taken fall-through, so " + function.getName() +
						" may decompile wrongly (issue #66)");
					warned++;
				}
			}
		}
		if (warned > 0) Msg.info(this, getName() + "> " + warned + " warning(s)");
		return true;
	}

	/** A jump continued past a return that preempts it (C6000DelaySlots.neutralise): its taken edge is gone. */
	private static boolean continued(Instruction branch) {
		for (Reference ref : branch.getReferencesFrom()) {
			if (ref.getReferenceType() == RefType.JUMP_OVERRIDE_UNCONDITIONAL && ref.isPrimary() &&
				ref.getToAddress().compareTo(branch.getMaxAddress()) > 0) return true;
		}
		return false;
	}
}
