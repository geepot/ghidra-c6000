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
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Issue #131: warn where a branch may be a return through a copy of the entry link that C6000 Link Copy Returns can't prove. */
public final class C6000LinkCopyWarningAnalyzer extends AbstractAnalyzer {
	public static final String CATEGORY = "C6000 Link Copy";

	public C6000LinkCopyWarningAnalyzer() {
		super("C6000 Link Copy Warnings",
			"Warns where a register branch that is not a proven return goes through the register its function copied its return address to",
			AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		// After calls, returns and jump tables are final.
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after().after().after().after().after());
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
			for (Instruction branch : program.getListing().getInstructions(function.getBody(), true)) {
				var flow = C6000PacketStagingAnalyzer.flow(branch);
				if (C6000PacketStagingAnalyzer.inert(branch) || branch.getFlowOverride() != FlowOverride.NONE ||
					!flow.isComputed() || !flow.isJump() || branch.getFlows().length > 0 || !walker.mayHoldEntryLink(branch)) continue;
				bookmarks.setBookmark(branch.getMinAddress(), BookmarkType.WARNING, CATEGORY, branch +
					" goes through the register " + function.getName() + " copied its return address to, but a call may change it" +
					" or the copy issues with the first branch, so it is not proven to return: " + function.getName() +
					" may decompile wrongly (issue #131)");
				warned++;
			}
		}
		if (warned > 0) Msg.info(this, getName() + "> " + warned + " warning(s)");
		return true;
	}
}
