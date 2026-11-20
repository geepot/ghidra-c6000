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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
			// Nested pairs, outer then inner, chained where one's inner is another's outer: a pipelined
			// loop's prolog nests a branch in every cycle, and one warning per chain says as much.
			List<Instruction[]> pairs = new ArrayList<>();
			Map<Address, Address> chain = new HashMap<>();
			for (Instruction branch : program.getListing().getInstructions(function.getBody(), true)) {
				monitor.checkCancelled();
				String op = C6000CallAnalyzer.baseName(branch);
				if (!op.startsWith("B") || op.startsWith("BITC") || op.startsWith("BITR") || continued(branch)) continue;
				// A continued jump's preempting return has a window cut where the jump lands.
				var preemption = walker.preempting(branch);
				if (preemption != null && continued(preemption.jump())) continue;
				Instruction inner = walker.nestedTransfer(branch);
				// Lifted with no window, a branch whose delay cycles are idle when taken is exact: the
				// transfers it nests are not taken with it.
				if (inner != null && !branch.getFlowType().isCall() && !laid(program, branch) && walker.idleWhenTaken(branch))
					inner = null;
				if (inner != null) {
					pairs.add(new Instruction[] { branch, inner });
					chain.put(root(chain, inner.getMinAddress()), root(chain, branch.getMinAddress()));
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
			Map<Address, List<Instruction[]>> chains = new LinkedHashMap<>();
			for (Instruction[] pair : pairs)
				chains.computeIfAbsent(root(chain, pair[0].getMinAddress()), k -> new ArrayList<>()).add(pair);
			for (List<Instruction[]> links : chains.values()) {
				Instruction branch = links.get(0)[0], inner = links.get(0)[1];
				Address at = program.getListing().getInstructionAt(inner.getMinAddress()) != null ?
					inner.getMinAddress() : branch.getMinAddress();
				StringBuilder more = new StringBuilder();
				for (int i = 1; i < links.size(); i++) more.append(i == 1 ? "" : ", ").append(links.get(i)[1].getMinAddress());
				bookmarks.setBookmark(at, BookmarkType.WARNING, CATEGORY, inner + " at " + inner.getMinAddress() +
					" issues in the delay window of " + branch + " at " + branch.getMinAddress() +
					" and lands after it" + (links.size() > 1 ? ", and so do the transfers at " + more + " in the windows before them" : "") +
					": native lifting cannot place them, so " + function.getName() + " may decompile wrongly (issue #64)");
				warned++;
			}
		}
		if (warned > 0) Msg.info(this, getName() + "> " + warned + " warning(s)");
		return true;
	}

	private static Address root(Map<Address, Address> chain, Address at) {
		for (Address up = chain.get(at); up != null && !up.equals(at); up = chain.get(at)) at = up;
		return at;
	}

	/** A native window past the branch's own execute packet. */
	private static boolean laid(Program program, Instruction branch) {
		try {
			return branch.getPrototype().getDelaySlotByteCount() > C6000ExecutionPackets.parallelBytes(program, branch.getAddress());
		}
		catch (ghidra.program.model.mem.MemoryAccessException e) {
			return true;
		}
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
