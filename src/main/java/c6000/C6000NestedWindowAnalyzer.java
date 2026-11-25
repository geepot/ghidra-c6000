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
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Issues #64-#66: warn where native lifting cannot place a transfer, so a function's C may be wrong. */
public final class C6000NestedWindowAnalyzer extends AbstractAnalyzer {
	public static final String CATEGORY = "C6000 Nested Delay Window";
	/** On a jump into another function's code that carries a {@link #CATEGORY} warning (issue #108). */
	public static final String ENTERED = "C6000 Nested Delay Window (entered)";

	public C6000NestedWindowAnalyzer() {
		super("C6000 Nested Delay Windows",
			"Warns where a branch is issued in another branch's delay window, or a predicated call returns to earlier code: native lifting gives wrong C there",
			AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		// After the windows, function bodies and issue #52 releases are final.
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
			// An active reviewed schedule lifts every transfer in flight.
			if (C6000ProgramActions.hasActiveReview(program, function)) continue;
			// Nested pairs, outer then inner, chained where one's inner is another's outer: a pipelined
			// loop's prolog nests a branch in every cycle, and one warning per chain says as much.
			List<Instruction[]> pairs = new ArrayList<>();
			Map<Address, Address> chain = new HashMap<>();
			Map<Address, String> reasons = new HashMap<>();
			for (Instruction branch : program.getListing().getInstructions(function.getBody(), true)) {
				monitor.checkCancelled();
				String op = C6000CallAnalyzer.baseName(branch);
				if (!op.startsWith("B") || op.startsWith("BITC") || op.startsWith("BITR")) continue;
				Instruction inner = walker.nestedTransfer(branch);
				// Nesting only matters where native lifting runs something other than the hardware.
				String why = inner == null ? null : walker.nativeMismatch(branch);
				if (why != null) {
					// Say why latching the branches (C6000 Nested Branch Lifting) does not fix it.
					var plan = walker.liftPlan(branch);
					String unlifted = plan == null ? walker.liftRefusal : walker.liftMismatch(plan, branch);
					if (unlifted != null) why += "; not lifted by latching because " + (plan == null ? unlifted : "then " + unlifted);
					// A plan that passed its check and was dropped all the same (issue #140).
					String dropped = unlifted == null ? C6000NestedLiftAnalyzer.dropped(program, branch.getMinAddress()) : null;
					if (dropped != null) why += "; a lifting by latching was planned and dropped because " + dropped;
					pairs.add(new Instruction[] { branch, inner });
					reasons.put(branch.getMinAddress(), why);
					chain.put(root(chain, inner.getMinAddress()), root(chain, branch.getMinAddress()));
				}
				// Latched, such a call lands as a call and then jumps to its return point.
				Address back = C6000PacketStagingAnalyzer.inert(branch) ? null : walker.predicatedBackwardCall(branch);
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
					(links.size() > 1 ? ", and so do the transfers at " + more + " in the windows before them" : "") +
					": " + reasons.get(branch.getMinAddress()) + ", so " + function.getName() +
					" may decompile wrongly (issue #64)");
				warned++;
			}
		}
		// The decompiler follows a jump into another function's code, so that code's warning is the
		// jumping function's too. Both ways round: these functions' own jumps out, and jumps in from others.
		java.util.Set<Function> jumpers = new java.util.LinkedHashSet<>();
		for (Function function : program.getFunctionManager().getFunctions(set, true)) {
			jumpers.add(function);
			var targets = program.getReferenceManager().getReferenceDestinationIterator(function.getBody(), true);
			while (targets.hasNext()) {
				monitor.checkCancelled();
				for (var ref : program.getReferenceManager().getReferencesTo(targets.next())) {
					Function from = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
					if (from != null && !from.equals(function) && ref.getReferenceType().isJump()) jumpers.add(from);
				}
			}
		}
		for (Function function : jumpers) {
			bookmarks.removeBookmarks(function.getBody(), BookmarkType.WARNING, ENTERED, monitor);
			for (Instruction jump : program.getListing().getInstructions(function.getBody(), true)) {
				for (var ref : jump.getReferencesFrom()) {
					if (!ref.getReferenceType().isJump()) continue;
					Function owner = program.getFunctionManager().getFunctionContaining(ref.getToAddress());
					if (owner == null || owner.equals(function)) continue;
					Address first = null;
					for (var it = bookmarks.getBookmarksIterator(owner.getEntryPoint(), true); it.hasNext();) {
						var mark = it.next();
						if (!owner.getBody().contains(mark.getAddress())) {
							if (mark.getAddress().compareTo(owner.getBody().getMaxAddress()) > 0) break;
							continue;
						}
						if (mark.getCategory().equals(CATEGORY)) { first = mark.getAddress(); break; }
					}
					if (first == null) continue;
					bookmarks.setBookmark(jump.getMinAddress(), BookmarkType.WARNING, ENTERED, jump + " jumps into " + owner.getName() +
						" at " + ref.getToAddress() + ", whose code has a nested delay window warning at " + first + ": " +
						function.getName() + " runs that code and may decompile wrongly too (issue #108)");
					warned++;
				}
			}
		}
		if (warned > 0) Msg.info(this, getName() + "> " + warned + " warning(s)");
		return true;
	}

	private static Address root(Map<Address, Address> chain, Address at) {
		for (Address up = chain.get(at); up != null && !up.equals(at); up = chain.get(at)) at = up;
		return at;
	}
}
