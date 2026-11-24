// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check nested-window warnings in a tests/fixtures/nested-window.py image (issues #64-#66).
// Run as preScript with "prepare CASES.json", then as postScript with CASES.json.

import c6000.C6000PacketContext;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import java.nio.file.*;
import java.util.*;

public class C6000NestedWindowTest extends GhidraScript {
	// C6000NestedWindowAnalyzer.CATEGORY, spelled out so the check also runs without the analyzer.
	private static final String CATEGORY = "C6000 Nested Delay Window";

	private static final class Case {
		String name;
		long entry, h, end;
		long[] warn;
		String[] c;
		long[] functions, labels, declare, entered;
		@com.google.gson.annotations.SerializedName("plain_at") long plainAt;
		String[] either, plain, absent;
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		boolean prepare = args.length == 2 && args[0].equals("prepare");
		if (!prepare && args.length != 1) throw new IllegalArgumentException("Expected [prepare] CASES.json");
		var cases = new com.google.gson.Gson().fromJson(Files.readString(Paths.get(args[args.length - 1])), Case[].class);
		if (prepare) {
			C6000PacketContext.prime(currentProgram, monitor);
			currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(cases[0].entry));
			for (var item : cases) {
				for (long at : new long[] { item.entry, item.h }) {
					disassemble(toAddr(at));
					createFunction(toAddr(at), at == item.entry ? item.name : item.name + "_h");
				}
				// More entries a symbol table or a seed list would give.
				if (item.declare != null) for (long at : item.declare) {
					disassemble(toAddr(at));
					createFunction(toAddr(at), null);
				}
			}
			return;
		}
		int warned = 0, clean = 0, lifted = 0;
		for (var item : cases) {
			Set<Long> found = new TreeSet<>();
			StringBuilder comments = new StringBuilder();
			var range = new AddressSet(toAddr(item.entry), toAddr(item.end));
			Iterator<Bookmark> bookmarks = currentProgram.getBookmarkManager().getBookmarksIterator(BookmarkType.WARNING);
			while (bookmarks.hasNext()) {
				Bookmark bookmark = bookmarks.next();
				if (bookmark.getCategory().equals(CATEGORY) && range.contains(bookmark.getAddress())) {
					found.add(bookmark.getAddress().getOffset());
					comments.append(bookmark.getComment()).append('\n');
					println(item.name + ": " + bookmark.getComment());
				}
			}
			// Warned where the decompiler would not take the lifting (Ghidra 12.2's overlap limit), lifted where it does.
			if (item.either != null && found.isEmpty()) {
				item.warn = new long[0];
				item.c = item.either;
			}
			// One warning per chain of nested transfers, at its first; it names the rest.
			Set<Long> expected = new TreeSet<>();
			for (long at : item.warn) expected.add(at);
			if (!expected.isEmpty()) expected = new TreeSet<>(Set.of(((TreeSet<Long>) expected).first()));
			if (!found.equals(expected))
				throw new AssertionError(item.name + ": warnings at " + hex(found) + ", want " + hex(expected));
			for (long at : item.warn) {
				if (!found.contains(at) && !comments.toString().contains(" at " + toAddr(at) + " "))
					throw new AssertionError(item.name + ": no warning names the transfer at " + toAddr(at) + ": " + comments);
			}
			// A jump into another function's warned code carries its own warning (issue #108).
			if (item.entered != null) for (long at : item.entered) {
				boolean marked = false;
				for (Bookmark mark : currentProgram.getBookmarkManager().getBookmarks(toAddr(at)))
					marked |= mark.getCategory().equals("C6000 Nested Delay Window (entered)");
				if (!marked) throw new AssertionError(item.name + ": the jump at " + toAddr(at) + " into warned code is not warned");
			}
			// A callback taken by address is a function (C6000 Code Pointers); a plain label is not.
			if (item.functions != null) for (long at : item.functions)
				if (getFunctionAt(toAddr(at)) == null) throw new AssertionError(item.name + ": no function at " + toAddr(at));
			if (item.labels != null) for (long at : item.labels)
				if (getFunctionAt(toAddr(at)) != null) throw new AssertionError(item.name + ": a function at the label " + toAddr(at));
			if (item.plain != null || item.absent != null) {
				var decompiler = new ghidra.app.decompiler.DecompInterface();
				decompiler.openProgram(currentProgram);
				var result = decompiler.decompileFunction(getFunctionAt(toAddr(item.plainAt != 0 ? item.plainAt : item.entry)), 60, monitor);
				String c = result.decompileCompleted() ? result.getDecompiledFunction().getC() : String.valueOf(result.getErrorMessage());
				decompiler.dispose();
				if (item.plain != null) for (String text : item.plain)
					if (!c.contains(text)) throw new AssertionError(item.name + ": C lacks \"" + text + "\":\n" + c);
				if (item.absent != null) for (String text : item.absent)
					if (c.contains(text)) throw new AssertionError(item.name + ": C must not hold \"" + text + "\":\n" + c);
			}
			if (item.c != null && item.c.length > 0) {
				// Lifted: its nested branches are latched, and the C is the hardware's.
				boolean latched = false;
				for (var insn : currentProgram.getListing().getInstructions(range, true))
					latched |= java.math.BigInteger.ONE.equals(insn.getValue(currentProgram.getRegister("c_inert"), false));
				if (!latched) throw new AssertionError(item.name + ": no branch is latched");
				var decompiler = new ghidra.app.decompiler.DecompInterface();
				decompiler.openProgram(currentProgram);
				var result = decompiler.decompileFunction(getFunctionAt(toAddr(item.entry)), 60, monitor);
				String c = result.decompileCompleted() ? result.getDecompiledFunction().getC() : String.valueOf(result.getErrorMessage());
				decompiler.dispose();
				for (String text : item.c)
					if (!c.contains(text)) throw new AssertionError(item.name + ": C lacks \"" + text + "\":\n" + c);
				lifted++;
			}
			if (expected.isEmpty()) clean++;
			else warned++;
		}
		println("C6000_NESTED_WINDOW_OK warned=" + warned + " clean=" + clean + " lifted=" + lifted);
	}

	private static List<String> hex(Set<Long> addresses) {
		List<String> out = new ArrayList<>();
		for (long at : addresses) out.add(Long.toHexString(at));
		return out;
	}
}
