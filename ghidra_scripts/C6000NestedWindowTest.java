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
			}
			return;
		}
		int warned = 0, clean = 0;
		for (var item : cases) {
			Set<Long> found = new TreeSet<>();
			var range = new AddressSet(toAddr(item.entry), toAddr(item.end));
			Iterator<Bookmark> bookmarks = currentProgram.getBookmarkManager().getBookmarksIterator(BookmarkType.WARNING);
			while (bookmarks.hasNext()) {
				Bookmark bookmark = bookmarks.next();
				if (bookmark.getCategory().equals(CATEGORY) && range.contains(bookmark.getAddress())) {
					found.add(bookmark.getAddress().getOffset());
					println(item.name + ": " + bookmark.getComment());
				}
			}
			Set<Long> expected = new TreeSet<>();
			for (long at : item.warn) expected.add(at);
			if (!found.equals(expected))
				throw new AssertionError(item.name + ": warnings at " + hex(found) + ", want " + hex(expected));
			if (expected.isEmpty()) clean++;
			else warned++;
		}
		println("C6000_NESTED_WINDOW_OK warned=" + warned + " clean=" + clean);
	}

	private static List<String> hex(Set<Long> addresses) {
		List<String> out = new ArrayList<>();
		for (long at : addresses) out.add(Long.toHexString(at));
		return out;
	}
}
