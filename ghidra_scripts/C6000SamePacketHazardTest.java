// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check same-packet hazard warnings in a tests/fixtures/same-packet-hazard.py image (issue #71).
// Run as preScript with "prepare CASES.json", then as postScript with CASES.json.

import c6000.C6000PacketContext;
import c6000.C6000PipelineContracts;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.nio.file.*;
import java.util.*;

public class C6000SamePacketHazardTest extends GhidraScript {
	// The analyzer's CATEGORY and NOTE, spelled out so the check also runs without it.
	private static final String CATEGORY = "C6000 Same-Packet Hazard";
	private static final String NOTE = "WARNING: C6000 same-packet hazard";
	private static final String EVIDENCE = "Fixture entry: drained pipeline, caller return link in B3";

	private static final class Case {
		String name;
		long entry, end;
		long[] warn;
		String[] c;
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
				disassemble(toAddr(item.entry));
				createFunction(toAddr(item.entry), item.name);
			}
			return;
		}
		var decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		int warned = 0, clean = 0;
		for (var item : cases) {
			Set<Long> expected = new TreeSet<>();
			for (long at : item.warn) expected.add(at);
			check(decompiler, item, expected);
			if (item.name.equals("reviewed")) {
				// An active reviewed schedule reads before it writes: its function is not warned.
				Function function = getFunctionAt(toAddr(item.entry));
				long start = item.entry & ~31L;
				var sources = List.of(new C6000PipelineContracts.SourceWindow(start, 0x40,
					C6000PipelineContracts.sha256(getBytes(toAddr(start), 0x40))));
				var review = C6000PipelineContracts.review(currentProgram, function, EVIDENCE, Set.of(), sources, monitor);
				C6000PipelineContracts.record(currentProgram, function, review, monitor);
				C6000PipelineContracts.activate(currentProgram, function, monitor);
				var analyzer = Class.forName("c6000.C6000SamePacketHazardAnalyzer").getConstructor().newInstance();
				analyzer.getClass().getMethod("added", Program.class, AddressSetView.class, TaskMonitor.class, MessageLog.class)
					.invoke(analyzer, currentProgram, function.getBody(), monitor, new MessageLog());
				decompiler.flushCache();
				check(decompiler, item, Set.of());
			}
			if (expected.isEmpty()) clean++;
			else warned++;
		}
		decompiler.dispose();
		println("C6000_SAME_PACKET_HAZARD_OK warned=" + warned + " clean=" + clean);
	}

	/** The case's warnings are exactly expected, and its C carries the note only if any. */
	private void check(DecompInterface decompiler, Case item, Set<Long> expected) throws Exception {
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
		if (!found.equals(expected))
			throw new AssertionError(item.name + ": warnings at " + hex(found) + ", want " + hex(expected));
		var result = decompiler.decompileFunction(getFunctionAt(toAddr(item.entry)), 60, monitor);
		if (!result.decompileCompleted()) throw new AssertionError(item.name + ": " + result.getErrorMessage());
		String c = result.getDecompiledFunction().getC();
		if (c.contains(NOTE) == expected.isEmpty())
			throw new AssertionError(item.name + ": note " + (expected.isEmpty() ? "present" : "missing") + " in\n" + c);
		// A staged packet reads before it writes: the C is the hardware's result.
		if (item.c != null) for (String text : item.c)
			if (!c.contains(text)) throw new AssertionError(item.name + ": C lacks \"" + text + "\":\n" + c);
	}

	private static List<String> hex(Set<Long> addresses) {
		List<String> out = new ArrayList<>();
		for (long at : addresses) out.add(Long.toHexString(at));
		return out;
	}
}
