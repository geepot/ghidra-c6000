// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Absorbing a window's unowned slots must not stale another schedule over the same fetch packet,
// in a tests/fixtures/nested-window-schedule.py image. Run after C6000NestedWindowScheduleTest.java prepare.

import c6000.C6000PipelineContracts;
import c6000.C6000PipelineSchedules;
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;

public class C6000WindowNeighbourTest extends GhidraScript {
	private static final String EVIDENCE = "fixture entry: drained pipeline";
	private final Map<Long, List<C6000PipelineContracts.SourceWindow>> pins = new HashMap<>();
	private int checks;

	interface Action { void run() throws Exception; }

	@Override
	protected void run() throws Exception {
		Function absorber = getFunctionAt(toAddr(0x112cL)), neighbour = getFunctionAt(toAddr(0x1120L));
		// The shape: the absorber's B tail2 slots are unowned and share neighbour's fetch packet.
		if (absorber == null || neighbour == null || getFunctionContaining(toAddr(0x1134L)) != null ||
			!absorber.getBody().contains(toAddr(0x1148L)) || neighbour.getBody().contains(toAddr(0x1134L))) {
			throw new AssertionError("fixture shape changed: " + absorber + " " +
				(absorber == null ? "" : absorber.getBody()) + ", " + neighbour);
		}
		// Known-bad: a jump from another function into the slots makes them a shared tail.
		var jump = currentProgram.getReferenceManager().addMemoryReference(toAddr(0x1124L), toAddr(0x1134L),
			RefType.CONDITIONAL_JUMP, SourceType.USER_DEFINED, 0);
		refuses(() -> review(absorber), "alternate entry into scheduled code at 00001134");
		currentProgram.getReferenceManager().delete(jump);
		// Known-good: no schedule reads the shared packet, so the absorber alone stays reviewable.
		review(absorber);
		Path directory = Files.createTempDirectory("c6000-window-neighbour");
		Path manifest = directory.resolve("manifest.json"), report = directory.resolve("report.json");
		// Known-bad: callee's code is elsewhere, but it pins the shared packet as an entry source,
		// which its source hash reads too: in one batch, and once recorded.
		Function callee = getFunctionAt(toAddr(0x10c0L));
		pins.put(0x10c0L, List.of(source(callee), window(0x1120L)));
		Files.writeString(manifest, manifest(absorber, callee));
		runScript("C6000ReviewPipelineSchedules.java", new String[] { manifest.toString(), report.toString() });
		var pinned = JsonParser.parseString(Files.readString(report)).getAsJsonObject().getAsJsonArray("functions");
		if (!pinned.get(0).getAsJsonObject().has("reason") ||
			!pinned.get(0).getAsJsonObject().get("reason").getAsString().contains("would change the reviewed source of 000010c0") ||
			!pinned.get(1).getAsJsonObject().get("status").getAsString().equals("eligible")) {
			throw new AssertionError("batch must refuse the absorber over callee's entry source: " + pinned);
		}
		checks++;
		C6000PipelineContracts.record(currentProgram, callee, review(callee), monitor);
		refuses(() -> review(absorber), "would change the reviewed source of 000010c0");
		currentProgram.getOptions(C6000PipelineSchedules.OPTIONS).removeOption(C6000PipelineContracts.key(callee));
		review(absorber);
		// One batch, absorber first: its enable would change the neighbour's pinned source.
		Files.writeString(manifest, manifest(absorber, neighbour));
		runScript("C6000ReviewPipelineSchedules.java", new String[] { manifest.toString(), report.toString() });
		String digest = C6000PipelineContracts.sha256(Files.readAllBytes(report));
		runScript("C6000ReviewPipelineSchedules.java",
			new String[] { manifest.toString(), report.toString(), "apply", digest });
		var rows = JsonParser.parseString(Files.readString(report)).getAsJsonObject().getAsJsonArray("functions");
		String reason = rows.get(0).getAsJsonObject().has("reason") ?
			rows.get(0).getAsJsonObject().get("reason").getAsString() : "";
		if (!reason.contains("would change the reviewed source of 00001120") ||
			!rows.get(1).getAsJsonObject().get("status").getAsString().equals("eligible") ||
			enabled(absorber) || !enabled(neighbour)) {
			throw new AssertionError("batch must refuse the absorber and enable the neighbour: " + rows);
		}
		checks++;
		// The neighbour's binding is still fresh.
		C6000PipelineContracts.activate(currentProgram, neighbour, monitor);
		// Known-bad: the neighbour is now recorded, so the absorber alone is refused too.
		refuses(() -> review(absorber), "would change the reviewed source of 00001120");
		for (Path file : List.of(manifest, report)) Files.deleteIfExists(file);
		try (var archives = Files.newDirectoryStream(directory)) { for (Path file : archives) Files.delete(file); }
		Files.delete(directory);
		println("C6000_WINDOW_NEIGHBOUR_OK checks=" + checks);
	}

	private boolean enabled(Function f) {
		return BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(
			currentProgram.getRegister("c_schedule_entry"), f.getEntryPoint(), false));
	}

	private C6000PipelineContracts.SourceWindow window(long start) throws Exception {
		return new C6000PipelineContracts.SourceWindow(start, 32,
			C6000PipelineContracts.sha256(getBytes(toAddr(start), 32)));
	}

	private C6000PipelineContracts.SourceWindow source(Function f) throws Exception {
		return window(f.getEntryPoint().getOffset() & ~31L);
	}

	private List<C6000PipelineContracts.SourceWindow> sources(Function f) throws Exception {
		var pinned = pins.get(f.getEntryPoint().getOffset());
		return pinned != null ? pinned : List.of(source(f));
	}

	private C6000PipelineContracts.Review review(Function f) throws Exception {
		return C6000PipelineContracts.review(currentProgram, f, EVIDENCE, Set.of(), sources(f), monitor);
	}

	private String manifest(Function... functions) throws Exception {
		var plan = new JsonObject();
		plan.addProperty("schema", 1);
		plan.addProperty("language_id", currentProgram.getLanguageID().getIdAsString());
		var rows = new JsonArray();
		for (var f : functions) {
			var row = new JsonObject();
			row.addProperty("entry", f.getEntryPoint().getOffset());
			row.addProperty("drained_entry_evidence", EVIDENCE);
			row.add("previous_e1_writes", new JsonArray());
			row.add("entry_sources", new Gson().toJsonTree(sources(f)));
			rows.add(row);
		}
		plan.add("functions", rows);
		return plan.toString();
	}

	private void refuses(Action action, String reason) throws Exception {
		try {
			action.run();
		}
		catch (Exception error) {
			if (!error.toString().contains(reason)) throw new AssertionError("wrong refusal: " + error, error);
			checks++;
			return;
		}
		throw new AssertionError("accepted: " + reason);
	}
}
