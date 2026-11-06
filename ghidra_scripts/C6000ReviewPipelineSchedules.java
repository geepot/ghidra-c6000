// SPDX-License-Identifier: Apache-2.0
// @category C6000
// MANIFEST REPORT [record|apply REVIEW_SHA256]. Report mode never changes the program.
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.core.analysis.*;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;
import c6000.C6000PipelineContracts;

public class C6000ReviewPipelineSchedules extends GhidraScript {
    private static final Gson JSON = new GsonBuilder().setPrettyPrinting().create();

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 && args.length != 4) {
            throw new IllegalArgumentException("MANIFEST REPORT [record|apply REVIEW_SHA256]");
        }
        boolean mutate = args.length == 4;
        if (mutate && !Set.of("record", "apply").contains(args[2])) {
            throw new IllegalArgumentException("explicit record or apply mode required");
        }
        Path manifestPath = Paths.get(args[0]).toAbsolutePath().normalize();
        Path reportPath = Paths.get(args[1]).toAbsolutePath().normalize();
        if (manifestPath.equals(reportPath)) throw new IllegalArgumentException("manifest and report must differ");
        JsonObject approved = null;
        if (mutate) {
            byte[] report = Files.readAllBytes(reportPath);
            if (!C6000PipelineContracts.sha256(report).equals(args[3])) {
                throw new IllegalArgumentException("review report SHA changed");
            }
            approved = JsonParser.parseString(new String(report, java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();
        }
        byte[] source = Files.readAllBytes(manifestPath);
        String manifestHash = C6000PipelineContracts.sha256(source);
        var manifest = JsonParser.parseString(new String(source, java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();
        if (manifest.get("schema").getAsInt() != 1 ||
            !manifest.get("language_id").getAsString().equals(currentProgram.getLanguageID().getIdAsString())) {
            throw new IllegalArgumentException("manifest schema or language mismatch");
        }
        long before = currentProgram.getModificationNumber();
        List<C6000PipelineContracts.Review> plans = new ArrayList<>();
        List<Object> reports = new ArrayList<>();
        Map<Long, Map<String,Object>> rows = new HashMap<>();
        Set<Long> seen = new HashSet<>();
        for (var value : manifest.getAsJsonArray("functions")) {
            monitor.checkCancelled();
            var item = value.getAsJsonObject();
            long entry = item.get("entry").getAsLong();
            if (!seen.add(entry)) throw new IllegalArgumentException("duplicate function entry");
            var row = new LinkedHashMap<String,Object>();
            row.put("entry", entry);
            try {
                Function function = currentProgram.getFunctionManager().getFunctionAt(toAddr(entry));
                if (function == null) throw new IllegalArgumentException("function entry is not defined");
                Set<String> writes = new TreeSet<>();
                for (var name : item.getAsJsonArray("previous_e1_writes")) writes.add(name.getAsString());
                List<C6000PipelineContracts.SourceWindow> windows = new ArrayList<>();
                for (var window : item.getAsJsonArray("entry_sources")) {
                    windows.add(JSON.fromJson(window, C6000PipelineContracts.SourceWindow.class));
                }
                var plan = C6000PipelineContracts.review(currentProgram, function,
                    item.get("drained_entry_evidence").getAsString(), writes, windows, monitor);
                plans.add(plan);row.put("status", "eligible");row.put("review", plan);
            }
            catch (ghidra.util.exception.CancelledException cancelled) {
                throw cancelled;
            }
            catch (Exception refused) {
                row.put("status", "refused");row.put("reason", refused.getMessage());
            }
            reports.add(row);rows.put(entry, row);
        }
        // Apply enables in order: refuse a schedule whose enable would change the source another one pins.
        Map<Long, C6000PipelineContracts.Footprint> footprints = new LinkedHashMap<>();
        for (var plan : plans) {
            footprints.put(plan.entry(), C6000PipelineContracts.footprint(currentProgram,
                currentProgram.getFunctionManager().getFunctionAt(toAddr(plan.entry())), plan, monitor));
        }
        for (var absorber : footprints.entrySet()) {
            for (var other : footprints.entrySet()) {
                if (other.getKey().equals(absorber.getKey()) ||
                    !other.getValue().source().intersects(absorber.getValue().absorbed())) continue;
                var row = rows.get(absorber.getKey());
                row.put("status", "refused");row.remove("review");
                row.put("reason", "enabling would change the reviewed source of " + toAddr(other.getKey()) +
                    " in this batch: covered code outside the body shares its fetch packets");
                plans.removeIf(plan -> plan.entry() == absorber.getKey());
                break;
            }
        }
        if (before != currentProgram.getModificationNumber()) throw new AssertionError("report changed program");
        String planHash = C6000PipelineContracts.sha256(JSON.toJson(plans).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        var report = new LinkedHashMap<String,Object>();
        report.put("schema", 1);report.put("mode", mutate ? args[2] : "report");
        report.put("manifest_sha256", manifestHash);report.put("plan_sha256", planHash);
        report.put("eligible_count", plans.size());report.put("functions", reports);
        if (mutate) {
            if (!approved.get("manifest_sha256").getAsString().equals(manifestHash) ||
                !approved.get("plan_sha256").getAsString().equals(planHash)) {
                throw new IllegalArgumentException("reviewed inputs or schedule changed");
            }
            var manager = AutoAnalysisManager.getAnalysisManager(currentProgram);
            if (manager.isAnalyzing()) throw new IllegalArgumentException("apply requires idle analysis");
            Path archive = reportPath.resolveSibling(reportPath.getFileName() + ".reviewed-" + args[3] + ".json");
            if (Files.exists(archive)) {
                if (!C6000PipelineContracts.sha256(Files.readAllBytes(archive)).equals(args[3])) {
                    throw new IllegalArgumentException("review archive differs");
                }
            }
            else Files.copy(reportPath, archive);
            boolean ok = manager.scheduleWorker(new AnalysisWorker() {
                public String getWorkerName() { return "Apply reviewed C6000 exact schedules"; }
                public boolean analysisWorkerCallback(Program program, Object context,
                        TaskMonitor task) throws Exception {
                    int transaction = program.startTransaction(getWorkerName());
                    boolean commit = false;
                    try {
                        for (var plan : plans) {
                            task.checkCancelled();
                            var function = program.getFunctionManager().getFunctionAt(toAddr(plan.entry()));
                            if (function == null) throw new IllegalArgumentException("reviewed function disappeared");
                            C6000PipelineContracts.record(program, function, plan, task);
                            if (args[2].equals("apply")) C6000PipelineContracts.activate(program, function, task);
                        }
                        commit = true;return true;
                    }
                    finally { program.endTransaction(transaction, commit); }
                }
            }, null, false, monitor);
            if (!ok) throw new IllegalStateException("reviewed schedule worker did not complete");
            report.put("review_report_sha256", args[3]);
        }
        report.put("recorded_count", mutate ? plans.size() : 0);
        report.put("enabled_count", mutate && args[2].equals("apply") ? plans.size() : 0);
        report.put("program_modification_unchanged", before == currentProgram.getModificationNumber());
        Files.writeString(reportPath, JSON.toJson(report) + "\n");
        println("C6000_REVIEW_PIPELINE_OK mode=" + report.get("mode") +
            " eligible=" + plans.size() + " enabled=" + report.get("enabled_count"));
    }
}
