// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.math.BigInteger;
import java.util.*;

import com.google.gson.Gson;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.util.task.TaskMonitor;

/** Reviewed, source-bound activation of the existing exact scheduler.
 * Drainage is an explicit reviewer precondition, never inferred from an ABI.
 * SPRUFE8B 3.5, 3.8.3 and 4.2: packet snapshots and architectural write phases.
 */
public final class C6000PipelineContracts {
    private static final Gson JSON = new Gson();
    private static final String PREFIX = "Reviewed schedule ";
    private static final int SCHEMA = 1;

    public record SourceWindow(long start, int length, String sha256) {}
    public record Review(int schema, String language, long entry, String evidence,
            List<String> previousE1Writes, List<SourceWindow> entrySources,
            String sourceSha256, String scheduleSha256, int states, int operations) {
        public Review {
            previousE1Writes = List.copyOf(previousE1Writes);
            entrySources = List.copyOf(entrySources);
        }
    }
    private record Binding(Review review, String activeSourceSha256) {}

    private C6000PipelineContracts() {}

    public static String key(Function function) {
        return PREFIX + function.getEntryPoint();
    }

    public static boolean isRecorded(Program program, Function function) {
        boolean present = false;
        for (String group : program.getOptionsNames()) {
            if (group.equals(C6000PipelineSchedules.OPTIONS)) present = true;
        }
        if (!present) return false;
        return program.getOptions(C6000PipelineSchedules.OPTIONS).contains(key(function));
    }

    private static Binding binding(Program program, Function function) {
        try {
            String value = program.getOptions(C6000PipelineSchedules.OPTIONS)
                .getString(key(function), "");
            Binding result = JSON.fromJson(value, Binding.class);
            if (result == null || result.review() == null ||
                result.review().schema() != SCHEMA || result.activeSourceSha256() == null) {
                throw new IllegalArgumentException("missing or invalid reviewed schedule binding");
            }
            identity(program, function, result.review());
            return result;
        }
        catch (RuntimeException error) {
            throw new IllegalArgumentException("Invalid exact schedule contract at " +
                function.getEntryPoint() + ": " + error.getMessage(), error);
        }
    }

    /** Stored authoring inputs only. This does not validate freshness or authorize activation. */
    public static Review recordedReview(Program program, Function function) {
        return binding(program, function).review();
    }

    static boolean isPending(Program program, Function function) {
        return isRecorded(program, function) && binding(program, function).activeSourceSha256().isEmpty();
    }

    static void validatePending(Program program, Function function, String evidence,
            Set<String> writes, C6000PipelineCompiler.Result schedule,
            TaskMonitor monitor) throws Exception {
        Binding pending = binding(program, function);
        if (!pending.activeSourceSha256().isEmpty() ||
            !pending.review().evidence().equals(evidence) ||
            !Set.copyOf(pending.review().previousE1Writes()).equals(writes)) {
            throw new IllegalArgumentException("pending review differs from the supplied entry contract");
        }
        check(program, function, pending.review(), pending.review().sourceSha256(), schedule, monitor);
    }

    private static void identity(Program program, Function function, Review review) {
        if (function.getEntryPoint().getAddressSpace() !=
                program.getAddressFactory().getDefaultAddressSpace() ||
            function.getEntryPoint().getAddressSpace().isOverlaySpace() ||
            review.schema() != SCHEMA || review.entry() != function.getEntryPoint().getOffset() ||
            !program.getLanguageID().getIdAsString().equals(review.language()) ||
            review.evidence() == null || review.evidence().isBlank()) {
            throw new IllegalArgumentException("schedule identity/evidence mismatch");
        }
    }

    public static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static String sha256(String text) throws Exception {
        return sha256(text.getBytes(StandardCharsets.UTF_8));
    }

    private static Address address(Program program, long offset) {
        if (offset < 0 || offset > 0xffffffffL) {
            throw new IllegalArgumentException("source address is outside C6000 memory");
        }
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private static byte[] bytes(Program program, Address start, int size) throws Exception {
        byte[] result = new byte[size];
        if (program.getMemory().getBytes(start, result) != size) {
            throw new IllegalArgumentException("source bytes are not completely initialized");
        }
        return result;
    }

    private static void sourceWindows(Program program, List<SourceWindow> windows,
            AddressSet scope) throws Exception {
        if (windows == null || windows.size() > 32) {
            throw new IllegalArgumentException("bounded entry-source windows required");
        }
        for (SourceWindow window : windows) {
            if (window.length() <= 0 || window.length() > 65536 ||
                window.start() + window.length() > 0x100000000L ||
                (window.start() & 31) != 0 || (window.length() & 31) != 0 ||
                window.sha256() == null || !window.sha256().matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("entry evidence needs pinned full-fetch windows");
            }
            Address start = address(program, window.start());
            if (!sha256(bytes(program, start, window.length())).equals(window.sha256())) {
                throw new IllegalArgumentException("entry-source bytes changed at " + start);
            }
            scope.add(start, start.add(window.length() - 1));
        }
    }

    private static void node(StringBuilder text, Varnode node) {
        if (node == null) text.append('-');
        else text.append(node.getAddress().getAddressSpace().getName()).append(':')
            .append(Long.toUnsignedString(node.getOffset(), 16)).append('/').append(node.getSize());
        text.append(';');
    }

    private static String reference(ghidra.program.model.symbol.Reference ref) {
        return ref.getFromAddress() + "|" + ref.getToAddress() + "|" +
            ref.getOperandIndex() + "|" + ref.getReferenceType() + "|" +
            ref.getSource() + "|" + ref.isPrimary();
    }

    private static String scheduleHash(C6000PipelineCompiler.Result schedule,
            TaskMonitor monitor) throws Exception {
        StringBuilder text = new StringBuilder();
        for (PcodeOp op : schedule.code()) {
            monitor.checkCancelled();
            text.append(op.getOpcode()).append(':');
            node(text, op.getOutput());
            for (Varnode input : op.getInputs()) node(text, input);
            text.append('\n');
        }
        return sha256(text.toString());
    }

    /** Includes source bytes, decode context, ownership, data, and incoming/outgoing references.
     * Only our own entry selector is normalized, allowing activation to be idempotent.
     */
    private static String sourceHash(Program program, Function function,
            C6000PipelineCompiler.Result schedule, List<SourceWindow> windows,
            TaskMonitor monitor) throws Exception {
        var calls = C6000PipelineSchedules.closedCalls(program, function);
        String configuration = calls.isEmpty() ? "" : program.getOptions(C6000PipelineSchedules.OPTIONS)
            .getString(C6000PipelineSchedules.closedCallsKey(function), "");
        return sourceHash(program, function, schedule, windows, monitor, calls, configuration);
    }

    private static String sourceHash(Program program, Function function,
            C6000PipelineCompiler.Result schedule, List<SourceWindow> windows,
            TaskMonitor monitor, List<C6000PipelineCompiler.ClosedCallPlan> calls,
            String configuration) throws Exception {
        Address entry = function.getEntryPoint();
        C6000PipelineSchedules.validateClosedCallScope(program, function, calls);
        Set<Address> declaredEntries = new HashSet<>();declaredEntries.add(entry);
        for (var call : calls) declaredEntries.add(address(program, call.callee().ownerEntry()));
        if (entry.getAddressSpace() != program.getAddressFactory().getDefaultAddressSpace() ||
            entry.getAddressSpace().isOverlaySpace() ||
            !C6000ExecutionPackets.issuePrefix(program, entry).isEmpty()) {
            throw new IllegalArgumentException("exact schedule must start at a default-space execute packet");
        }
        for (AddressRange range : schedule.covered()) {
            long end = range.getMaxAddress().getOffset();
            for (long offset = range.getMinAddress().getOffset(); offset <= end;) {
                monitor.checkCancelled();
                Address at = address(program, offset);
                // CPKT is structural metadata in the compiler's covered set,
                // not an instruction start accepted by instructionLengthAt().
                if ((offset & 31) == 28 && (program.getMemory().getInt(at) >>> 28) == 14) {
                    if (offset + 3 > end || !BigInteger.ONE.equals(program.getProgramContext()
                            .getValue(program.getRegister("c_isheader"), at, false))) {
                        throw new IllegalArgumentException("stored packet context conflicts with physical header at " + at);
                    }
                    offset += 4;continue;
                }
                int width = C6000ExecutionPackets.instructionLengthAt(program, at);
                if (offset + width - 1 > end) {
                    throw new IllegalArgumentException("scheduled extent splits a physical instruction at " + at);
                }
                for (var field : C6000PacketContext.physicalDecodeFields(program, at).entrySet()) {
                    BigInteger actual = program.getProgramContext().getValue(program.getRegister(field.getKey()), at, false);
                    if (!(actual == null ? BigInteger.ZERO : actual).equals(BigInteger.valueOf(field.getValue()))) {
                        throw new IllegalArgumentException("stored packet context conflicts with physical bytes at " + at + ": " + field.getKey());
                    }
                }
                offset += width;
            }
        }
        AddressSet scope = new AddressSet(function.getBody());
        scope.add(schedule.covered());
        AddressSet fetch = new AddressSet();
        for (AddressRange range : scope) {
            if (range.getMinAddress().getAddressSpace() != entry.getAddressSpace()) {
                throw new IllegalArgumentException("schedule scope crosses address spaces");
            }
            fetch.add(address(program, range.getMinAddress().getOffset() & ~31L),
                address(program, range.getMaxAddress().getOffset() | 31L));
        }
        sourceWindows(program, windows, fetch);
        if (fetch.getNumAddresses() > 4 * 1024 * 1024) {
            throw new IllegalArgumentException("review source exceeds four MiB");
        }
        StringBuilder text = new StringBuilder(program.getLanguageID().getIdAsString());
        text.append('|').append(entry).append('|').append(function.getBody()).append('\n');
        // The observation boundary is part of the reviewed source identity.
        // Keep legacy hashes unchanged when no post-return contract was recorded.
        var tail = C6000PipelineSchedules.storeTailContract(program, function);
        if (tail != null) text.append("store-tail:").append(JSON.toJson(tail)).append('\n');
        // Bind the stored serialization verbatim: Set iteration order after reopening
        // must not change a contract hash. Any plan edit invalidates the binding.
        if (!calls.isEmpty()) text.append("closed-calls:").append(configuration).append('\n');
        var context = program.getProgramContext();
        var base = program.getLanguage().getContextBaseRegister();
        for (AddressRange range : fetch) {
            monitor.checkCancelled();
            int size = (int) range.getLength();
            text.append(range).append(':').append(sha256(bytes(program, range.getMinAddress(), size))).append('\n');
            for (long offset = range.getMinAddress().getOffset();
                    offset <= range.getMaxAddress().getOffset(); offset += 2) {
                monitor.checkCancelled();
                Address at = address(program, offset);
                var owner = program.getFunctionManager().getFunctionContaining(at);
                text.append(at).append(':').append(owner == null ? "unowned" : owner.getEntryPoint());
                var value = context.getRegisterValue(base, at);
                var normalized = new ProcessorContextImpl(program.getLanguage());
                if (value != null) normalized.setRegisterValue(value);
                normalized.setRegisterValue(new RegisterValue(program.getRegister("c_schedule_entry"), BigInteger.ZERO));
                text.append(':').append(normalized.getRegisterValue(base)).append('\n');
                if (!at.equals(entry) && schedule.covered().contains(at) &&
                    BigInteger.ONE.equals(context.getValue(program.getRegister("c_schedule_entry"), at, false))) {
                    throw new IllegalArgumentException("another schedule entry lies inside the covered code");
                }
            }
        }
        var data = program.getListing().getDefinedData(fetch, true);
        while (data.hasNext()) {
            monitor.checkCancelled();
            var item = data.next();
            if (schedule.covered().intersects(item.getMinAddress(), item.getMaxAddress())) {
                throw new IllegalArgumentException("defined data overlaps scheduled code at " + item.getAddress());
            }
            text.append("data:").append(item.getAddress()).append(':').append(item.getLength())
                .append(':').append(item.getDataType().getPathName()).append('\n');
        }
        var instructions = program.getListing().getInstructions(fetch, true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            var item = instructions.next();
            text.append("instruction:").append(item.getAddress()).append(':')
                .append(item.getLength()).append(':').append(item.getFlowOverride()).append(':')
                .append(item.isFallThroughOverridden() ? item.getFallThrough() : "default")
                .append(':').append(item.isInDelaySlot()).append(':').append(item.getDelaySlotDepth()).append('\n');
        }
        var functions = program.getFunctionManager().getFunctions(fetch, true);
        while (functions.hasNext()) {
            var owner = functions.next();
            if (!declaredEntries.contains(owner.getEntryPoint()) && schedule.covered().contains(owner.getEntryPoint())) {
                throw new IllegalArgumentException("another function enters scheduled code at " + owner.getEntryPoint());
            }
            text.append("function:").append(owner.getEntryPoint()).append(':').append(owner.getBody()).append('\n');
        }
        SortedSet<String> references = new TreeSet<>();
        var manager = program.getReferenceManager();
        var sources = manager.getReferenceSourceIterator(fetch, true);
        while (sources.hasNext()) {
            monitor.checkCancelled();
            for (var ref : manager.getReferencesFrom(sources.next())) references.add(reference(ref));
        }
        var destinations = manager.getReferenceDestinationIterator(fetch, true);
        while (destinations.hasNext()) {
            monitor.checkCancelled();
            for (var ref : manager.getReferencesTo(destinations.next())) {
                if (schedule.covered().contains(ref.getToAddress()) &&
                    !declaredEntries.contains(ref.getToAddress()) &&
                    !schedule.covered().contains(ref.getFromAddress()) &&
                    (ref.getReferenceType().isFlow() || ref.getReferenceType().isData())) {
                    throw new IllegalArgumentException("alternate entry into scheduled code at " + ref.getToAddress());
                }
                references.add(reference(ref));
            }
        }
        for (String reference : references) text.append("ref:").append(reference).append('\n');
        var entries = program.getSymbolTable().getExternalEntryPointIterator();
        while (entries.hasNext()) {
            Address at = entries.next();
            if (fetch.contains(at)) {
                if (schedule.covered().contains(at) && !declaredEntries.contains(at)) {
                    throw new IllegalArgumentException("external entry inside scheduled code at " + at);
                }
                text.append("external:").append(at).append('\n');
            }
        }
        return sha256(text.toString());
    }

    /** Read-only source preflight for explicitly configured closed-call activation. */
    static void validateSourceScope(Program program, Function function,
            C6000PipelineCompiler.Result schedule, List<C6000PipelineCompiler.ClosedCallPlan> calls,
            TaskMonitor monitor) throws Exception {
        sourceHash(program, function, schedule, List.of(), monitor, calls, JSON.toJson(calls));
    }

    public static Review review(Program program, Function function, String evidence,
            Set<String> previousE1Writes, List<SourceWindow> entrySources,
            TaskMonitor monitor) throws Exception {
        if (evidence == null || evidence.isBlank()) {
            throw new IllegalArgumentException("reviewed drained-entry evidence is required");
        }
        if (entrySources == null || entrySources.isEmpty()) {
            throw new IllegalArgumentException("pin the source supporting the reviewed entry contract");
        }
        var schedule = C6000PipelineSchedules.compileConfigured(program, function, previousE1Writes, monitor);
        if (C6000PipelineSchedules.closedCalls(program, function).isEmpty() &&
                !new AddressSet(schedule.covered()).subtract(function.getBody()).isEmpty()) {
            throw new IllegalArgumentException("reviewed activation requires complete function ownership of the scheduled code");
        }
        return reviewed(program, function, evidence, previousE1Writes, entrySources, schedule, monitor);
    }

    private static Review reviewed(Program program, Function function, String evidence,
            Set<String> writes, List<SourceWindow> sources,
            C6000PipelineCompiler.Result schedule, TaskMonitor monitor) throws Exception {
        var result = new Review(SCHEMA, program.getLanguageID().getIdAsString(),
            function.getEntryPoint().getOffset(), evidence, new ArrayList<>(new TreeSet<>(writes)),
            sources, sourceHash(program, function, schedule, sources, monitor),
            scheduleHash(schedule, monitor), schedule.states(), schedule.code().length);
        identity(program, function, result);
        return result;
    }

    private static void check(Program program, Function function, Review review,
            String expectedSource, C6000PipelineCompiler.Result schedule,
            TaskMonitor monitor) throws Exception {
        identity(program, function, review);
        if (!sourceHash(program, function, schedule, review.entrySources(), monitor).equals(expectedSource)) {
            throw new IllegalArgumentException("reviewed schedule is stale; code, context, ownership or flow changed at " + function.getEntryPoint());
        }
        if (!scheduleHash(schedule, monitor).equals(review.scheduleSha256())) {
            throw new IllegalArgumentException("reviewed schedule is stale; generated p-code changed at " + function.getEntryPoint());
        }
    }

    /** Record only; the contract-gated analyzer may activate this approved plan later. */
    public static void record(Program program, Function function, Review review,
            TaskMonitor monitor) throws Exception {
        var schedule = C6000PipelineSchedules.compileConfigured(program, function, Set.copyOf(review.previousE1Writes()), monitor);
        check(program, function, review, review.sourceSha256(), schedule, monitor);
        program.getOptions(C6000PipelineSchedules.OPTIONS).setString(key(function),
            JSON.toJson(new Binding(review, "")));
    }

    /** Called inside enable's transaction after the reviewed body expansion. */
    static void bind(Program program, Function function, String evidence, Set<String> writes,
            C6000PipelineCompiler.Result schedule, TaskMonitor monitor) throws Exception {
        Binding pending = isRecorded(program, function) ? binding(program, function) : null;
        List<SourceWindow> sources = pending == null ? List.of() : pending.review().entrySources();
        var expanded = C6000PipelineSchedules.compileConfigured(program, function, writes, monitor);
        if (!scheduleHash(schedule, monitor).equals(scheduleHash(expanded, monitor))) {
            throw new IllegalArgumentException("body expansion changes the reviewed schedule; review the complete scope first");
        }
        Review review = reviewed(program, function, evidence, writes, sources, schedule, monitor);
        program.getOptions(C6000PipelineSchedules.OPTIONS).setString(key(function),
            JSON.toJson(new Binding(review, review.sourceSha256())));
    }

    public static C6000PipelineCompiler.Result activate(Program program, Function function,
            TaskMonitor monitor) throws Exception {
        Binding binding = binding(program, function);
        var review = binding.review();
        if (!binding.activeSourceSha256().isEmpty() && !BigInteger.ONE.equals(
                program.getProgramContext().getValue(program.getRegister("c_schedule_entry"),
                    function.getEntryPoint(), false))) {
            throw new IllegalArgumentException("active entry selector changed; review the contract again");
        }
        var writes = Set.copyOf(review.previousE1Writes());
        var schedule = C6000PipelineSchedules.compileConfigured(program, function, writes, monitor);
        check(program, function, review, binding.activeSourceSha256().isEmpty() ?
            review.sourceSha256() : binding.activeSourceSha256(), schedule, monitor);
        // Expected refusals are read-only. enable() owns the write transaction
        // and repeats pending-review validation before changing the selector.
        return C6000PipelineSchedules.enable(program, function, review.evidence(), writes, monitor);
    }

    public static void validate(Program program, Function function,
            C6000PipelineCompiler.Result schedule, TaskMonitor monitor) throws Exception {
        Binding binding = binding(program, function);
        if (binding.activeSourceSha256().isEmpty()) {
            throw new IllegalArgumentException("reviewed schedule has not been activated");
        }
        if (!BigInteger.ONE.equals(program.getProgramContext().getValue(
                program.getRegister("c_schedule_entry"), function.getEntryPoint(), false))) {
            throw new IllegalArgumentException("active entry selector changed; review the contract again");
        }
        var options = program.getOptions(C6000PipelineSchedules.OPTIONS);
        if (!binding.review().evidence().equals(options.getString(C6000PipelineSchedules.contractKey(function), "")) ||
            !String.join(",", binding.review().previousE1Writes()).equals(options.getString(C6000PipelineSchedules.hazardsKey(function), ""))) {
            throw new IllegalArgumentException("recorded entry assumptions changed");
        }
        check(program, function, binding.review(), binding.activeSourceSha256(), schedule, monitor);
    }
}
