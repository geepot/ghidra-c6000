// SPDX-License-Identifier: Apache-2.0
package c6000;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Set;
import java.util.List;
import java.util.Arrays;
import java.util.TreeSet;
import java.util.Objects;
import com.google.gson.Gson;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;
/** Explicit opt-in, never an automatic analyzer. See docs/pipeline-schedules.md. */
public final class C6000PipelineSchedules {
    public static final String OPTIONS = "C6000 pipeline schedules";

    private C6000PipelineSchedules() {
    }

    public static String contractKey(Function function) {
        return "Drained entry contract " + function.getEntryPoint();
    }

    public static String hazardsKey(Function function) {
        return "Previous E1 writes " + function.getEntryPoint();
    }

    /** One instruction's listing state that clearing code units drops (comments survive). */
    private record Annotation(Address at, int length, FlowOverride flow, boolean overridden,
            Address fallThrough, Reference[] references, List<String[]> equates) {}

    private static List<Annotation> annotations(Program program, Address start, Address end) {
        var saved = new ArrayList<Annotation>();
        var equates = program.getEquateTable();
        for (var instruction : program.getListing().getInstructions(new AddressSet(start, end), true)) {
            var named = new ArrayList<String[]>();
            for (var equate : equates.getEquates(instruction.getAddress()))
                for (var use : equate.getReferences(instruction.getAddress()))
                    named.add(new String[] {equate.getName(), Long.toString(equate.getValue()), Short.toString(use.getOpIndex()), Long.toString(use.getDynamicHashValue())});
            saved.add(new Annotation(instruction.getAddress(), instruction.getLength(), instruction.getFlowOverride(),
                instruction.isFallThroughOverridden(), instruction.getFallThrough(), instruction.getReferencesFrom(), named));
        }
        return saved;
    }

    /** Reapply saved state; native restores require each instruction back at its saved extent. */
    private static void restore(Program program, List<Annotation> saved, boolean exact) throws Exception {
        var listing = program.getListing();
        var manager = program.getReferenceManager();
        var equates = program.getEquateTable();
        for (var item : saved) {
            var instruction = listing.getInstructionAt(item.at());
            if (instruction == null || instruction.getLength() != item.length())
                throw new IllegalStateException("Entry window instruction changed extent at " + item.at());
            if (exact && item.at().compareTo(saved.get(0).at()) > 0 && !instruction.isInDelaySlot())
                throw new IllegalStateException("Native entry slot not restored at " + item.at());
            // Drop the fresh decode's references; the saved ones carry any fall-through override.
            manager.removeAllReferencesFrom(item.at());
            if (instruction.isFallThroughOverridden()) instruction.clearFallThroughOverride();
            instruction.setFlowOverride(item.flow());
            for (var reference : item.references()) {
                var added = manager.addReference(reference);
                if (reference.getSymbolID() >= 0 && reference.getSymbolID() != added.getSymbolID()) {
                    var symbol = program.getSymbolTable().getSymbol(reference.getSymbolID());
                    if (symbol != null) manager.setAssociation(symbol, added);
                }
            }
            for (var use : item.equates()) {
                var equate = equates.getEquate(use[0]);
                if (equate == null) equate = equates.createEquate(use[0], Long.parseLong(use[1]));
                long hash = Long.parseLong(use[3]);
                if (hash != 0) equate.addReference(hash, item.at());
                else equate.addReference(item.at(), Short.parseShort(use[2]));
            }
            if (item.overridden() && !instruction.isFallThroughOverridden()) instruction.setFallThrough(item.fallThrough());
            if (!item.overridden() && instruction.isFallThroughOverridden()) instruction.clearFallThroughOverride();
        }
    }

    /** Delay bytes of the entry's ordinary decode, with only the schedule selector cleared. */
    private static int nativeDelayBytes(Program program, Address at) throws Exception {
        var language = program.getLanguage();
        var context = new ProcessorContextImpl(language);
        var stored = program.getProgramContext().getRegisterValue(language.getContextBaseRegister(), at);
        if (stored != null) context.setRegisterValue(stored);
        context.setRegisterValue(new RegisterValue(program.getRegister("c_schedule_entry"), BigInteger.ZERO));
        return language.parse(new DumbMemBufferImpl(program.getMemory(), at), context, false).getDelaySlotByteCount();
    }

    /** Last address of the entry's native slot window: only its own straight-line slots, entered from nowhere else. */
    private static Address entryWindowEnd(Program program, Function function, Instruction entry,
            TaskMonitor monitor) throws Exception {
        int depth = entry.getDelaySlotDepth(), bytes = entry.getPrototype().getDelaySlotByteCount();
        Address start = entry.getAddress(), end = entry.getMaxAddress();
        if (depth == 0 && bytes == 0) return end;
        var listing = program.getListing();
        for (int slot = 0; slot < depth; slot++) {
            var instruction = listing.getInstructionAt(end.next());
            if (instruction == null || !instruction.isInDelaySlot() || instruction.getDelaySlotDepth() != 0 ||
                    !instruction.getFlowType().isFallthrough() || instruction.getFlowOverride() != FlowOverride.NONE)
                throw new IllegalArgumentException("entry native delay window is not straight-line code at " + end.next());
            end = instruction.getMaxAddress();
        }
        var after = listing.getInstructionAt(end.next());
        if (depth == 0 || end.subtract(entry.getMaxAddress()) != bytes || after != null && after.isInDelaySlot())
            throw new IllegalArgumentException("entry native delay window does not match its " + bytes + " delay bytes");
        var functions = program.getFunctionManager();
        var references = program.getReferenceManager();
        for (Address at = entry.getMaxAddress().next(); at.compareTo(end) <= 0; at = at.next()) {
            monitor.checkCancelled();
            var owner = functions.getFunctionContaining(at);
            if (owner != null && !owner.equals(function) || functions.getFunctionAt(at) != null ||
                    program.getSymbolTable().isExternalEntryPoint(at))
                throw new IllegalArgumentException("entry native delay window holds another entry or owner at " + at);
            for (var reference : references.getReferencesTo(at)) {
                Address from = reference.getFromAddress();
                if (!from.isMemoryAddress() || from.compareTo(start) < 0 || from.compareTo(end) > 0)
                    throw new IllegalArgumentException("entry native delay window entered from " + from + " at " + at);
            }
        }
        return end;
    }

    public static String storeTailKey(Function function) {
        return "Post-return store tail " + function.getEntryPoint();
    }

    public static C6000PipelineCompiler.StoreTailContract storeTailContract(Program program, Function function) {
        var options = program.getOptions(OPTIONS);
        if (!options.contains(storeTailKey(function))) return null;
        try {
            var contract = new Gson().fromJson(options.getString(storeTailKey(function), ""),
                C6000PipelineCompiler.StoreTailContract.class);
            return new C6000PipelineCompiler.StoreTailContract(contract.idleAdvances(), contract.evidence());
        }
        catch (RuntimeException error) {
            throw new IllegalArgumentException("Invalid post-return store-tail contract", error);
        }
    }

    public static String closedCallsKey(Function function) {
        return "Closed-call trace " + function.getEntryPoint();
    }

    /** Persisted opt-in only. The ordinary injector never guesses a call scope. */
    public static List<C6000PipelineCompiler.ClosedCallPlan> closedCalls(Program program, Function function) {
        var options = program.getOptions(OPTIONS);
        if (!options.contains(closedCallsKey(function))) return List.of();
        try {
            var plans = new Gson().fromJson(options.getString(closedCallsKey(function), ""),
                C6000PipelineCompiler.ClosedCallPlan[].class);
            if (plans == null || plans.length == 0 || plans.length > 16)
                throw new IllegalArgumentException("one to sixteen closed calls required");
            return List.copyOf(Arrays.asList(plans));
        }
        catch (RuntimeException error) {
            throw new IllegalArgumentException("Invalid closed-call decompiler contract", error);
        }
    }

    static void validateClosedCallScope(Program program, Function function,
            List<C6000PipelineCompiler.ClosedCallPlan> plans) {
        if (plans.isEmpty()) return;
        var first = plans.get(0);
        if (first.startPc() != function.getEntryPoint().getOffset() || first.stopPc() != null ||
                first.callerReturnPc() == null)
            throw new IllegalArgumentException("closed-call activation requires entry through complete caller return");
        var window = first.caller();
        var body = new AddressSet(function.getEntryPoint().getNewAddress(window.start()),
            function.getEntryPoint().getNewAddress(window.end() - 1));
        if (!window.unownedSpans().isEmpty() || !body.equals(function.getBody()) ||
                plans.stream().anyMatch(p -> !p.callee().unownedSpans().isEmpty()))
            throw new IllegalArgumentException("closed-call activation requires complete declared ownership; no body adoption");
    }

    /** Activate a reviewed multi-owner schedule through the normal injection library.
     * SPRUFE8B 3.5/3.7/4.2: entry drainage remains an explicit assertion; all
     * callee effects and caller delay packets come from the production call trace.
     * Call/callee windows, owners and references are source-bound without merging bodies.
     */
    public static C6000PipelineCompiler.ClosedCallsTraceResult enableClosedCalls(Program program,
            Function function, List<C6000PipelineCompiler.ClosedCallPlan> plans,
            TaskMonitor monitor) throws Exception {
        plans = List.copyOf(plans);
        if (plans.isEmpty()) throw new IllegalArgumentException("explicit closed calls required");
        monitor.checkCancelled();validateClosedCallScope(program, function, plans);
        var old = closedCalls(program, function);
        if ((C6000PipelineContracts.isRecorded(program, function) || !old.isEmpty()) && !old.equals(plans))
            throw new IllegalArgumentException("Entry already reviewed with a different closed-call contract");
        if (storeTailContract(program, function) != null)
            throw new IllegalArgumentException("closed-call and post-return store-tail contracts cannot be combined");
        // Compile all semantic refusals before even recording a program option.
        var trace = C6000PipelineCompiler.compileClosedCallsTrace(program, function, plans);
        C6000PipelineContracts.validateSourceScope(program, function, trace.schedule(), plans, monitor);
        var first = plans.get(0);
        if (!old.isEmpty()) {
            enable(program, function, first.evidence(), first.entry().previousE1Writes(), monitor);
            return trace;
        }
        int transaction = program.startTransaction("Enable reviewed closed-call decompilation");
        boolean commit = false;
        try {
            program.getOptions(OPTIONS).setString(closedCallsKey(function), new Gson().toJson(plans));
            enable(program, function, first.evidence(), first.entry().previousE1Writes(), monitor);
            monitor.checkCancelled();commit = true;return trace;
        }
        finally { program.endTransaction(transaction, commit); }
    }

    static C6000PipelineCompiler.Result compileConfigured(Program program, Function function,
            Set<String> writes) throws Exception {
        return compileConfigured(program, function, writes, TaskMonitor.DUMMY);
    }

    static C6000PipelineCompiler.Result compileConfigured(Program program, Function function,
            Set<String> writes, TaskMonitor monitor) throws Exception {
        monitor.checkCancelled();
        var calls = closedCalls(program, function);
        var tail = storeTailContract(program, function);
        if (!calls.isEmpty()) {
            if (tail != null) throw new IllegalArgumentException("closed-call and post-return store-tail contracts cannot be combined");
            validateClosedCallScope(program, function, calls);
            if (!calls.get(0).entry().previousE1Writes().equals(writes))
                throw new IllegalArgumentException("closed-call entry hazard assumptions changed");
            return C6000PipelineCompiler.compileClosedCallsTrace(program, function, calls).schedule();
        }
        var compiler = new C6000PipelineCompiler(program, function, writes);
        return tail == null ? compiler.compile(monitor) : compiler.compileStoreTail(tail).schedule();
    }

    /** Explicitly install an observation contract, atomically with reviewed activation.
     * Ordinary compile() still refuses pending returns. See SPRUFE8B 4.2.3/4.2.6.
     */
    public static C6000PipelineCompiler.Result enableStoreTail(Program program, Function function,
            String drainedEntryContract, Set<String> previousE1Writes,
            C6000PipelineCompiler.StoreTailContract tail, TaskMonitor monitor) throws Exception {
        Objects.requireNonNull(tail);
        var old = storeTailContract(program, function);
        if (C6000PipelineContracts.isRecorded(program, function) && !tail.equals(old))
            throw new IllegalArgumentException("Entry already reviewed with a different store-tail contract");
        if (drainedEntryContract == null || drainedEntryContract.isBlank())
            throw new IllegalArgumentException("Evidence for a drained entry pipeline is required");
        // Expected semantic refusals must not even create a program option.
        new C6000PipelineCompiler(program, function, previousE1Writes).compileStoreTail(tail);
        int transaction = program.startTransaction("Enable contracted post-return stores");
        boolean commit = false;
        try {
            program.getOptions(OPTIONS).setString(storeTailKey(function), new Gson().toJson(tail));
            var result = enable(program, function, drainedEntryContract, previousE1Writes, monitor);
            commit = true;
            return result;
        }
        finally { program.endTransaction(transaction, commit); }
    }
    /**
    * Compile before changing the listing. The caller must establish that there
    * are no pending writes or transfers at function entry,
    * and describe that evidence in drainedEntryContract. This is a precondition,
    * not something inferred from a C signature or an ordinary function boundary.
    * SPRUFE8B 3.5, 3.8.3 and 4.2 describe effects crossing such boundaries.
    */

    public static C6000PipelineCompiler.Result enable(Program program, Function function,             String drainedEntryContract, Set<String> previousE1Writes, TaskMonitor monitor) throws Exception {
        if (drainedEntryContract == null || drainedEntryContract.isBlank()) {
            throw new IllegalArgumentException("Evidence for a drained entry pipeline is required");
        }
        monitor.checkCancelled();
        var result = compileConfigured(program, function, previousE1Writes, monitor);
        var at = function.getEntryPoint();
        var context = program.getProgramContext();
        var enabled = context.getValue(program.getRegister("c_schedule_entry"), at, false);
        if (BigInteger.ONE.equals(enabled)) {
            if (C6000PipelineContracts.isPending(program, function)) {
                int transaction = program.startTransaction("Refresh reviewed exact schedule");
                boolean commit = false;
                try {
                    C6000PipelineContracts.validatePending(program, function,
                        drainedEntryContract, previousE1Writes, result, monitor);
                    includeFunctionScope(program, function, result);
                    program.getOptions(OPTIONS).setString(contractKey(function), drainedEntryContract);
                    program.getOptions(OPTIONS).setString(hazardsKey(function), String.join(",", new TreeSet<>(previousE1Writes)));
                    C6000PipelineContracts.bind(program, function, drainedEntryContract, previousE1Writes, result, monitor);
                    monitor.checkCancelled();commit = true;return result;
                }
                finally { program.endTransaction(transaction, commit); }
            }
            if (!String.join(",",new TreeSet<>(previousE1Writes)).equals(program.getOptions(OPTIONS).getString(hazardsKey(function), "")) || !drainedEntryContract.equals(program.getOptions(OPTIONS)                     .getString(contractKey(function), null))) {
                throw new IllegalArgumentException("Entry already enabled with a different contract");
            }
            if (C6000PipelineContracts.isRecorded(program, function)) {
                C6000PipelineContracts.validate(program, function, result, monitor);
            }
            else {
                // An explicit repeat of the legacy API attests its entry assumptions
                // again. Merely opening an old program never creates a binding.
                C6000PipelineContracts.bind(program, function, drainedEntryContract,
                    previousE1Writes, result, monitor);
            }
            return result;
        }
        var listing = program.getListing();
        var old = listing.getInstructionAt(at);
        if (old == null || old.isInDelaySlot()) {
            throw new IllegalArgumentException("Entry must be a defined instruction outside native delay slots");
        }
        int length = old.getLength();
        Address end = entryWindowEnd(program, function, old, monitor);
        var saved = annotations(program, at, end);
        int transaction = program.startTransaction("Enable exact C6000 pipeline schedule");
        boolean commit = false;
        try {
            if (C6000PipelineContracts.isPending(program, function)) {
                C6000PipelineContracts.validatePending(program, function,
                    drainedEntryContract, previousE1Writes, result, monitor);
            }
            listing.clearCodeUnits(at, end, false);
            context.setValue(program.getRegister("c_schedule_entry"), at, at, BigInteger.ONE);
            var command = new DisassembleCommand(at, new AddressSet(at, at.add(length - 1)), false);
            if (!command.applyTo(program, monitor)) {
                throw new IllegalStateException("Cannot decode scheduled entry: " + command.getStatusMsg());
            }
            var instruction = listing.getInstructionAt(at);
            if (instruction == null || instruction.getLength() != length || instruction.getDelaySlotDepth() != 0) {
                throw new IllegalStateException("Scheduled entry changed instruction extent");
            }
            // The entry's former slots become ordinary instructions the schedule issues itself (SPRUFE8B 3.5).
            if (end.compareTo(instruction.getMaxAddress()) > 0) {
                var slots = new DisassembleCommand(instruction.getMaxAddress().next(),
                    new AddressSet(instruction.getMaxAddress().next(), end), false);
                if (!slots.applyTo(program, monitor)) {
                    throw new IllegalStateException("Cannot decode scheduled entry slots: " + slots.getStatusMsg());
                }
            }
            restore(program, saved, false);
            includeFunctionScope(program, function, result);
            program.getOptions(OPTIONS).setString(contractKey(function), drainedEntryContract);
            program.getOptions(OPTIONS).setString(hazardsKey(function), String.join(",", new TreeSet<>(previousE1Writes)));
            C6000PipelineContracts.bind(program, function, drainedEntryContract,
                previousE1Writes, result, monitor);
            monitor.checkCancelled();
            commit = true;
            return result;
        }
        finally {
            program.endTransaction(transaction, commit);
        }
    }
    private static void includeFunctionScope(Program program, Function function,
            C6000PipelineCompiler.Result schedule) throws Exception {
        if (!closedCalls(program, function).isEmpty()) return;
        var body = new AddressSet(function.getBody());body.add(schedule.covered());function.setBody(body);
    }

    /** Explicitly return to ordinary instruction lifting; preserve listing annotations and scope. */
    public static void disable(Program program, Function function, TaskMonitor monitor) throws Exception {
        monitor.checkCancelled();
        if (!C6000PacketContext.isC6000(program)) throw new IllegalArgumentException("Expected C6000 program");
        var at = function.getEntryPoint();
        boolean active = BigInteger.ONE.equals(program.getProgramContext().getValue(program.getRegister("c_schedule_entry"), at, false));
        if (!active && !C6000PipelineContracts.isRecorded(program, function)) return;
        int transaction = program.startTransaction("Disable exact C6000 schedule");
        boolean commit = false;
        try {
            var listing = program.getListing();
            var old = listing.getInstructionAt(at);
            if (active && old != null) {
                int length = old.getLength();
                // The unchanged decode context re-derives the native slot window enable replaced.
                Address end = old.getMaxAddress().add(nativeDelayBytes(program, at));
                if (listing.getDefinedData(new AddressSet(at, end), true).hasNext())
                    throw new IllegalArgumentException("Cannot restore the entry's native delay window over defined data");
                var saved = annotations(program, at, end);
                listing.clearCodeUnits(at, end, false);
                program.getProgramContext().setValue(program.getRegister("c_schedule_entry"), at, at, BigInteger.ZERO);
                var disassemble = new DisassembleCommand(at, new AddressSet(at, end), false);
                if (!disassemble.applyTo(program, monitor)) throw new IllegalStateException("Cannot decode ordinary entry: " + disassemble.getStatusMsg());
                var instruction = listing.getInstructionAt(at);
                if (instruction == null || instruction.getLength() != length ||
                        !instruction.getMaxAddress().add(instruction.getPrototype().getDelaySlotByteCount()).equals(end))
                    throw new IllegalStateException("Ordinary entry changed instruction extent");
                restore(program, saved, true);
            } else if (active) program.getProgramContext().setValue(program.getRegister("c_schedule_entry"), at, at, BigInteger.ZERO);
            var options = program.getOptions(OPTIONS);
            for (String key : List.of(contractKey(function), hazardsKey(function), storeTailKey(function),
                    closedCallsKey(function), C6000PipelineContracts.key(function))) options.removeOption(key);
            monitor.checkCancelled();commit = true;
        } finally { program.endTransaction(transaction, commit); }
    }

}
