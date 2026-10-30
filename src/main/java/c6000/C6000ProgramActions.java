// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.util.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.*;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Native tool operations. No script discovery, execution or file manifests are involved. */
public final class C6000ProgramActions {
    private C6000ProgramActions() {}

    public static Set<String> previousWrites(Program program, String text) {
        var result = new TreeSet<String>();
        if (text == null || text.isBlank()) return Set.of();
        for (String value : text.trim().split("[,\\s]+")) {
            String name = value.toUpperCase(Locale.ROOT);
            if (!name.matches("[AB]([0-9]|[12][0-9]|3[01])") || program.getRegister(name) == null)
                throw new IllegalArgumentException("Previous-cycle writes must name registers A0–A31 or B0–B31: " + value);
            result.add(name);
        }
        return Set.copyOf(result);
    }

    public static boolean canModify(Program program) {
        return C6000PacketContext.isC6000(program) && !program.isClosed() && program.isChangeable();
    }

    private static void requireChangeable(Program program) {
        if (!canModify(program)) throw new IllegalArgumentException("This program view is immutable. Open an editable program to make changes.");
    }

    public static boolean supportedAddress(Program program, Address at) {
        return C6000PacketContext.isC6000(program) && at != null &&
            at.getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace()) &&
            (at.getOffset() & 1) == 0 && program.getMemory().getAllInitializedAddressSet().contains(at);
    }

    public static boolean canSetEntry(Program program, Address at) {
        if (!canModify(program) || !supportedAddress(program, at) || program.getListing().getDefinedDataContaining(at) != null) return false;
        try { C6000ExecutionPackets.instructionLengthAt(program, at); }
        catch (ghidra.program.model.mem.MemoryAccessException invalidSlot) { return false; }
        var instruction = program.getListing().getInstructionContaining(at);
        if (instruction != null && (!instruction.getAddress().equals(at) || instruction.isInDelaySlot() || instruction.getMnemonicString().equals("CPKT"))) return false;
        var function = program.getFunctionManager().getFunctionContaining(at);
        return function == null || function.getEntryPoint().equals(at);
    }

    /** A native background command: edits are one undoable transaction and refusals roll back. */
    public static final class SetEntry extends BackgroundCommand<Program> {
        private final Address address;
        public SetEntry(Address address) { super("Set C6000 entry point", true, true, false); this.address = address; }
        @Override public boolean applyTo(Program program, TaskMonitor monitor) {
            if (!canModify(program)) { setStatusMsg("Open an editable C6000 program to set an entry point");return false; }
            int transaction = program.startTransaction(getName());
            boolean commit = false;
            try {
                monitor.checkCancelled();
                if (!canSetEntry(program, address)) throw new IllegalArgumentException("Choose an executable instruction boundary in initialized memory, outside defined data and other function interiors");
                C6000PacketContext.prime(program, monitor);
                var disassemble = new DisassembleCommand(address, null, true);
                if (!disassemble.applyTo(program, monitor)) throw new IllegalArgumentException("Cannot disassemble entry: " + disassemble.getStatusMsg());
                var instruction = program.getListing().getInstructionAt(address);
                if (instruction == null || instruction.getMnemonicString().equals("CPKT") || instruction.isInDelaySlot())
                    throw new IllegalArgumentException("Choose an executable instruction, not a packet header or delay slot");
                var owner = program.getFunctionManager().getFunctionContaining(address);
                if (owner != null && !owner.getEntryPoint().equals(address))
                    throw new IllegalArgumentException("Address belongs to " + owner.getName() + "; choose its entry or an unowned address");
                if (owner == null) {
                    var create = new CreateFunctionCmd(address, false);
                    if (!create.applyTo(program, monitor)) throw new IllegalArgumentException("Cannot create entry function: " + create.getStatusMsg());
                }
                program.getSymbolTable().addExternalEntryPoint(address);
                monitor.checkCancelled();commit = true;return true;
            } catch (CancelledException cancelled) { setStatusMsg("Entry setup cancelled");return false;
            } catch (Exception failure) { setStatusMsg(failure.getMessage());return false;
            } finally { program.endTransaction(transaction, commit); }
        }
    }

    public static C6000PipelineContracts.Review preview(Program program, Address entry,
            String evidence, String writes, Address sourceStart, Address sourceEnd, TaskMonitor monitor) throws Exception {
        monitor.checkCancelled();
        if (!C6000PacketContext.isC6000(program)) throw new IllegalArgumentException("Open a C6000 program");
        if (AutoAnalysisManager.getAnalysisManager(program).isAnalyzing())
            throw new IllegalArgumentException("Wait for auto-analysis to finish, then preview again");
        if (sourceStart == null || sourceEnd == null || !sourceStart.getAddressSpace().equals(sourceEnd.getAddressSpace()) ||
            !sourceStart.getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace()) || sourceEnd.compareTo(sourceStart) < 0)
            throw new IllegalArgumentException("Choose an ordered evidence range in the default memory space");
        long size = sourceEnd.subtract(sourceStart) + 1;
        if (size > 65536 || (sourceStart.getOffset() & 31) != 0 || (size & 31) != 0 ||
                !program.getMemory().getAllInitializedAddressSet().contains(sourceStart, sourceEnd))
            throw new IllegalArgumentException("Evidence must cover whole initialized 32-byte fetch packets, at most 64 KiB");
        var function = program.getFunctionManager().getFunctionAt(entry);
        if (function == null) throw new IllegalArgumentException("Select a defined function");
        if (!C6000PipelineSchedules.closedCalls(program, function).isEmpty() ||
                C6000PipelineSchedules.storeTailContract(program, function) != null)
            throw new IllegalArgumentException("This function uses an advanced call or post-return observation contract. Use its API/batch review workflow; the ordinary GUI preview cannot review those assumptions.");
        if (C6000PipelineContracts.isRecorded(program, function) &&
                C6000PipelineContracts.recordedReview(program, function).entrySources().size() > 1)
            throw new IllegalArgumentException("This review pins multiple evidence ranges. Renew it with its API/batch workflow to preserve every source assumption.");
        long before = program.getModificationNumber();
        var bytes = new byte[(int) size];
        if (program.getMemory().getBytes(sourceStart, bytes) != bytes.length) throw new IllegalArgumentException("Cannot read evidence bytes");
        var source = new C6000PipelineContracts.SourceWindow(sourceStart.getOffset(), bytes.length, C6000PipelineContracts.sha256(bytes));
        var review = C6000PipelineContracts.review(program, function, evidence, previousWrites(program, writes), List.of(source), monitor);
        monitor.checkCancelled();
        if (before != program.getModificationNumber()) throw new IllegalArgumentException("Program changed during preview; preview again");
        return review;
    }

    public static boolean hasActiveReview(Program program, Function function) {
        return function != null && C6000PipelineContracts.isRecorded(program, function) &&
            java.math.BigInteger.ONE.equals(program.getProgramContext().getValue(program.getRegister("c_schedule_entry"), function.getEntryPoint(), false));
    }

    /** Run off the Swing thread. Revalidate the exact preview while Ghidra suspends analysis. */
    public static void activate(Program program, C6000PipelineContracts.Review review, TaskMonitor monitor) throws Exception {
        worker(program, "Enable reviewed C6000 schedule", monitor, (p, task) -> {
            var function = p.getFunctionManager().getFunctionAt(p.getAddressFactory().getDefaultAddressSpace().getAddress(review.entry()));
            if (function == null) throw new IllegalArgumentException("Reviewed function no longer exists");
            C6000PipelineContracts.record(p, function, review, task);
            C6000PipelineContracts.activate(p, function, task);
        });
    }

    public static void disable(Program program, Address entry, TaskMonitor monitor) throws Exception {
        worker(program, "Disable exact C6000 schedule", monitor, (p, task) -> {
            var function = p.getFunctionManager().getFunctionAt(entry);
            if (function == null) throw new IllegalArgumentException("Function no longer exists");
            C6000PipelineSchedules.disable(p, function, task);
        });
    }

    private interface Operation { void apply(Program program, TaskMonitor monitor) throws Exception; }
    private static void worker(Program program, String name, TaskMonitor monitor, Operation operation) throws Exception {
        requireChangeable(program);
        boolean completed = AutoAnalysisManager.getAnalysisManager(program).scheduleWorker(new AnalysisWorker() {
            @Override public String getWorkerName() { return name; }
            @Override public boolean analysisWorkerCallback(Program p, Object context, TaskMonitor task) throws Exception {
                requireChangeable(p);
                int transaction = p.startTransaction(getWorkerName());boolean commit = false;
                try { task.checkCancelled();operation.apply(p, task);task.checkCancelled();commit = true;return true;
                } finally { p.endTransaction(transaction, commit); }
            }
        }, null, false, monitor);
        monitor.checkCancelled();
        if (!completed) throw new IllegalStateException(name + " did not complete");
    }

    public static long validate(Program program, Address entry, TaskMonitor monitor) throws Exception {
        monitor.checkCancelled();
        long before = program.getModificationNumber();
        var function = program.getFunctionManager().getFunctionAt(entry);
        if (function == null || !C6000PipelineContracts.isRecorded(program, function))
            throw new IllegalArgumentException("This function has no recorded exact-schedule review");
        String writes = program.getOptions(C6000PipelineSchedules.OPTIONS).getString(C6000PipelineSchedules.hazardsKey(function), "");
        var schedule = C6000PipelineSchedules.compileConfigured(program, function, previousWrites(program, writes), monitor);
        C6000PipelineContracts.validate(program, function, schedule, monitor);
        monitor.checkCancelled();
        if (before != program.getModificationNumber()) throw new IllegalArgumentException("Program changed during validation; validate again");
        return before;
    }
}
