// SPDX-License-Identifier: Apache-2.0
package c6000;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Issue #52: keep functions with entered delay windows decompilable (C6000DelaySlots.relieveOverlaps). */
public final class C6000WindowOverlapAnalyzer extends AbstractAnalyzer {
    public C6000WindowOverlapAnalyzer() {
        super("C6000 Entered Delay Windows",
            "Releases a native delay window entered by a jump only when the decompiler cannot otherwise decompile its function",
            AnalyzerType.FUNCTION_ANALYZER);
        setDefaultEnablement(true);
        // After the windows and function bodies are final.
        setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after().after());
    }

    @Override
    public boolean canAnalyze(Program program) {
        return C6000PacketContext.isC6000(program);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        // `set` holds function entries. Scan each to the next function's entry: the
        // decompiler can follow flow past a stale body into unowned code.
        var functions = program.getFunctionManager();
        var scan = new AddressSet();
        for (var function : functions.getFunctions(set, true)) {
            monitor.checkCancelled();
            scan.add(function.getBody());
            var after = functions.getFunctions(function.getEntryPoint().next(), true);
            var next = after.hasNext() ? after.next() : null;
            var block = program.getMemory().getBlock(function.getEntryPoint());
            Address end = next != null && block != null && block.contains(next.getEntryPoint())
                ? next.getEntryPoint().previous() : block == null ? function.getEntryPoint() : block.getEnd();
            if (end.compareTo(function.getEntryPoint()) >= 0) scan.add(function.getEntryPoint(), end);
        }
        try {
            C6000DelaySlots.relieveOverlaps(program, scan, monitor);
        }
        catch (CancelledException e) { throw e; }
        catch (Exception e) {
            throw new IllegalStateException("C6000 entered delay-window release failed", e);
        }
        return true;
    }
}
