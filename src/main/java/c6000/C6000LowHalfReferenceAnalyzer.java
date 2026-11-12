// SPDX-License-Identifier: Apache-2.0
package c6000;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.util.Set;

// Drops the scalar DATA reference of an MVK low half that an MVKH completes to another value (SPRUFE8B pp. 380, 383).
public final class C6000LowHalfReferenceAnalyzer extends AbstractAnalyzer {
    // SPRUFE8B 4.2.6, Table 4-11: a branch lands six cycles after it issues, so none issued at or after the MVK lands within five.
    private static final int WINDOW = 5;
    private static final Set<String> BRANCHES = Set.of("B", "BNOP", "BDEC", "BPOS", "CALLP");
    private static final Set<String> UNTIMED = Set.of("IDLE", "SPLOOP", "SPLOOPD", "SPLOOPW", "SPKERNEL", "SPKERNELR", "SPMASK", "SPMASKR");

    public C6000LowHalfReferenceAnalyzer() {
        super("C6000 Low-Half References",
            "Removes the scalar data reference of an MVK whose register an MVKH completes to another address before anything reads it",
            AnalyzerType.INSTRUCTION_ANALYZER);
        setDefaultEnablement(true);
        // After Scalar Operand References, which adds the reference.
        setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
    }

    @Override
    public boolean canAnalyze(Program program) {
        return C6000PacketContext.isC6000(program);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        var references = program.getReferenceManager();
        for (Instruction mvk : program.getListing().getInstructions(set, true)) {
            monitor.checkCancelled();
            if (!op(mvk).equals("MVK") && !op(mvk).equals("MVKL")) continue;
            var scalar = mvk.getScalar(0);
            Register dst = mvk.getRegister(1);
            if (scalar == null || dst == null) continue;
            long low = scalar.getSignedValue() & 0xffffffffL;
            Long full;
            try {
                full = completed(program, mvk, dst, low);
            }
            catch (MemoryAccessException | IllegalArgumentException e) {
                continue;
            }
            if (full == null || full == low) continue;
            for (Reference r : references.getReferencesFrom(mvk.getAddress()))
                if (r.getSource() == SourceType.ANALYSIS && r.getReferenceType().isData() &&
                        r.getToAddress().getOffset() == low) references.delete(r);
        }
        return true;
    }

    // dst after an unpredicated MVKH within WINDOW cycles, or null if dst is read or written first or a branch may land before it.
    private static Long completed(Program program, Instruction mvk, Register dst, long low) throws MemoryAccessException {
        var listing = program.getListing();
        Instruction first = mvk;
        int span = 1;
        // MVK's own packet: a parallel write of dst conflicts; a parallel read sees the old value (SPRUFE8B 3.5).
        for (var at : C6000ExecutionPackets.issuePrefix(program, mvk.getAddress())) {
            var peer = listing.getInstructionAt(at);
            if (peer == null || writes(peer, dst)) return null;
            if (peer.getAddress().compareTo(first.getAddress()) < 0) first = peer;
            span = Math.max(span, cycles(program, peer));
        }
        Instruction cur = mvk;
        while (C6000ExecutionPackets.parallelWithNext(program, cur)) {
            cur = next(program, cur);
            if (cur == null || writes(cur, dst)) return null;
            span = Math.max(span, cycles(program, cur));
        }
        int cycle = 0;
        Long result = null;
        while (result == null) {
            cycle += span;
            if (cycle > WINDOW) return null;
            cur = next(program, cur);
            if (cur == null) return null;
            span = 1;
            while (true) {
                // MVKH keeps dst's low 16 bits, so its own read of dst completes the value (SPRUFE8B p. 383).
                if (result == null && op(cur).equals("MVKH") && dst.equals(cur.getRegister(1)) &&
                        !cur.getMnemonicString().contains("[") && cur.getScalar(0) != null)
                    result = (cur.getScalar(0).getUnsignedValue() & 0xffffL) << 16 | (low & 0xffffL);
                else if (reads(cur, dst) || writes(cur, dst)) return null;
                span = Math.max(span, cycles(program, cur));
                if (!C6000ExecutionPackets.parallelWithNext(program, cur)) break;
                cur = next(program, cur);
                if (cur == null) return null;
            }
        }
        return landsBefore(program, first, cycle) ? null : result;
    }

    // A branch issued in the WINDOW cycles before MVK's packet (cycle 0) may land in cycles 1..limit; stops at a function entry.
    private static boolean landsBefore(Program program, Instruction first, int limit) throws MemoryAccessException {
        var listing = program.getListing();
        int cycle = 0;
        Instruction start = first;
        while (true) {
            if (program.getFunctionManager().getFunctionAt(start.getAddress()) != null) return false;
            for (var i = start; i != null && C6000ExecutionPackets.parallelWithNext(program, i); i = next(program, i))
                if (jumpedTo(program, next(program, i))) return true;
            if (jumpedTo(program, start)) return true;
            if (cycle <= -WINDOW) return false;
            Instruction last = before(listing, start);
            if (last == null) return true;
            Instruction head = last;
            for (var b = before(listing, head); b != null && C6000ExecutionPackets.parallelWithNext(program, b); b = before(listing, head))
                head = b;
            int span = 1;
            for (var i = head; i != null && i.getAddress().compareTo(last.getAddress()) <= 0; i = next(program, i))
                span = Math.max(span, cycles(program, i));
            cycle -= span;
            for (var i = head; i != null && i.getAddress().compareTo(last.getAddress()) <= 0; i = next(program, i)) {
                boolean branch = BRANCHES.contains(op(i)) || i.getFlowType().isJump() || i.getFlowType().isCall();
                if (branch && cycle + 6 > 0 && cycle + 6 <= limit) return true;
            }
            start = head;
        }
    }

    // The contiguous instruction before i; a gap or fetch-packet header ends the walk.
    private static Instruction before(ghidra.program.model.listing.Listing listing, Instruction i) {
        var b = listing.getInstructionBefore(i.getAddress());
        return b != null && b.getMaxAddress().next().equals(i.getAddress()) && !op(b).equals("CPKT") ? b : null;
    }

    // The contiguous instruction after i; a gap or fetch-packet header ends the walk.
    private static Instruction next(Program program, Instruction i) {
        var n = program.getListing().getInstructionAfter(i.getAddress());
        return n != null && n.getMinAddress().equals(i.getMaxAddress().next()) && !op(n).equals("CPKT") ? n : null;
    }

    private static boolean jumpedTo(Program program, Instruction i) {
        if (i == null) return false;
        for (var r : program.getReferenceManager().getReferencesTo(i.getAddress()))
            if (r.getReferenceType().isFlow() && !r.getReferenceType().isFallthrough()) return true;
        return false;
    }

    private static String op(Instruction i) {
        return C6000CallAnalyzer.baseName(i).split("\\.")[0];
    }

    // SPRUFE8B 3.8.10: a packet lasts as long as its multicycle NOP; IDLE and loop-buffer timing are not modelled.
    private static int cycles(Program program, Instruction i) throws MemoryAccessException {
        String name = op(i);
        if (UNTIMED.contains(name)) throw new IllegalArgumentException("untimed packet at " + i.getAddress());
        if (name.equals("BNOP")) return 1 + C6000ExecutionPackets.bnopCount(program, i);
        if (name.equals("CALLP")) return 6;
        var count = name.equals("NOP") ? i.getScalar(0) : name.equals("ADDKPC") ? i.getScalar(2) : null;
        if (count == null) return 1;
        return name.equals("NOP") ? Math.max(1, (int) count.getUnsignedValue()) : 1 + (int) count.getUnsignedValue();
    }

    private static boolean writes(Instruction i, Register r) {
        for (Object o : i.getResultObjects()) if (o instanceof Register w && overlaps(w, r)) return true;
        return false;
    }

    private static boolean reads(Instruction i, Register r) {
        for (Object o : i.getInputObjects()) if (o instanceof Register w && overlaps(w, r)) return true;
        return false;
    }

    private static boolean overlaps(Register a, Register b) {
        return a.equals(b) || a.contains(b) || b.contains(a);
    }
}
