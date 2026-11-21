// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.math.BigInteger;
import java.util.*;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Prove finite native delay windows, then expose them to SLEIGH in bytes.
 * SPRUFE8B 3.5, 3.10.2.3, 4.2.6; B/BNOP/CALLP execution descriptions.
 * This is control-flow scheduling, not a register-write latency model.
 */
public final class C6000DelaySlots {
    private static final int MAX_BYTES = 254;
    private static final int MAX_INSTRUCTIONS = 64;
    /** Bookmark category on a branch whose window relieveOverlaps released. */
    public static final String RELEASED = "C6000 Released Delay Window";
    private C6000DelaySlots() { }

    public record Repair(String branch, String end, int delayBytes, int oldDepth,
            int newDepth, long addedBodyBytes) { }
    private record SavedRef(Reference reference, boolean primary, long symbolId) { }
    private record SavedInstruction(Address at, FlowOverride override, String[] comments,
            List<SavedRef> references, boolean fallThroughOverridden, Address fallThrough) { }
    private record Window(Instruction branch, Address end, Function owner) { }

    /**
     * The modification number at which a recovery last changed nothing. Recovery reads only the
     * program, so on the same program it would change nothing again: Late Branch Flow and Register
     * Branch Flow often run it back to back, over the whole program.
     */
    private static final Map<Program, Long> SETTLED = Collections.synchronizedMap(new WeakHashMap<>());

    /** B/BNOP or CALLP; nested transfers and ownership conflicts are refused. */
    public static List<Repair> recover(Program program, TaskMonitor monitor, MessageLog log)
            throws Exception {
        int transaction = program.startTransaction("Recover C6000 delay windows");
        try {
            long before = program.getModificationNumber();
            if (Long.valueOf(before).equals(SETTLED.get(program))) return new ArrayList<>();
            List<Repair> result = recoverWindows(program, monitor, log);
            if (result.isEmpty() && program.getModificationNumber() == before) SETTLED.put(program, before);
            else SETTLED.remove(program);
            // A disassembler poll stops quietly: report its cancel.
            monitor.checkCancelled();
            return result;
        }
        finally {
            // Aborting a nested transaction aborts all of auto-analysis; a failed window is put back instead.
            program.endTransaction(transaction, true);
        }
    }

    private static List<Repair> recoverWindows(Program program, TaskMonitor monitor, MessageLog log)
            throws Exception {
        Map<Address, C6000CallAnalyzer.Preemption> cuts = new HashMap<>();
        List<Repair> result = new ArrayList<>();
        int preempted = neutralise(program, cuts, result, monitor);
        if (preempted > 0) log.appendMsg("C6000 Delay Slots", "continued " + preempted + " preempted jump(s)");
        List<Address> candidates = new ArrayList<>(), stale = new ArrayList<>(), uncut = new ArrayList<>();
        var it = program.getListing().getInstructions(true);
        while (it.hasNext()) {
            var ins = it.next();
            String full = ins.getMnemonicString(), name = C6000CallAnalyzer.baseName(ins);
            // A latched branch has no window: the instruction it lands behind transfers.
            if (full.startsWith("_") || C6000PacketStagingAnalyzer.inert(ins)) continue;
            if (!(name.equals("B.S1") || name.equals("B.S2") || name.equals("BNOP.S1") ||
                    name.equals("BNOP.S2") || name.equals("CALLP.S1") || name.equals("CALLP.S2"))) continue;
            var override = ins.getFlowOverride();
            // Issue #34: the SLEIGH captures a predicate and target before the
            // slots, so predicated and delayed-call displacement branches are
            // lifted correctly once their window is proven.
            // The register form also captures predicate and target first, so a
            // register call, jump or return gets its window too (SPRUFE8B 4.2.6, B; issue #70).
            boolean displacement = ins.getRegister(0) == null;
            boolean tail = override == FlowOverride.CALL_RETURN && !full.startsWith("[") && !name.startsWith("CALLP");
            if (full.startsWith("[") && !displacement && override != FlowOverride.CALL && !cuts.containsKey(ins.getAddress())) {
                // A return's window that no cut supports this pass is stale unless its full window is proven.
                boolean cut = preemptingTransfer(ins) &&
                    ins.getPrototype().getDelaySlotByteCount() > parallelBytes(program, ins.getAddress());
                if (override != FlowOverride.NONE && override != FlowOverride.RETURN) {
                    if (cut) stale.add(ins.getAddress());
                    continue;
                }
                if (cut) uncut.add(ins.getAddress());
            }
            if (override != FlowOverride.NONE && override != FlowOverride.RETURN &&
                    override != FlowOverride.CALL && !tail) continue;
            candidates.add(ins.getAddress());
        }
        for (Address at : stale) result.add(release(program, program.getListing().getInstructionAt(at)));
        Reader reader = new Reader(program, cuts);
        for (Address at : candidates) {
            monitor.checkCancelled();
            if (!lay(program, reader, at, cuts.get(at), result, monitor) && uncut.contains(at))
                result.add(release(program, program.getListing().getInstructionAt(at)));
        }
        // Windows lay() did not lay or confirm: the packet primer's parallel-peer windows, say.
        List<Instruction> windowed = new ArrayList<>();
        for (Instruction ins : program.getListing().getInstructions(true))
            if (ins.getPrototype().getDelaySlotByteCount() > 0) windowed.add(ins);
        for (Instruction ins : windowed) proveFallThrough(program, ins);
        if (!result.isEmpty()) Msg.info(C6000DelaySlots.class, "C6000 Delay Slots> recovered " + result.size() + " proven window(s)");
        return result;
    }

    /** Lay the branch's proven window, cut where preemption's jump lands if non-null; true once it is laid. */
    private static boolean lay(Program program, Reader reader, Address at,
            C6000CallAnalyzer.Preemption preemption, List<Repair> result, TaskMonitor monitor) throws Exception {
        Instruction branch = program.getListing().getInstructionAt(at);
        if (branch == null || branch.isInDelaySlot()) return false;
        // Issue #52: relieveOverlaps released this window for the decompiler.
        if (program.getBookmarkManager().getBookmark(at, BookmarkType.ANALYSIS, RELEASED) != null) return false;
        Window window = reader.window(branch, monitor, preemption);
        if (window == null) return false;
        int bytes = (int) (window.end().subtract(branch.getMaxAddress()));
        if (bytes == 0) return branch.getPrototype().getDelaySlotByteCount() == 0;
        // A tail call inherits B3; a B that sets B3 returns (SPRUFE8B 4.2.6, B, ADDKPC).
        if (branch.getFlowOverride() == FlowOverride.CALL_RETURN &&
                (setsLink(program, reader, branch, window.end()) ||
                    new C6000CallAnalyzer.Walker(program).recognize(branch) != null)) return false;
        BigInteger old = program.getProgramContext().getValue(
            program.getRegister("c_flow_delay"), at, false);
        boolean nativeReady = old != null && old.intValue() == bytes &&
            branch.getPrototype().getDelaySlotByteCount() == bytes;
        if (nativeReady) {
            var last = program.getListing().getInstructionContaining(window.end());
            nativeReady = last != null && last.isInDelaySlot();
        }
        // A delayed call returns after its window; the call analyzer's
        // fallthrough to the first slot predates the window.
        boolean delayedCall=branch.getFlowOverride()==FlowOverride.CALL &&
            branch.getMaxAddress().next().equals(branch.getFallThrough());
        if (!nativeReady) {
            if (!canMaterialize(program, window, bytes, monitor)) return false;
            result.add(apply(program, window, bytes));
        }
        else if (window.owner() != null && !window.owner().getBody().contains(window.end())) {
            var body = new AddressSet(window.owner().getBody());
            long before = body.getNumAddresses();body.add(at, window.end());
            window.owner().setBody(body);
            result.add(new Repair(at.toString(),window.end().toString(),bytes,
                branch.getDelaySlotDepth(),branch.getDelaySlotDepth(),body.getNumAddresses()-before));
        }
        // Ghidra's generic fallthrough calculator parses the slots with the
        // issue's context: wrong across mixed widths, and for big-endian
        // compact slots, whose halfword is context (issue #31). Keep the
        // proven next execute-packet address.
        Instruction now = program.getListing().getInstructionAt(at);
        boolean generic = now.getFlowType().hasFallthrough() && !now.isFallThroughOverridden();
        Address resume = resume(program, window.end());
        // A call's slots are laid: its callee returns where B3 points, which the hardware decides.
        if (delayedCall) {
            Address link = new C6000CallAnalyzer.Walker(program).returnPoint(now);
            if (link != null) resume = link;
        }
        if ((delayedCall || generic) && !resume.equals(now.getFallThrough())) {
            now.setFallThrough(resume);
            if(nativeReady)result.add(new Repair(at.toString(),window.end().toString(),bytes,
                branch.getDelaySlotDepth(),branch.getDelaySlotDepth(),0));
        }
        return true;
    }

    /**
     * Issue #52: release native windows that make a function undecompilable.
     * A jump from outside into a window's slots is legal: the hardware runs the
     * slots in sequence from there (SPRUFE8B 3.5, 4.2.6). The decompiler lifts a
     * branch and its native slots as one instruction, re-reads an entered window
     * with an "overlaps instruction" warning and still produces correct C, but
     * Ghidra 12.2 counts each overlap as bad data and abandons the function past
     * its limit (four by default). Decompile each function holding an entered
     * window; while it fails on an overlap, release the window the error names
     * and retry. Only those windows lose their delay-slot lifting.
     * @return the number of windows released
     */
    public static int relieveOverlaps(Program program, AddressSetView set, TaskMonitor monitor)
            throws Exception {
        var functions = program.getFunctionManager();
        Set<Function> candidates = new LinkedHashSet<>();
        for (Instruction branch : program.getListing().getInstructions(set, true)) {
            monitor.checkCancelled();
            int laid = branch.getPrototype().getDelaySlotByteCount();
            Address at = branch.getAddress();
            if (laid <= parallelBytes(program, at) || !entered(program, at, branch.getMaxAddress().add(laid))) continue;
            // The decompiler follows flow past a stale body: also try the function before unowned code.
            Function owner = functions.getFunctionContaining(at);
            if (owner == null) {
                var before = functions.getFunctions(at, false);
                owner = before.hasNext() ? before.next() : null;
            }
            if (owner != null) candidates.add(owner);
        }
        if (candidates.isEmpty()) return 0;
        int released = 0;
        var decompiler = new ghidra.app.decompiler.DecompInterface();
        // Default options: the CodeBrowser's bad-data limit is not a tool option.
        decompiler.setOptions(new ghidra.app.decompiler.DecompileOptions());
        if (!decompiler.openProgram(program)) return 0;
        int transaction = program.startTransaction("Release C6000 delay windows for the decompiler");
        try {
            for (Function function : candidates) {
                for (int attempt = 0; attempt < MAX_INSTRUCTIONS && !function.isDeleted(); attempt++) {
                    monitor.checkCancelled();
                    var result = decompiler.decompileFunction(function, 60, monitor);
                    if (result == null || result.decompileCompleted()) break;
                    String error = result.getErrorMessage();
                    Instruction branch = overlapped(program, error);
                    // Other bad data (an unmapped target, say) can be the last straw:
                    // the function's own entered windows still count toward the limit.
                    if (branch == null && error != null && error.contains("Bad instruction count exceeded"))
                        branch = enteredIn(program, function);
                    if (branch == null) break;
                    Address at = branch.getAddress();
                    if (branch.getPrototype().getDelaySlotByteCount() <= parallelBytes(program, at)) break;
                    // Entered only at NOP slots, which only idle (SPRUFE8B p. 388): end the window before them and keep every effect.
                    Address idle = idleTail(program, branch);
                    if (idle != null) release(program, branch, (int) idle.subtract(branch.getMaxAddress()) - 1);
                    else release(program, branch);
                    uncontinue(program, at);
                    Instruction now = program.getListing().getInstructionAt(at);
                    if (now != null) proveFallThrough(program, now);
                    decompiler.flushCache();
                    program.getBookmarkManager().setBookmark(at, BookmarkType.ANALYSIS, RELEASED,
                        (idle != null ? "Native delay window ended before its entered NOP slots at " + idle + ": "
                            : "Native delay window released: ") + function.getName() +
                        " exceeded the decompiler's overlapping-instruction limit (issue #52)");
                    released++;
                }
            }
            // A cancelled decompile only fails: report the cancel.
            monitor.checkCancelled();
        }
        finally {
            // Never abort: release puts a failed window back (see recover).
            program.endTransaction(transaction, true);
            decompiler.dispose();
        }
        if (released > 0) Msg.info(C6000DelaySlots.class, "C6000 Delay Slots> released " + released +
            " entered window(s) for the decompiler");
        return released;
    }

    private static final java.util.regex.Pattern OVERLAP = java.util.regex.Pattern.compile(
        "overlaps instruction at \\((\\w+),0x([0-9a-fA-F]+)\\)");

    /** The branch whose native window a decompiler "overlaps instruction" error names. */
    private static Instruction overlapped(Program program, String error) {
        var m = error == null ? null : OVERLAP.matcher(error);
        if (m == null || !m.find()) return null;
        var space = program.getAddressFactory().getAddressSpace(m.group(1));
        if (space == null) return null;
        return program.getListing().getInstructionAt(space.getAddress(Long.parseUnsignedLong(m.group(2), 16)));
    }

    /** The first branch in the function's body whose laid window is entered, or null. */
    private static Instruction enteredIn(Program program, Function function) {
        for (Instruction branch : program.getListing().getInstructions(function.getBody(), true)) {
            int laid = branch.getPrototype().getDelaySlotByteCount();
            Address at = branch.getAddress();
            if (laid > parallelBytes(program, at) && entered(program, at, branch.getMaxAddress().add(laid))) return branch;
        }
        return null;
    }

    /** First slot entered from outside the window when only NOPs follow to its end, else null. */
    private static Address idleTail(Program program, Instruction branch) {
        Address at = branch.getAddress(), end = branch.getMaxAddress().add(branch.getPrototype().getDelaySlotByteCount());
        Address first = firstEntry(program, at, end);
        if (first == null || first.compareTo(branch.getMaxAddress().add(parallelBytes(program, at))) <= 0) return null;
        var listing = program.getListing();
        for (Address cursor = first; cursor.compareTo(end) <= 0;) {
            Instruction slot = listing.getInstructionAt(cursor);
            if (slot == null || !C6000CallAnalyzer.baseName(slot).equals("NOP")) return null;
            cursor = slot.getMaxAddress().next();
        }
        return first;
    }

    /** Control from outside [at, end] reaches one of the slots after at. */
    private static boolean entered(Program program, Address at, Address end) {
        return firstEntry(program, at, end) != null;
    }

    /** The lowest slot after at that control from outside [at, end] reaches, or null. */
    private static Address firstEntry(Program program, Address at, Address end) {
        var references = program.getReferenceManager();
        var targets = references.getReferenceDestinationIterator(new AddressSet(at.next(), end), true);
        while (targets.hasNext()) {
            Address target = targets.next();
            for (var it = references.getReferencesTo(target); it.hasNext();) {
                Reference r = it.next();
                Address from = r.getFromAddress();
                if (r.getReferenceType().isFlow() && (from.compareTo(at) < 0 || from.compareTo(end) > 0)) return target;
            }
        }
        return null;
    }

    /** A return through B3. */
    static boolean preemptingTransfer(Instruction transfer) {
        var register = transfer.getRegister(0);
        var override = transfer.getFlowOverride();
        return register != null && register.getName().equals("B3") && !C6000PacketStagingAnalyzer.flow(transfer).isCall() &&
            override != FlowOverride.CALL && override != FlowOverride.CALL_RETURN;
    }

    /** Whether the jump's branch is overridden to continue (see neutralise). */
    static boolean continues(Program program, Instruction jump) {
        for (Reference r : program.getReferenceManager().getReferencesFrom(jump.getAddress())) {
            if (r.getReferenceType() == RefType.JUMP_OVERRIDE_UNCONDITIONAL && r.isPrimary()) return true;
        }
        return false;
    }

    /** Bytes of the branch's own execute packet after it: the primer's c_flow_delay (C6000PacketContext). */
    private static int parallelBytes(Program program, Address at) {
        try { return C6000ExecutionPackets.parallelBytes(program, at); }
        catch (MemoryAccessException e) { return 0; }
    }

    /**
     * Undo apply(): the slots become ordinary instructions again, lifted after
     * the transfer as before issues #34 and #48. Keep the branch's override, the
     * slots' annotations and every reference.
     */
    private static Repair release(Program p, Instruction original) throws Exception {
        return release(p, original, parallelBytes(p, original.getAddress()));
    }

    /** As above, but the first keep bytes after the branch stay in its window. */
    private static Repair release(Program p, Instruction original, int keep) throws Exception {
        var listing = p.getListing();
        Address at = original.getAddress();
        Address end = original.getMaxAddress().add(original.getPrototype().getDelaySlotByteCount());
        int oldDepth = original.getDelaySlotDepth();
        FlowOverride override = original.getFlowOverride();
        List<SavedInstruction> saved = snapshot(p, at, end);
        var undo = Undo.of(p, at, end, override, saved);
        listing.clearCodeUnits(at, end, false);
        try {
            p.getProgramContext().setValue(p.getRegister("c_flow_delay"), at, at, BigInteger.valueOf(keep));
            // Never polled: a cancel here would leave the window half decoded.
            Disassembler disassembler = Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null);
            // A terminal branch has no fall-through: decode each released slot run too.
            for (Address cursor = at; cursor.compareTo(end) <= 0;) {
                if (listing.getInstructionContaining(cursor) == null)
                    disassembler.disassemble(cursor, new AddressSet(cursor, end), false);
                var ins = listing.getInstructionContaining(cursor);
                if (ins == null) throw new IllegalStateException("Could not re-decode released window at " + cursor);
                cursor = ins.getMaxAddress().next();
            }
            var branch = listing.getInstructionAt(at);
            if (branch == null || branch.getPrototype().getDelaySlotByteCount() != keep)
                throw new IllegalStateException("Could not release native delay window at " + at + ": " + branch);
            branch.setFlowOverride(override);
            // The fall-through past the window belonged to the window; any other override stays.
            restore(p, at, saved, false, resume(p, end));
            return new Repair(at.toString(), end.toString(), keep, oldDepth, branch.getDelaySlotDepth(), 0);
        }
        catch (Exception failure) {
            throw undo.putBack(failure);
        }
    }

    /**
     * Ghidra's generic fall-through re-parses the slots with the issue's context, so it is wrong
     * across mixed widths and for big-endian compact slots (issue #31; Ghidra #10242). Give a
     * windowed conditional jump with no fall-through override the next execute packet after its
     * native window. Returns whether it changed.
     */
    private static boolean proveFallThrough(Program p, Instruction ins) {
        int bytes = ins.getPrototype().getDelaySlotByteCount();
        if (bytes == 0 || !ins.getFlowType().isJump() || !ins.getFlowType().hasFallthrough()) return false;
        Address end, resume;
        try { end = ins.getMaxAddress().add(bytes); resume = resume(p, end); }
        catch (AddressOutOfBoundsException e) { return false; }
        boolean changed = false;
        if (!ins.isFallThroughOverridden() && !resume.equals(ins.getFallThrough())) {
            ins.setFallThrough(resume);
            changed = true;
        }
        if (!resume.equals(ins.getFallThrough())) return changed;
        // Ghidra's body walk (FollowFlow) counts slots with the same generic parse and can drop the
        // tail of the window once the fall-through skips it: keep the window, as lay() does.
        Function owner = p.getFunctionManager().getFunctionContaining(ins.getAddress());
        if (owner != null && !owner.getBody().contains(ins.getAddress(), end)) {
            var body = new AddressSet(owner.getBody());
            body.add(ins.getAddress(), end);
            try { owner.setBody(body); }
            catch (ghidra.program.database.function.OverlappingFunctionException e) { }
        }
        return changed;
    }

    /** The next execute packet after a window ending at end: past a fetch-packet header (SPRUFE8B 3.10.2). */
    private static Address resume(Program program, Address end) {
        Address next = end.next();
        try {
            if ((next.getOffset() & 31) == 28 && (program.getMemory().getInt(next) >>> 28) == 0xe) return next.add(4);
        }
        catch (MemoryAccessException | AddressOutOfBoundsException e) { }
        return next;
    }

    /**
     * A jump whose target only idles until a return issued in its
     * window lands (C6000CallAnalyzer.Preemption) leaves nothing to its target:
     * execution goes on through its window. Override its branch to its own
     * fall-through and drop the edge to the target, whose NOPs are usually
     * another return's delay slots. The return's window then ends where the
     * jump lands (Reader.window), so the jump is continued only once that
     * shortened window is laid; only the window's code is decoded before. An analysis
     * override whose preemption no longer holds is removed. Fills cuts with
     * the return of every continued jump; recoverWindows releases a predicated
     * return's window that no cut supports any more.
     * @return the number of jumps continued or restored
     */
    private static int neutralise(Program program, Map<Address, C6000CallAnalyzer.Preemption> cuts,
            List<Repair> result, TaskMonitor monitor) throws Exception {
        var listing = program.getListing();
        var references = program.getReferenceManager();
        var walker = new C6000CallAnalyzer.Walker(program);
        var reader = new Reader(program, Map.of());
        List<Address> jumps = new ArrayList<>();
        for (var it = listing.getInstructions(true); it.hasNext();) {
            var ins = it.next();
            if (C6000CallAnalyzer.Walker.displacementJump(ins)) jumps.add(ins.getAddress());
        }
        Disassembler disassembler = null;
        int count = 0;
        for (Address at : jumps) {
            monitor.checkCancelled();
            // Disassembly below can change the listing the list was taken from.
            Instruction jump = listing.getInstructionAt(at);
            if (jump == null || !C6000CallAnalyzer.Walker.displacementJump(jump)) continue;
            Address target = jump.getDefaultFlows()[0];
            Address next = jump.getMaxAddress().next().add(jump.getPrototype().getDelaySlotByteCount());
            Reference ours = null;
            boolean overridden = false, other = false;
            for (Reference r : references.getReferencesFrom(at)) {
                if (r.getReferenceType() != RefType.JUMP_OVERRIDE_UNCONDITIONAL) continue;
                if (r.getToAddress().equals(next) && r.isPrimary()) {
                    overridden = true;
                    if (r.getSource() == SourceType.ANALYSIS) ours = r;
                }
                else other = true;
            }
            // Someone else's override stands.
            if (other) continue;
            var preemption = walker.preemption(jump);
            boolean proven = preemption != null && preemption.exact() && preemptingTransfer(preemption.transfer()) &&
                reader.window(preemption.transfer(), monitor, preemption) != null;
            boolean changed = false;
            if (proven && listing.getInstructionAt(next) == null) {
                if (disassembler == null) disassembler = Disassembler.getDisassembler(program, monitor, null);
                disassembler.disassemble(next, null, true);
                changed = true;
            }
            // Proven is not laid: lay the return's cut window before the jump continues.
            proven = proven && lay(program, reader, preemption.transfer().getAddress(), preemption, result, monitor);
            if (!proven) {
                if (ours != null) {
                    restoreJump(program, jump, ours, target);
                    count++;
                }
                continue;
            }
            cuts.put(preemption.transfer().getAddress(), preemption);
            for (Reference r : references.getReferencesFrom(at)) {
                if (r.getReferenceType().isFlow() && !r.getReferenceType().isOverride() && r.getToAddress().equals(target)) {
                    references.delete(r);
                    changed = true;
                }
            }
            if (!overridden) {
                var r = references.addMemoryReference(at, next, RefType.JUMP_OVERRIDE_UNCONDITIONAL,
                    SourceType.ANALYSIS, 0);
                references.setPrimary(r, true);
                changed = true;
            }
            if (!changed) continue;
            count++;
            // The window runs after the jump on every path: the jump's function owns it.
            // Extend the body only; recomputing it from flow could absorb a later entry.
            Function owner = program.getFunctionManager().getFunctionContaining(at);
            var window = new AddressSet(next, preemption.windowEnd());
            if (owner != null && !owner.getBody().contains(window)) {
                boolean free = true;
                for (var it = program.getFunctionManager().getFunctionsOverlapping(window); it.hasNext();)
                    if (!it.next().equals(owner)) free = false;
                if (free) {
                    try { owner.setBody(new AddressSet(owner.getBody()).union(window)); }
                    catch (ghidra.program.database.function.OverlappingFunctionException e) { }
                }
            }
        }
        return count;
    }

    /** Give each jump continued on the released return at at (neutralise) its target back. */
    private static void uncontinue(Program program, Address at) {
        var walker = new C6000CallAnalyzer.Walker(program);
        for (int i = 1; i <= C6000CallAnalyzer.MAX_WINDOW && at.getOffset() >= 4L * i; i++) {
            Instruction jump = program.getListing().getInstructionAt(at.subtract(4L * i));
            if (jump == null || !C6000CallAnalyzer.Walker.displacementJump(jump)) continue;
            for (Reference r : program.getReferenceManager().getReferencesFrom(jump.getAddress())) {
                if (r.getReferenceType() != RefType.JUMP_OVERRIDE_UNCONDITIONAL || !r.isPrimary() ||
                        r.getSource() != SourceType.ANALYSIS) continue;
                var preemption = walker.preemption(jump);
                if (preemption != null && preemption.transfer().getAddress().equals(at))
                    restoreJump(program, jump, r, jump.getDefaultFlows()[0]);
                break;
            }
        }
    }

    /**
     * Undo neutralise for a jump whose preemption no longer holds: drop our
     * override and restore the edge to its target. The return's cut window is
     * released or recomputed by the recovery that follows.
     */
    private static void restoreJump(Program program, Instruction jump, Reference ours, Address target) {
        var references = program.getReferenceManager();
        references.delete(ours);
        for (Reference r : references.getReferencesFrom(jump.getAddress()))
            if (r.getReferenceType().isFlow() && r.getToAddress().equals(target)) return;
        references.addMemoryReference(jump.getAddress(), target, jump.getFlowType(), SourceType.DEFAULT, 0);
    }

    /** Last byte of a branch's proven delay window, or null when it is not proven. */
    static Address windowEnd(Program program, Instruction branch, TaskMonitor monitor)
            throws CancelledException {
        Window window = new Reader(program).window(branch, monitor);
        return window == null ? null : window.end();
    }

    /** Whether the branch's packet or window writes B3 other than by a load restoring it. */
    private static boolean setsLink(Program p, Reader reader, Instruction branch, Address end) {
        var b3 = p.getRegister("B3");
        List<Instruction> packet = new ArrayList<>();
        try {
            for (Address at : C6000ExecutionPackets.issuePrefix(p, branch.getAddress())) packet.add(reader.decode(at));
        }
        catch (MemoryAccessException e) {
            return true;
        }
        for (Instruction i = reader.next(branch); i != null && i.getMinAddress().compareTo(end) <= 0; i = reader.next(i)) {
            packet.add(i);
        }
        for (Instruction i : packet) {
            if (i == null) return true;
            if (C6000CallAnalyzer.baseName(i).startsWith("LD")) continue;
            for (Object o : C6000PacketStagingAnalyzer.hardware(i).getResultObjects()) {
                if (o instanceof ghidra.program.model.lang.Register r && r.contains(b3)) return true;
            }
        }
        return false;
    }

    /** Dry-run native parsing with the proposed context before removing any code units. */
    private static boolean canMaterialize(Program p, Window window, int bytes, TaskMonitor monitor) {
        Instruction issue = window.branch();
        Address at = issue.getAddress();
        var base = p.getLanguage().getContextBaseRegister();
        RegisterValue context = p.getProgramContext().getRegisterValue(base, at);
        if (context == null) context = new RegisterValue(base);
        context = context.combineValues(new RegisterValue(p.getRegister("c_flow_delay"),
            BigInteger.valueOf(bytes)));
        if (issue.getRegister(0) != null && !issue.getMnemonicString().startsWith("CALLP")) {
            context = context.combineValues(new RegisterValue(p.getRegister("c_branch_terminal"),
                BigInteger.ONE));
        }
        var disassembler = Disassembler.getDisassembler(p, monitor, null);
        // The pseudo parser's default argument cannot override stored context.
        // Supply an explicit future seed without writing the ProgramContext.
        var seed = new ghidra.program.disassemble.DisassemblerContextImpl(p.getProgramContext());
        seed.setFutureRegisterValue(at, context);
        disassembler.setSeedContext(seed);
        var block = disassembler.pseudoDisassembleBlock(
            new ghidra.program.model.mem.DumbMemBufferImpl(p.getMemory(), at), context, 1);
        if (block == null) return false;
        var branch = block.getInstructionAt(at);
        var tail = block.findFirstIntersectingInstruction(window.end(), window.end());
        return branch != null && branch.getPrototype().getDelaySlotByteCount() == bytes &&
            tail != null && tail.isInDelaySlot() && tail.getMaxAddress().equals(window.end());
    }

    private static Repair apply(Program p, Window window, int bytes)
            throws Exception {
        var listing = p.getListing();var original = window.branch();
        Address at = original.getAddress();int oldDepth = original.getDelaySlotDepth();
        FlowOverride override = original.getFlowOverride();
        boolean registerBranch=original.getRegister(0)!=null && !original.getMnemonicString().startsWith("CALLP");
        // A shorter window than the native one releases the old slots too.
        Address end = window.end(), old = original.getMaxAddress().add(original.getPrototype().getDelaySlotByteCount());
        // A jump's fall-through proven for the old window (proveFallThrough) goes with it.
        Address oldResume = original.getFlowType().isJump() && original.getPrototype().getDelaySlotByteCount() > 0 ?
            resume(p, old) : null;
        if (old.compareTo(end) > 0) end = old;
        List<SavedInstruction> saved = snapshot(p, at, end);
        var undo = Undo.of(p, at, end, override, saved);
        // A B B3 proven a call keeps its CALL override (issue #39).
        boolean isReturn = override == FlowOverride.RETURN || (override != FlowOverride.CALL &&
            original.getNumOperands()>0 && "B3".equals(original.getDefaultOperandRepresentation(0)) &&
                !original.getMnemonicString().startsWith("CALLP"));
        if(isReturn)override=FlowOverride.RETURN;
        listing.clearCodeUnits(at,end,false);
        try {
            p.getProgramContext().setValue(p.getRegister("c_flow_delay"),at,at,BigInteger.valueOf(bytes));
            if(registerBranch)
                p.getProgramContext().setValue(p.getRegister("c_branch_terminal"),at,at,BigInteger.ONE);
            // Never polled: a cancel here would leave the window half decoded.
            Disassembler disassembler=Disassembler.getDisassembler(p,TaskMonitor.DUMMY,null);
            disassembler.disassemble(at,new AddressSet(at,end),false);
            // The released slots after a terminal transfer are reached by no fall-through.
            if(end.compareTo(window.end())>0&&listing.getInstructionContaining(window.end().next())==null)
                disassembler.disassemble(window.end().next(),new AddressSet(window.end().next(),end),false);
            var branch=listing.getInstructionAt(at);var tail=listing.getInstructionContaining(window.end());
            if(branch==null||branch.getPrototype().getDelaySlotByteCount()!=bytes||tail==null||!tail.isInDelaySlot())
                throw new IllegalStateException("Could not materialize native delay window at "+at+" end="+window.end()+" bytes="+bytes+" branch="+branch+" depth="+(branch==null?-1:branch.getDelaySlotDepth())+" tail="+tail);
            branch.setFlowOverride(override);
            restore(p, at, saved, isReturn, oldResume);
            long added=0;
            if(window.owner()!=null) {
                var body=new AddressSet(window.owner().getBody());long before=body.getNumAddresses();
                body.add(at,window.end());window.owner().setBody(body);added=body.getNumAddresses()-before;
            }
            return new Repair(at.toString(),window.end().toString(),bytes,oldDepth,branch.getDelaySlotDepth(),added);
        }
        catch (Exception failure) {
            throw undo.putBack(failure);
        }
    }

    /** The instruction that owns {@code ins} when it is a delay slot, else {@code ins}. */
    static Instruction unitOwner(Program p, Instruction ins) {
        Instruction owner = ins;
        while (owner != null && owner.isInDelaySlot()) owner = p.getListing().getInstructionBefore(owner.getAddress());
        return owner == null ? ins : owner;
    }

    /**
     * Decode the instruction at {@code at} and its native delay window again with context fields
     * changed: {@code fields} maps an instruction's address to the fields to set there. Every
     * instruction keeps its place, length, override, fall-through, references and comments; on a
     * failure everything is put back as it was.
     */
    static void recontext(Program p, Address at, Map<Address, Map<Register, BigInteger>> fields) throws Exception {
        var listing = p.getListing();
        Instruction first = listing.getInstructionAt(at);
        if (first == null || first.isInDelaySlot()) throw new IllegalArgumentException("no instruction unit at " + at);
        Address end = first.getMaxAddress().add(first.getPrototype().getDelaySlotByteCount());
        FlowOverride override = first.getFlowOverride();
        List<SavedInstruction> saved = snapshot(p, at, end);
        var undo = Undo.of(p, at, end, override, saved);
        listing.clearCodeUnits(at, end, false);
        try {
            for (var unit : undo.units()) {
                RegisterValue context = unit.context();
                for (var field : fields.getOrDefault(unit.at(), Map.of()).entrySet()) {
                    context = context.assign(field.getKey(), field.getValue());
                    p.getProgramContext().setValue(field.getKey(), unit.at(), unit.at(), field.getValue());
                }
                var decode = new ProcessorContextImpl(p.getLanguage());
                decode.setRegisterValue(context);
                var buffer = new DumbMemBufferImpl(p.getMemory(), unit.at());
                var prototype = p.getLanguage().parse(buffer, decode, unit.prototype().isInDelaySlot());
                if (prototype.getLength() != unit.prototype().getLength() ||
                    prototype.getDelaySlotByteCount() != unit.prototype().getDelaySlotByteCount())
                    throw new IllegalStateException("context change alters the instruction at " + unit.at());
                listing.createInstruction(unit.at(), prototype, buffer, decode, unit.length());
            }
            listing.getInstructionAt(at).setFlowOverride(override);
            restore(p, at, saved, false, null);
        }
        catch (Exception failure) {
            throw undo.putBack(failure);
        }
    }

    /** What {@link #relift} replaced, to put back if the new lifting does not hold. */
    interface Relifted {
        void putBack();
    }

    /**
     * Decode [start, end] again as straight-line code with the context fields in {@code fields}
     * set, and with no native delay window on any instruction named there. Overrides, references
     * and comments are kept; a failure puts everything back.
     */
    static Relifted relift(Program p, Address start, Address end, Map<Address, Map<Register, BigInteger>> fields)
            throws Exception {
        var listing = p.getListing();
        Instruction first = listing.getInstructionAt(start);
        if (first == null || first.isInDelaySlot()) throw new IllegalArgumentException("no instruction unit at " + start);
        FlowOverride override = first.getFlowOverride();
        List<SavedInstruction> saved = snapshot(p, start, end);
        var undo = Undo.of(p, start, end, override, saved);
        listing.clearCodeUnits(start, end, false);
        try {
            for (var entry : fields.entrySet())
                for (var field : entry.getValue().entrySet())
                    p.getProgramContext().setValue(field.getKey(), entry.getKey(), entry.getKey(), field.getValue());
            Disassembler.getDisassembler(p, TaskMonitor.DUMMY, null).disassemble(start, new AddressSet(start, end), false);
            for (var unit : undo.units()) {
                Instruction now = listing.getInstructionAt(unit.at());
                if (now == null || now.getLength() != unit.prototype().getLength() || now.isInDelaySlot() ||
                    now.getPrototype().hasDelaySlots())
                    throw new IllegalStateException("could not decode " + unit.at() + " as straight-line code");
            }
            listing.getInstructionAt(start).setFlowOverride(override);
            restore(p, start, saved, false, null);
            return () -> undo.putBack(new IllegalStateException("lifting taken back"));
        }
        catch (Exception failure) {
            throw undo.putBack(failure);
        }
    }

    private record SavedUnit(Address at, InstructionPrototype prototype, RegisterValue context, int length) { }

    /** What clearing [at, end] removes: instructions and their context, stored context, annotations. */
    private record Undo(Program p, Address at, Address end, FlowOverride override, List<SavedInstruction> saved,
            List<SavedUnit> units, Map<Address, RegisterValue> context) {
        static Undo of(Program p, Address at, Address end, FlowOverride override, List<SavedInstruction> saved) {
            var base = p.getLanguage().getContextBaseRegister();
            List<SavedUnit> units = new ArrayList<>();
            for (var ins : p.getListing().getInstructions(new AddressSet(at, end), true))
                units.add(new SavedUnit(ins.getAddress(), ins.getPrototype(), ins.getRegisterValue(base),
                    ins.isLengthOverridden() ? ins.getLength() : 0));
            Map<Address, RegisterValue> context = new HashMap<>();
            for (Address cursor = at; cursor.compareTo(end) <= 0; cursor = cursor.next())
                context.put(cursor, p.getProgramContext().getNonDefaultValue(base, cursor));
            return new Undo(p, at, end, override, saved, units, context);
        }

        /** Put the window back as it was before it was cleared; return failure to rethrow. */
        Exception putBack(Exception failure) {
            try {
                var listing = p.getListing();
                var programContext = p.getProgramContext();
                var base = p.getLanguage().getContextBaseRegister();
                listing.clearCodeUnits(at, end, false);
                for (var entry : context.entrySet()) {
                    Address cursor = entry.getKey();
                    if (Objects.equals(programContext.getNonDefaultValue(base, cursor), entry.getValue())) continue;
                    if (entry.getValue() == null) programContext.remove(cursor, cursor, base);
                    else programContext.setRegisterValue(cursor, cursor, entry.getValue());
                }
                for (var unit : units) {
                    var decode = new ProcessorContextImpl(p.getLanguage());
                    if (unit.context() != null) decode.setRegisterValue(unit.context());
                    listing.createInstruction(unit.at(), unit.prototype(),
                        new DumbMemBufferImpl(p.getMemory(), unit.at()), decode, unit.length());
                }
                var branch = listing.getInstructionAt(at);
                if (branch != null) branch.setFlowOverride(override);
                restore(p, at, saved, false, null);
            }
            catch (Exception again) {
                failure.addSuppressed(again);
            }
            return failure;
        }
    }

    /** Annotations in [at, end]. Undisassembled tail bytes can already carry user comments and refs. */
    private static List<SavedInstruction> snapshot(Program p, Address at, Address end) {
        var listing = p.getListing();
        List<SavedInstruction> saved = new ArrayList<>();
        // Snapshot every address, including those without a defined instruction.
        for(Address cursor=at;cursor.compareTo(end)<=0;cursor=cursor.next()) {
            var ins=listing.getInstructionAt(cursor);List<SavedRef> refs=new ArrayList<>();
            for(var r:p.getReferenceManager().getReferencesFrom(cursor))
                refs.add(new SavedRef(r,r.isPrimary(),r.getSymbolID()));
            String[] comments=new String[5];for(int i=0;i<5;i++)comments[i]=listing.getComment(i,cursor);
            saved.add(new SavedInstruction(cursor,ins==null?FlowOverride.NONE:ins.getFlowOverride(),comments,refs,ins!=null&&ins.isFallThroughOverridden(),ins==null?null:ins.getFallThrough()));
        }
        return saved;
    }

    /**
     * Restore a snapshot around the re-decoded branch at at, whose own override the
     * caller sets. A return drops its flow references; dropFallThrough is the
     * branch fall-through that belonged to a released window.
     */
    private static void restore(Program p, Address at, List<SavedInstruction> saved, boolean isReturn,
            Address dropFallThrough) {
        var listing = p.getListing();
        for(var snapshot:saved) {
            var ins=listing.getInstructionAt(snapshot.at());
            boolean issue=snapshot.at().equals(at);
            if(ins!=null&&!issue)ins.setFlowOverride(snapshot.override());
            if(ins!=null&&snapshot.fallThroughOverridden()&&
                    !(issue&&snapshot.fallThrough()!=null&&snapshot.fallThrough().equals(dropFallThrough)))
                ins.setFallThrough(snapshot.fallThrough());
            for(int i=0;i<5;i++)if(snapshot.comments()[i]!=null)listing.setComment(snapshot.at(),i,snapshot.comments()[i]);
            for(var ref:snapshot.references()) {
                var r=ref.reference();
                if(issue&&isReturn&&r.getReferenceType().isFlow())continue;
                // A dropped fall-through's reference goes with it.
                if(issue&&dropFallThrough!=null&&r.getReferenceType().isFallthrough()&&r.getToAddress().equals(dropFallThrough))continue;
                var manager=p.getReferenceManager();
                var restored=r.isRegisterReference() ? manager.addRegisterReference(r.getFromAddress(),r.getOperandIndex(),p.getRegister(r.getToAddress()),r.getReferenceType(),r.getSource()) : manager.addReference(r);
                manager.setPrimary(restored,ref.primary());
                var symbol=p.getSymbolTable().getSymbol(ref.symbolId());
                if(symbol!=null)manager.setAssociation(symbol,restored);
            }
        }
    }

    private static final class Reader {
        private final Program program;private final Listing listing;private final PseudoDisassembler pseudo;
        private final Map<Address,C6000CallAnalyzer.Preemption> cuts;
        /** cuts: the transfer of each continued jump (neutralise); null looks the preemption up. */
        Reader(Program p,Map<Address,C6000CallAnalyzer.Preemption> cuts){program=p;listing=p.getListing();pseudo=new PseudoDisassembler(p);this.cuts=cuts;}
        Reader(Program p){this(p,null);}
        Instruction decode(Address at) {
            if (at == null) return null;
            var old=listing.getInstructionAt(at);if(old!=null)return old;
            if(listing.getInstructionContaining(at)!=null||listing.getDefinedDataContaining(at)!=null)return null;
            try{return pseudo.disassemble(at);}catch(Exception e){return null;}
        }
        Instruction next(Instruction i){var next=decode(i.getMaxAddress().next());
            while(next!=null&&C6000CallAnalyzer.baseName(next).equals("CPKT"))next=decode(next.getMaxAddress().next());return next;}
        Window window(Instruction issue,TaskMonitor monitor)throws CancelledException {
            C6000CallAnalyzer.Preemption preemption=null;
            if(preemptingTransfer(issue)){
                if(cuts!=null)preemption=cuts.get(issue.getAddress());
                else{preemption=new C6000CallAnalyzer.Walker(program).preempting(issue);
                    if(preemption!=null&&!(preemption.exact()&&continues(program,preemption.jump())))preemption=null;}
            }
            return window(issue,monitor,preemption);
        }
        /** The window of issue, cut where preemption's jump lands when it is non-null. */
        Window window(Instruction issue,TaskMonitor monitor,C6000CallAnalyzer.Preemption preemption)throws CancelledException {
            int remaining=5;
            String name=C6000CallAnalyzer.baseName(issue);
            if(name.startsWith("CALLP"))remaining=0;
            // A BNOP's NOP cycles count in its own packet (C6000ExecutionPackets.cycles).
            // Issued in a preempted jump's window: that jump lands first and its target only idles.
            Address cut=null;
            if(preemption!=null){remaining=5-preemption.cycle();cut=preemption.windowEnd();}
            var owner=program.getFunctionManager().getFunctionContaining(issue.getAddress());
            Instruction current=issue;int count=0;
            try {
                boolean issuePacket=true;
                do {
                    int cycles=issuePacket?packetCycles(issue):1;
                    if(cycles<0)return null;
                    Instruction nopGenerator=issuePacket&&C6000ExecutionPackets.startsMulticycleNop(issue)?issue:null;
                    int packetInstructions=issuePacket?1:0;
                    if(issuePacket)for(var priorAt:C6000ExecutionPackets.issuePrefix(program,issue.getAddress())) {
                        if(++packetInstructions>8)return null;
                        var prior=decode(priorAt);if(prior==null)return null;
                        if(C6000PacketStagingAnalyzer.flow(prior).isJump()||C6000PacketStagingAnalyzer.flow(prior).isCall()||C6000PacketStagingAnalyzer.flow(prior).isTerminal())return null;
                        var priorOwner=program.getFunctionManager().getFunctionContaining(priorAt);
                        // A physical predecessor's p bit does not prove that
                        // an alternate entry executed it. Require the owned
                        // prefix and reject incoming control into this suffix.
                        if(owner==null||!owner.equals(priorOwner))return null;
                        var incoming=program.getReferenceManager().getReferencesTo(issue.getAddress());
                        while(incoming.hasNext())if(incoming.next().getReferenceType().isFlow())return null;
                        if(C6000ExecutionPackets.startsMulticycleNop(prior)) {
                            if(nopGenerator!=null&&!C6000ExecutionPackets.sameMulticycleNop(nopGenerator,prior))return null;
                            nopGenerator=prior;
                        }
                        int priorCycles=packetCycles(prior);if(priorCycles<0)return null;
                        cycles=Math.max(cycles,priorCycles);
                    }
                    while(!issuePacket||C6000ExecutionPackets.parallelWithNext(program,current)) {
                        monitor.checkCancelled();if(++packetInstructions>8)return null;var next=next(current);if(next==null||++count>MAX_INSTRUCTIONS)return null;
                        if(next.getAddress().subtract(issue.getMaxAddress())>MAX_BYTES)return null;
                        if(C6000PacketStagingAnalyzer.flow(next).isJump()||C6000PacketStagingAnalyzer.flow(next).isCall()||C6000PacketStagingAnalyzer.flow(next).isTerminal())return null;
                        var other=program.getFunctionManager().getFunctionContaining(next.getAddress());
                        if(other!=null&&!other.equals(owner))return null;
                        if(program.getFunctionManager().getFunctionAt(next.getAddress())!=null)return null;
                        if(C6000ExecutionPackets.startsMulticycleNop(next)) {
                            if(nopGenerator!=null&&!C6000ExecutionPackets.sameMulticycleNop(nopGenerator,next))return null;
                            nopGenerator=next;
                        }
                        int nextCycles=packetCycles(next);if(nextCycles<0)return null;
                        cycles=Math.max(cycles,nextCycles);current=next;
                        if(!C6000ExecutionPackets.parallelWithNext(program,current))break;
                    }
                    if(!issuePacket)remaining-=cycles;else remaining-=cycles-1;
                    issuePacket=false;
                }while(remaining>0);
                if(cut!=null&&!cut.equals(current.getMaxAddress()))return null;
                return new Window(issue,current.getMaxAddress(),owner);
            }catch(MemoryAccessException e){return null;}
        }
        int packetCycles(Instruction i)throws MemoryAccessException {
            Integer cycles=C6000ExecutionPackets.cycles(program,i);
            return cycles==null?-1:cycles;}
    }
}
