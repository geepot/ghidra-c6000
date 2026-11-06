// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.math.BigInteger;
import java.util.*;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
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
    private C6000DelaySlots() { }

    public record Repair(String branch, String end, int delayBytes, int oldDepth,
            int newDepth, long addedBodyBytes) { }
    private record SavedRef(Reference reference, boolean primary, long symbolId) { }
    private record SavedInstruction(Address at, FlowOverride override, String[] comments,
            List<SavedRef> references, boolean fallThroughOverridden, Address fallThrough) { }
    private record Window(Instruction branch, Address end, Function owner) { }

    /** B/BNOP or CALLP; nested transfers and ownership conflicts are refused. */
    public static List<Repair> recover(Program program, TaskMonitor monitor, MessageLog log)
            throws Exception {
        int transaction = program.startTransaction("Recover C6000 delay windows");
        boolean commit = false;
        try {
            List<Repair> result = recoverWindows(program, monitor, log);
            commit = true;
            return result;
        }
        finally {
            // A failed invariant must never leave a partly cleared instruction window.
            program.endTransaction(transaction, commit);
        }
    }

    private static List<Repair> recoverWindows(Program program, TaskMonitor monitor, MessageLog log)
            throws Exception {
        int preempted = neutralise(program, monitor);
        if (preempted > 0) log.appendMsg("C6000 Delay Slots", "continued " + preempted + " preempted jump(s)");
        List<Address> candidates = new ArrayList<>();
        var it = program.getListing().getInstructions(true);
        while (it.hasNext()) {
            var ins = it.next();
            String full = ins.getMnemonicString(), name = C6000CallAnalyzer.baseName(ins);
            if (full.startsWith("_")) continue;
            if (!(name.equals("B.S1") || name.equals("B.S2") || name.equals("BNOP.S1") ||
                    name.equals("BNOP.S2") || name.equals("CALLP.S1") || name.equals("CALLP.S2"))) continue;
            var override = ins.getFlowOverride();
            // Issue #34: the SLEIGH captures a predicate and target before the
            // slots, so predicated and delayed-call displacement branches are
            // lifted correctly once their window is proven.
            // ponytail: register forms stay unpredicated, non-call only until tested,
            // except a return that preempts a jump under the jump's predicate (tested).
            boolean displacement = ins.getRegister(0) == null;
            if (full.startsWith("[") && !displacement && !preemptingReturn(ins)) continue;
            if (override != FlowOverride.NONE && override != FlowOverride.RETURN &&
                    !(override == FlowOverride.CALL && displacement)) continue;
            candidates.add(ins.getAddress());
        }
        List<Repair> result = new ArrayList<>();
        Reader reader = new Reader(program);
        for (Address at : candidates) {
            monitor.checkCancelled();
            Instruction branch = program.getListing().getInstructionAt(at);
            if (branch == null || branch.isInDelaySlot()) continue;
            Window window = reader.window(branch, monitor);
            if (window == null) continue;
            int bytes = (int) (window.end().subtract(branch.getMaxAddress()));
            if (bytes == 0) continue;
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
                if (!canMaterialize(program, window, bytes, monitor)) continue;
                result.add(apply(program, window, bytes, monitor));
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
            if ((delayedCall || generic) && !window.end().next().equals(now.getFallThrough())) {
                now.setFallThrough(window.end().next());
                if(nativeReady)result.add(new Repair(at.toString(),window.end().toString(),bytes,
                    branch.getDelaySlotDepth(),branch.getDelaySlotDepth(),0));
            }
        }
        if (!result.isEmpty()) log.appendMsg("C6000 Delay Slots", "recovered " + result.size() + " proven window(s)");
        return result;
    }

    /** A return through B3. */
    static boolean preemptingTransfer(Instruction transfer) {
        var register = transfer.getRegister(0);
        var override = transfer.getFlowOverride();
        return register != null && register.getName().equals("B3") && !transfer.getFlowType().isCall() &&
            override != FlowOverride.CALL && override != FlowOverride.CALL_RETURN;
    }

    /** A predicated return whose window is cut exactly where a continued jump lands. */
    private static boolean preemptingReturn(Instruction transfer) {
        if (!preemptingTransfer(transfer)) return false;
        var preemption = new C6000CallAnalyzer.Walker(transfer.getProgram()).preempting(transfer);
        return preemption != null && preemption.exact() && continues(transfer.getProgram(), preemption.jump());
    }

    /** Whether the jump's branch is overridden to continue (see neutralise). */
    static boolean continues(Program program, Instruction jump) {
        for (Reference r : program.getReferenceManager().getReferencesFrom(jump.getAddress())) {
            if (r.getReferenceType() == RefType.JUMP_OVERRIDE_UNCONDITIONAL && r.isPrimary()) return true;
        }
        return false;
    }

    /**
     * A jump whose target only idles until a return issued in its
     * window lands (C6000CallAnalyzer.Preemption) leaves nothing to its target:
     * execution goes on through its window. Override its branch to its own
     * fall-through and drop the edge to the target, whose NOPs are usually
     * another return's delay slots. The return's window then ends where the
     * jump lands (Reader.window), which must hold on the not-taken path too.
     */
    private static int neutralise(Program program, TaskMonitor monitor) throws CancelledException {
        var listing = program.getListing();
        var references = program.getReferenceManager();
        var walker = new C6000CallAnalyzer.Walker(program);
        List<Instruction> jumps = new ArrayList<>();
        for (var it = listing.getInstructions(true); it.hasNext();) {
            var ins = it.next();
            if (C6000CallAnalyzer.Walker.displacementJump(ins)) jumps.add(ins);
        }
        Disassembler disassembler = null;
        int count = 0;
        for (Instruction jump : jumps) {
            monitor.checkCancelled();
            var preemption = walker.preemption(jump);
            if (preemption == null || !preemption.exact() || !preemptingTransfer(preemption.transfer())) continue;
            Address at = jump.getAddress(), target = jump.getDefaultFlows()[0];
            Address next = jump.getMaxAddress().next().add(jump.getPrototype().getDelaySlotByteCount());
            boolean changed = false, overridden = false, other = false;
            for (Reference r : references.getReferencesFrom(at)) {
                if (r.getReferenceType() != RefType.JUMP_OVERRIDE_UNCONDITIONAL) continue;
                if (r.getToAddress().equals(next) && r.isPrimary()) overridden = true;
                else other = true;
            }
            // Someone else's override stands.
            if (other) continue;
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
            if (listing.getInstructionAt(next) == null) {
                if (disassembler == null) disassembler = Disassembler.getDisassembler(program, monitor, null);
                disassembler.disassemble(next, null, true);
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

    /** Last byte of a branch's proven delay window, or null when it is not proven. */
    static Address windowEnd(Program program, Instruction branch, TaskMonitor monitor)
            throws CancelledException {
        Window window = new Reader(program).window(branch, monitor);
        return window == null ? null : window.end();
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

    private static Repair apply(Program p, Window window, int bytes, TaskMonitor monitor)
            throws Exception {
        var listing = p.getListing();var original = window.branch();
        Address at = original.getAddress();int oldDepth = original.getDelaySlotDepth();
        FlowOverride override = original.getFlowOverride();
        boolean registerBranch=original.getRegister(0)!=null && !original.getMnemonicString().startsWith("CALLP");
        List<SavedInstruction> saved = new ArrayList<>();
        // A shorter window than the native one releases the old slots too.
        Address end = window.end(), old = original.getMaxAddress().add(original.getPrototype().getDelaySlotByteCount());
        if (old.compareTo(end) > 0) end = old;
        // Undisassembled tail bytes can already carry user comments and refs.
        // Snapshot every address, including those without a defined instruction.
        for(Address cursor=at;cursor.compareTo(end)<=0;cursor=cursor.next()) {
            var ins=listing.getInstructionAt(cursor);List<SavedRef> refs=new ArrayList<>();
            for(var r:p.getReferenceManager().getReferencesFrom(cursor))
                refs.add(new SavedRef(r,r.isPrimary(),r.getSymbolID()));
            String[] comments=new String[5];for(int i=0;i<5;i++)comments[i]=listing.getComment(i,cursor);
            saved.add(new SavedInstruction(cursor,ins==null?FlowOverride.NONE:ins.getFlowOverride(),comments,refs,ins!=null&&ins.isFallThroughOverridden(),ins==null?null:ins.getFallThrough()));
        }
        boolean isReturn = override == FlowOverride.RETURN ||
            (original.getNumOperands()>0 && "B3".equals(original.getDefaultOperandRepresentation(0)) &&
                !original.getMnemonicString().startsWith("CALLP"));
        if(isReturn)override=FlowOverride.RETURN;
        listing.clearCodeUnits(at,end,false);
        p.getProgramContext().setValue(p.getRegister("c_flow_delay"),at,at,BigInteger.valueOf(bytes));
        if(registerBranch)
            p.getProgramContext().setValue(p.getRegister("c_branch_terminal"),at,at,BigInteger.ONE);
        Disassembler disassembler=Disassembler.getDisassembler(p,monitor,null);
        disassembler.disassemble(at,new AddressSet(at,end),false);
        // The released slots after a terminal transfer are reached by no fall-through.
        if(end.compareTo(window.end())>0&&listing.getInstructionContaining(window.end().next())==null)
            disassembler.disassemble(window.end().next(),new AddressSet(window.end().next(),end),false);
        var branch=listing.getInstructionAt(at);var tail=listing.getInstructionContaining(window.end());
        if(branch==null||branch.getPrototype().getDelaySlotByteCount()!=bytes||tail==null||!tail.isInDelaySlot())
            throw new IllegalStateException("Could not materialize native delay window at "+at+" end="+window.end()+" bytes="+bytes+" branch="+branch+" depth="+(branch==null?-1:branch.getDelaySlotDepth())+" tail="+tail);
        branch.setFlowOverride(override);
        for(var snapshot:saved) {
            var ins=listing.getInstructionAt(snapshot.at());
            if(ins!=null&&!snapshot.at().equals(at))ins.setFlowOverride(snapshot.override());
            if(ins!=null&&snapshot.fallThroughOverridden())ins.setFallThrough(snapshot.fallThrough());
            for(int i=0;i<5;i++)if(snapshot.comments()[i]!=null)listing.setComment(snapshot.at(),i,snapshot.comments()[i]);
            for(var ref:snapshot.references()) {
                var r=ref.reference();
                if(snapshot.at().equals(at)&&isReturn&&r.getReferenceType().isFlow())continue;
                var manager=p.getReferenceManager();
                var restored=r.isRegisterReference() ? manager.addRegisterReference(r.getFromAddress(),r.getOperandIndex(),p.getRegister(r.getToAddress()),r.getReferenceType(),r.getSource()) : manager.addReference(r);
                manager.setPrimary(restored,ref.primary());
                var symbol=p.getSymbolTable().getSymbol(ref.symbolId());
                if(symbol!=null)manager.setAssociation(symbol,restored);
            }
        }
        long added=0;
        if(window.owner()!=null) {
            var body=new AddressSet(window.owner().getBody());long before=body.getNumAddresses();
            body.add(at,window.end());window.owner().setBody(body);added=body.getNumAddresses()-before;
        }
        return new Repair(at.toString(),window.end().toString(),bytes,oldDepth,branch.getDelaySlotDepth(),added);
    }

    private static final class Reader {
        private final Program program;private final Listing listing;private final PseudoDisassembler pseudo;
        private final C6000CallAnalyzer.Walker walker;
        Reader(Program p){program=p;listing=p.getListing();pseudo=new PseudoDisassembler(p);walker=new C6000CallAnalyzer.Walker(p);}
        Instruction decode(Address at) {
            if (at == null) return null;
            var old=listing.getInstructionAt(at);if(old!=null)return old;
            if(listing.getInstructionContaining(at)!=null||listing.getDefinedDataContaining(at)!=null)return null;
            try{return pseudo.disassemble(at);}catch(Exception e){return null;}
        }
        Instruction next(Instruction i){var next=decode(i.getMaxAddress().next());
            while(next!=null&&C6000CallAnalyzer.baseName(next).equals("CPKT"))next=decode(next.getMaxAddress().next());return next;}
        Window window(Instruction issue,TaskMonitor monitor)throws CancelledException {
            int remaining=5;
            String name=C6000CallAnalyzer.baseName(issue);
            if(name.startsWith("CALLP"))remaining=0;
            else if(name.startsWith("BNOP")){var n=issue.getScalar(1);if(n==null)return null;remaining=Math.max(0,5-(int)n.getValue());}
            // Issued in a preempted jump's window: that jump lands first and its target only idles.
            Address cut=null;
            if((name.equals("B.S1")||name.equals("B.S2"))&&issue.getLength()==4&&preemptingTransfer(issue)){
                var preemption=walker.preempting(issue);
                if(preemption!=null&&preemption.exact()&&continues(program,preemption.jump())){
                    remaining=5-preemption.cycle();cut=preemption.windowEnd();
                }
            }
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
                        if(prior.getFlowType().isJump()||prior.getFlowType().isCall()||prior.getFlowType().isTerminal())return null;
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
                        if(next.getFlowType().isJump()||next.getFlowType().isCall()||next.getFlowType().isTerminal())return null;
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
        int packetCycles(Instruction i)throws MemoryAccessException {String name=C6000CallAnalyzer.baseName(i);
            // Loop control / asynchronous wakeup needs a pipeline model.
            if(name.equals("IDLE")||name.startsWith("SPLOOP")||name.startsWith("SPKERNEL")||name.startsWith("SPMASK")||name.equals("SWE")||name.equals("SWENR"))return -1;
            if(C6000ExecutionPackets.protectedLoad(program,i)) {
                // The unconditional case is specified by SPRUFE8B 3.10.2.2.
                // Do not assume a false load predicate still inserts its NOPs.
                if(i.getMnemonicString().contains("["))return -1;
                return 5;
            }
            if(name.equals("NOP")){var n=i.getScalar(0);return n==null?1:Math.max(1,(int)n.getValue());}
            if(name.startsWith("ADDKPC.")){var n=i.getScalar(2);return n==null?1:1+(int)n.getValue();}
            return 1;}
    }
}
