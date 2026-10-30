// SPDX-License-Identifier: Apache-2.0
package c6000;
import java.math.BigInteger;
import java.util.*;
import java.util.regex.*;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.pcode.*;
import ghidra.util.task.TaskMonitor;
/**
* Exact finite-state retiming of raw instruction p-code. Arithmetic is never
* reimplemented here. SPRUFE8B 3.5, 3.8.3, 3.10.2.2 and 4.2.1--4.2.8:
* E1 scalar capture, DP ports through E4, memory at E3, split delayed
* writeback through E10, software-loop dispatch, and branch landing C+6.
* Unsupported phase contracts fail before enabling this representation.
* A drained entry pipeline is an explicit precondition, never inferred from
* a function boundary. Use C6000PipelineSchedules.enable to record its evidence.
*/
public final class C6000PipelineCompiler {

    public record Result(PcodeOp[] code,int states,int packets,AddressSet covered,Map<Integer,Long> cycleStarts,Map<Integer,Integer> stallTargets){
    }

    /** Explicit observation after return, not an inferred C ABI or caller trace.
     * SPRUFE8B 4.2.3/4.2.6: an E3 store can outlive the five branch delay slots.
     * The reviewer guarantees no caller issue, interrupt or memory observation
     * during these idle advances. Loads, arithmetic and control tails refuse.
     */
    public record StoreTailContract(int idleAdvances,String evidence) {
        public StoreTailContract {
            if(idleAdvances<1||idleAdvances>2||evidence==null||evidence.isBlank())
                throw new IllegalArgumentException("store-tail contract requires one or two idle advances and explicit observation evidence");
        }
    }
    public record StoreTailWrite(int rawIndex,Varnode address,Varnode value,Varnode enabled) {}
    public record PendingStoreTail(long pc,int age,int remainingAdvances,Varnode predicate,List<StoreTailWrite> writes,String instructionHex) {
        public PendingStoreTail { writes=List.copyOf(writes); }
    }
    public record StoreTailBoundary(int pcodeIndex,long returnBranchPc,List<PendingStoreTail> stores) {
        public StoreTailBoundary { stores=List.copyOf(stores); }
    }
    public record StoreTailResult(Result schedule,StoreTailContract contract,List<StoreTailBoundary> boundaries) {
        public StoreTailResult { boundaries=List.copyOf(boundaries); }
    }
    /** cycleStarts marker for a contracted idle advance; never a memory address. */
    public static final long POST_RETURN_IDLE_PC=-2L;
    private StoreTailContract storeTailContract;
    private final List<StoreTailBoundary> storeTailBoundaries=new ArrayList<>();

    public StoreTailResult compileStoreTail(StoreTailContract contract)throws Exception {
        if(!states.isEmpty()||!instructions.isEmpty()||!b.code.isEmpty()||traceContract!=null||closedCall!=null||callerTail!=null||storeTailContract!=null)
            throw fail("store-tail compiler instance already used");
        storeTailContract=Objects.requireNonNull(contract);
        return new StoreTailResult(compileInternal(),contract,storeTailBoundaries);
    }

    private List<StoreTailWrite> storeTailWrites(Insn instruction,int age) {
        var writes=new ArrayList<StoreTailWrite>();long pc=instruction.instruction().getAddress().getOffset();
        for(int n=0;n<instruction.raw().length;n++){
            var op=instruction.raw()[n];if(op.getOpcode()!=PcodeOp.STORE)continue;
            if(op.getInput(1).getSize()!=4||op.getInput(2).getSize()>8)throw fail("unsupported store-tail memory effect");
            writes.add(new StoreTailWrite(n,slot("tail_address",pc,age,n,4),
                slot("tail_value",pc,age,n,op.getInput(2).getSize()),slot("tail_enabled",pc,age,n,1)));
        }
        if(writes.isEmpty())throw fail("store-tail instruction has no memory effects");
        return writes;
    }

    private void moveStoreTail(List<Runnable> moves,Insn instruction,int from,int to) {
        var before=storeTailWrites(instruction,from);var after=storeTailWrites(instruction,to);
        for(int k=0;k<before.size();k++){
            copy(moves,after.get(k).address(),before.get(k).address());
            copy(moves,after.get(k).value(),before.get(k).value());
            copy(moves,after.get(k).enabled(),before.get(k).enabled());
        }
    }

    private void storeTailReturn(State source,Branch landing,List<Flight> flights,List<Branch> branches,Insn issued,LoopPlan loop,List<Hazard> hazards)throws Exception {
        if(loop!=null||!branches.isEmpty()||issued!=null)throw fail("store-tail return has unresolved control effects");
        var stores=new ArrayList<PendingStoreTail>();
        for(var flight:flights){
            var instruction=decode(flight.pc());
            if(!instruction.store()||instruction.latency()!=3||flight.age()<1||flight.age()>2||
                instruction.outputs().stream().anyMatch(d->d.phase()>flight.age()))
                throw fail("store-tail return supports only pending E3 stores");
            if(3-flight.age()>storeTailContract.idleAdvances())throw fail("store-tail idle budget is too short");
            stores.add(new PendingStoreTail(flight.pc(),flight.age(),3-flight.age(),
                slot("predicate",flight.pc(),flight.age(),0,1),storeTailWrites(instruction,flight.age()),
                java.util.HexFormat.of().formatHex(instruction.instruction().getBytes())));
        }
        int marker=b.code.size();b.op(PcodeOp.COPY,temp(1),c(0,1));
        storeTailBoundaries.add(new StoreTailBoundary(marker,landing.pc(),stores));
        b.op(PcodeOp.COPY,new Varnode(program.getRegister("C6000_PIPE_RET").getAddress(),4),slot("target",landing.pc(),landing.age(),0,4));
        b.jump(PcodeOp.BRANCH,"node"+state(new State(POST_RETURN_IDLE_PC,storeTailContract.idleAdvances(),flights,List.of(),hazards,null,source.facts(),source.returns())),null);
    }

    /** Explicit read-only trace boundary, never an enable()/function contract. */
    public record TraceEntry(boolean drained,Set<String> previousE1Writes) {
        public TraceEntry {previousE1Writes=Set.copyOf(previousE1Writes);}
    }
    public record ReturnContinuation(long expectedEntryB3,long callerFunctionEntry,List<Long> callerPackets,long stopPc,String callerBytesSha256,boolean allowUnownedWindow,TraceEntry entry,String evidence) {
        public ReturnContinuation {
            callerPackets=List.copyOf(callerPackets);
            if(callerPackets.isEmpty()||expectedEntryB3<0||stopPc>0xffffffffL||callerPackets.get(0)!=expectedEntryB3||evidence==null||evidence.isBlank()||callerBytesSha256==null||!callerBytesSha256.matches("[0-9a-f]{64}"))throw new IllegalArgumentException("explicit immutable caller continuation evidence required");
            for(int k=0;k<callerPackets.size();k++)if(callerPackets.get(k)>=stopPc||k>0&&callerPackets.get(k)<=callerPackets.get(k-1))throw new IllegalArgumentException("caller packet order");
        }
    }
    public record PendingStore(long pc,int age,int remainingAdvances,Varnode predicate,Varnode address,Varnode value,Map<String,Varnode> capturedInputs,String instructionHex) {}
    private record StoreCapture(Varnode address,Varnode value) {}
    private final Map<Long,StoreCapture> traceEvaluatedStores=new HashMap<>();
    public record TraceBoundary(int pcodeIndex,long returnBranchPc,List<PendingStore> stores) {}
    public record TraceResult(Result schedule,ReturnContinuation contract,long exitPc,List<TraceBoundary> boundaries,Set<String> outgoingE1Writes) {
        /** The trace executor must check this before executing any p-code. */
        public void validateEntryB3(long actual){if((actual&0xffffffffL)!=contract.expectedEntryB3())throw new IllegalArgumentException("caller continuation entry B3 mismatch");}
    }
    /** Strict read-only continuation scope, including reachable callee code and data gaps. */
    public record CallerEntryEvidence(TraceWindow setup,long finalIssuedPacketPc,int trailingIdleAdvances,String evidence) {
        public CallerEntryEvidence {Objects.requireNonNull(setup);if(!setup.contains(finalIssuedPacketPc)||trailingIdleAdvances<0||trailingIdleAdvances>15||evidence==null||evidence.isBlank())throw new IllegalArgumentException("explicit caller-entry source evidence required");}
    }
    public record CallerTailPlan(String languageId,TraceWindow callee,TraceWindow caller,ReturnContinuation continuation,CallerEntryEvidence entryEvidence) {
        public CallerTailPlan {
            Objects.requireNonNull(languageId);Objects.requireNonNull(callee);Objects.requireNonNull(caller);Objects.requireNonNull(continuation);Objects.requireNonNull(entryEvidence);
            if(entryEvidence.setup().ownerEntry()!=caller.ownerEntry()||entryEvidence.setup().end()!=caller.start()||callee.start()!=callee.ownerEntry()||caller.ownerEntry()!=continuation.callerFunctionEntry()||caller.start()!=continuation.expectedEntryB3()||caller.end()!=continuation.stopPc()||!caller.fetchBytesSha256().equals(continuation.callerBytesSha256())||callee.start()<caller.end()&&caller.start()<callee.end())throw new IllegalArgumentException("caller-tail scope/continuation mismatch");
        }
    }
    public record CallerTailResult(TraceResult trace,CallerTailPlan contract) {}
    private CallerTailPlan callerTail;
    public CallerTailResult compileCallerTail(CallerTailPlan plan)throws Exception {
        if(!states.isEmpty()||!instructions.isEmpty()||!loopPlans.isEmpty()||!slots.isEmpty()||!b.code.isEmpty()||traceContract!=null||closedCall!=null||callerTail!=null)throw fail("compiler instance already used");callerTail=Objects.requireNonNull(plan);
        if(!program.getLanguageID().getIdAsString().equals(plan.languageId())||function.getEntryPoint().getOffset()!=plan.callee().ownerEntry())throw fail("caller-tail language/callee identity mismatch");
        validateWindowMetadata(plan.callee());validateWindowMetadata(plan.caller());validateWindowMetadata(plan.entryEvidence().setup());validateCallerEntryEvidence(plan);
        validateClosedTargetPacket(plan.callee().start());validateClosedTargetPacket(plan.caller().start());
        return new CallerTailResult(compileTrace(plan.continuation()),plan);
    }
    private ReturnContinuation traceContract;
    private final List<TraceBoundary> traceBoundaries=new ArrayList<>();
    private Set<String> traceExitWrites;
    public TraceResult compileTrace(ReturnContinuation contract)throws Exception {
        if(!states.isEmpty())throw fail("compiler instance already used");traceContract=Objects.requireNonNull(contract);
        if(contract.entry()==null||!contract.entry().drained())throw fail("caller continuation requires an explicit drained entry contract");
        Set<Long> expectedWrites=new TreeSet<>();for(String name:contract.entry().previousE1Writes()){var register=program.getRegister(name);if(register==null||!name.matches("[AB]([0-9]|[12][0-9]|3[01])"))throw fail("invalid entry hazard contract");expectedWrites.add(register.getAddress().getOffset());}
        if(!expectedWrites.equals(new TreeSet<>(entryWrites)))throw fail("entry hazard contract differs from compiler entry");
        if(program.getFunctionManager().getFunctionAt(entry.getNewAddress(contract.callerFunctionEntry()))==null)throw fail("caller function identity missing");
        long imageStart=contract.expectedEntryB3()&~31L,imageEnd=(contract.stopPc()+31)&~31L;long callerSize=imageEnd-imageStart;if(callerSize<=0||callerSize>4096)throw fail("caller continuation window exceeds bounded scope");byte[] callerBytes=new byte[(int)callerSize];
        if(program.getMemory().getBytes(entry.getNewAddress(imageStart),callerBytes)!=callerBytes.length)throw fail("short caller continuation byte read");
        for(long packet=imageStart;packet<imageEnd;packet+=32)if((program.getMemory().getInt(entry.getNewAddress(packet+28))>>>28)==14)throw fail("caller continuation currently requires headerless full32 context");
        String digest=java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(callerBytes));if(!digest.equals(contract.callerBytesSha256()))throw fail("caller continuation byte hash mismatch");
        for(int k=0;k<contract.callerPackets().size();k++){
            long pc=contract.callerPackets().get(k);var pack=packet(pc);long next=after(pack.get(pack.size()-1));
            long expected=k+1<contract.callerPackets().size()?contract.callerPackets().get(k+1):contract.stopPc();
            if(next!=expected)throw fail("caller packet window is not exact and contiguous");
            for(var instruction:pack)if(instruction.instruction().getLength()!=4||Set.of("B","BNOP","BDEC","BPOS","CALLP","SPLOOP","SPLOOPD","SPLOOPW","SPKERNEL","SPMASK").contains(instruction.name())||instruction.predicate()!=null)throw fail("caller continuation requires unconditional straight-line packets");
        }
        Result result=compileInternal();if(traceBoundaries.isEmpty()||traceExitWrites==null)throw fail("continuation did not reach a closed boundary");
        return new TraceResult(result,contract,contract.stopPc(),List.copyOf(traceBoundaries),Set.copyOf(traceExitWrites));
    }
    private boolean callerPc(long pc){return traceContract!=null&&pc>=traceContract.expectedEntryB3()&&pc<traceContract.stopPc();}
    private long continueReturn(Branch landing,List<Flight> flights,List<Branch> branches,Insn issueBranch,LoopPlan loop)throws Exception {
        if(loop!=null||!branches.isEmpty()||issueBranch!=null)throw fail("caller continuation has unresolved control effects");
        var stores=new ArrayList<PendingStore>();
        for(var flight:flights){var instruction=decode(flight.pc());if(!instruction.name().equals("STW")||instruction.latency()!=3||flight.age()<1||flight.age()>2)throw fail("caller continuation supports only captured STW E3 tails");var inputs=new LinkedHashMap<String,Varnode>();for(long offset:instruction.regs()){var register=program.getRegister(program.getAddressFactory().getRegisterSpace().getAddress(offset),4);if(register==null)throw fail("unknown captured store input");inputs.put(register.getName(),slot("input",flight.pc(),flight.age(),offset,4));}stores.add(new PendingStore(flight.pc(),flight.age(),3-flight.age(),slot("predicate",flight.pc(),flight.age(),0,1),slot("store_address",flight.pc(),flight.age(),0,4),slot("store_value",flight.pc(),flight.age(),0,4),Map.copyOf(inputs),java.util.HexFormat.of().formatHex(instruction.instruction().getBytes())));}
        int marker=b.code.size();b.op(PcodeOp.COPY,temp(1),c(0,1));traceBoundaries.add(new TraceBoundary(marker,landing.pc(),List.copyOf(stores)));
        return traceContract.expectedEntryB3();
    }
    private void closeTrace(State state)throws Exception {
        if(state.idle()!=0||!state.flights().isEmpty()||!state.branches().isEmpty()||state.loop()!=null)throw fail("caller continuation endpoint still has pending effects");
        Set<String> writes=new TreeSet<>();for(var hazard:state.hazards()){var instruction=decode(hazard.pc());if(instruction.predicate()!=null)throw fail("caller continuation exit has a conditional hazard");for(long offset:hazard.registers()){var register=program.getRegister(program.getAddressFactory().getRegisterSpace().getAddress(offset),4);if(register==null||!register.getName().matches("[AB]([0-9]|[12][0-9]|3[01])"))throw fail("caller continuation exit hazard is not a GPR");writes.add(register.getName());}}
        if(traceExitWrites!=null&&!traceExitWrites.equals(writes))throw fail("caller continuation has incompatible exit hazards");traceExitWrites=Set.copyOf(writes);
        b.op(PcodeOp.COPY,new Varnode(program.getRegister("C6000_PIPE_RET").getAddress(),4),c(traceContract.stopPc(),4));b.jump(PcodeOp.BRANCH,"exit",null);
    }


    /** Hashes cover complete fetch packets; execution permission is only [start,end). */
    public record UnownedSpan(long start,long end,String evidence) {
        public UnownedSpan {if(start<0||end<=start||evidence==null||evidence.isBlank())throw new IllegalArgumentException("explicit unowned code evidence required");}
        boolean contains(long pc){return pc>=start&&pc<end;}
    }
    public record TraceWindow(long ownerEntry,long start,long end,String fetchBytesSha256,List<UnownedSpan> unownedSpans) {
        public TraceWindow(long ownerEntry,long start,long end,String fetchBytesSha256){this(ownerEntry,start,end,fetchBytesSha256,List.of());}
        public TraceWindow {unownedSpans=List.copyOf(unownedSpans);if(start<0||end<=start||end>0x100000000L||end-start>4096||fetchBytesSha256==null||!fetchBytesSha256.matches("[0-9a-f]{64}"))throw new IllegalArgumentException("explicit bounded code-window hash required");long previous=start;for(var span:unownedSpans){if(span.start()<previous||span.end()>end)throw new IllegalArgumentException("unowned span outside exact ordered scope");previous=span.end();}}
        boolean contains(long pc){return pc>=start&&pc<end;}
        boolean unowned(long pc){return unownedSpans.stream().anyMatch(span->span.contains(pc));}
    }
    /** One statically proved closed call; null stop means the caller's actual register return. */
    public record ClosedCallPlan(String languageId,TraceWindow caller,TraceWindow callee,long startPc,Long stopPc,long callPc,long linkPc,long continuation,long calleeReturnPc,Long callerReturnPc,TraceEntry entry,String evidence) {
        public ClosedCallPlan {if(languageId==null||caller==null||callee==null||entry==null||evidence==null||evidence.isBlank()||!caller.contains(startPc)||!caller.contains(callPc)||!caller.contains(linkPc)||!caller.contains(continuation)||!callee.contains(calleeReturnPc)||(stopPc==null)==(callerReturnPc==null)||stopPc!=null&&stopPc!=caller.end()||callerReturnPc!=null&&!caller.contains(callerReturnPc)||caller.start()<callee.end()&&callee.start()<caller.end())throw new IllegalArgumentException("explicit disjoint closed-call scope required");}
    }
    public record PendingEffect(long pc,int age,int remainingAdvances,Varnode predicate,String instructionHex) {}
    public record BoundaryHazard(String register,Varnode enabled) {}
    public record ClosedCallBoundary(int pcodeIndex,String kind,long branchPc,Varnode capturedTarget,Long expectedTarget,List<PendingEffect> effects,List<PendingStore> stores,List<BoundaryHazard> hazards) {}
    /** Destination sampled at call E1; the link writers are proved from raw p-code. */
    public record ClosedCallProof(long callPc,String targetRegister,long expectedTarget,long continuation,List<Long> linkWriters,Varnode capturedTarget) {}
    public record ClosedCallTraceResult(Result schedule,ClosedCallPlan contract,List<ClosedCallBoundary> boundaries,Set<String> outgoingE1Writes,ClosedCallProof proof) {
        public ClosedCallTraceResult(Result schedule,ClosedCallPlan contract,List<ClosedCallBoundary> boundaries,Set<String> outgoingE1Writes){this(schedule,contract,boundaries,outgoingE1Writes,null);}
    }
    /** Sequential, nonrecursive calls to owned leaf windows, with one active invocation. */
    public record ClosedCallsTraceResult(Result schedule,List<ClosedCallPlan> contracts,List<ClosedCallBoundary> boundaries,Set<String> outgoingE1Writes,List<ClosedCallProof> proofs) {}
    private ClosedCallPlan closedCall;
    private final Map<Long,ClosedCallPlan> closedCalls=new LinkedHashMap<>();
    private final Map<Long,ClosedCallProof> closedProofs=new LinkedHashMap<>();
    private final Map<Long,Long> closedInstructionPackets=new HashMap<>();
    private final Set<Long> closedInternalBranches=new HashSet<>();
    private final Set<Long> closedPackets=new HashSet<>();
    private final List<ClosedCallBoundary> closedBoundaries=new ArrayList<>();
    private Set<String> closedExitWrites;
    /** Read-only multi-owner trace. This result is never an enable()/function contract. */
    public static ClosedCallTraceResult compileClosedCallTrace(Program program,Function caller,ClosedCallPlan plan)throws Exception {
        var result=compileClosedCallsTrace(program,caller,List.of(plan));
        return new ClosedCallTraceResult(result.schedule(),plan,result.boundaries(),result.outgoingE1Writes(),result.proofs().get(0));
    }
    public static ClosedCallsTraceResult compileClosedCallsTrace(Program program,Function caller,List<ClosedCallPlan> plans)throws Exception {
        plans=List.copyOf(plans);if(plans.isEmpty()||plans.size()>16)throw new IllegalArgumentException("one to sixteen explicit leaf calls required");
        var first=plans.get(0);var compiler=new C6000PipelineCompiler(program,caller,first.entry().previousE1Writes(),first.startPc());compiler.closedCall=first;
        for(var plan:plans){
            if(!plan.languageId().equals(first.languageId())||!plan.caller().equals(first.caller())||plan.startPc()!=first.startPc()||!Objects.equals(plan.stopPc(),first.stopPc())||!Objects.equals(plan.callerReturnPc(),first.callerReturnPc())||!plan.entry().equals(first.entry()))throw compiler.fail("closed-call shared caller/entry/endpoint mismatch");
            if(compiler.closedCalls.put(plan.callPc(),plan)!=null)throw compiler.fail("closed-call duplicate call site");
        }
        compiler.validateClosedCall();var result=compiler.compileInternal();
        for(var plan:plans)if(compiler.closedBoundaries.stream().noneMatch(x->x.kind().equals("CALL_ENTER")&&x.branchPc()==plan.callPc())||compiler.closedBoundaries.stream().noneMatch(x->x.kind().equals("CALL_RETURN")&&x.branchPc()==plan.calleeReturnPc()))throw compiler.fail("closed-call trace did not close all declared edges");
        if(compiler.closedExitWrites==null)throw compiler.fail("closed-call trace did not close caller endpoint");
        return new ClosedCallsTraceResult(result,plans,List.copyOf(compiler.closedBoundaries),Set.copyOf(compiler.closedExitWrites),List.copyOf(compiler.closedProofs.values()));
    }
    private boolean declaredCalleeReturn(long pc){return closedCalls.values().stream().anyMatch(p->p.calleeReturnPc()==pc);}
    private boolean strictScope(){return closedCall!=null||callerTail!=null;}
    private TraceWindow closedWindow(long pc){if(callerTail!=null){if(callerTail.callee().contains(pc))return callerTail.callee();if(callerTail.caller().contains(pc))return callerTail.caller();return null;}if(closedCall==null)return null;if(closedCall.caller().contains(pc))return closedCall.caller();for(var plan:closedCalls.values())if(plan.callee().contains(pc))return plan.callee();return null;}
    private boolean observesStores(){return traceContract!=null||closedCall!=null;}
    private int closedPhysicalLength(Address at){
        try{return C6000ExecutionPackets.instructionLengthAt(program,at);}
        catch(ghidra.program.model.mem.MemoryAccessException invalid){throw fail("closed-call invalid physical instruction start at "+at+": "+invalid.getMessage());}
    }
    private void validateClosedInstruction(Instruction instruction)throws Exception {
        validateWindowInstruction(instruction,closedWindow(instruction.getAddress().getOffset()));
    }
    private void validateWindowInstruction(Instruction instruction,TraceWindow window)throws Exception {
        long start=instruction.getAddress().getOffset(),end=start+instruction.getLength();
        if(window==null||start<window.start()||end>window.end())throw fail("closed-call instruction leaves declared window at "+instruction.getAddress());
        UnownedSpan gap=null;for(var candidate:window.unownedSpans())if(candidate.start()<end&&start<candidate.end()){
            if(gap!=null||candidate.start()>start||candidate.end()<end)throw fail("closed-call unowned span cuts an instruction at "+instruction.getAddress());gap=candidate;
        }
        for(long pc=start;pc<end;pc++){
            var at=entry.getNewAddress(pc);if(program.getListing().getDefinedDataContaining(at)!=null)throw fail("closed-call instruction overlaps defined data at "+at);
            var owner=program.getFunctionManager().getFunctionContaining(at);
            if(gap!=null?owner!=null:owner==null||owner.getEntryPoint().getOffset()!=window.ownerEntry()||!owner.getBody().contains(at))throw fail("closed-call instruction leaves declared byte ownership at "+at);
        }
    }
    private Instruction entryEvidenceInstruction(long pc,TraceWindow window)throws Exception {
        var at=entry.getNewAddress(pc);int length=closedPhysicalLength(at);var context=new ProcessorContextImpl(program.getLanguage());
        for(var field:C6000PacketContext.physicalDecodeFields(program,at).entrySet())context.setRegisterValue(new RegisterValue(program.getRegister(field.getKey()),BigInteger.valueOf(field.getValue())));
        context.setRegisterValue(new RegisterValue(program.getRegister("c_flow_delay"),BigInteger.ZERO));context.setRegisterValue(new RegisterValue(program.getRegister("c_schedule_entry"),BigInteger.ZERO));context.setRegisterValue(new RegisterValue(program.getRegister("c_branch_terminal"),BigInteger.ONE));
        var memory=new DumbMemBufferImpl(program.getMemory(),at);var prototype=program.getLanguage().parse(memory,context,false);var instruction=new PseudoInstruction(program,at,prototype,memory,context);
        if(instruction.getLength()!=length)throw fail("caller-entry width conflicts with physical layout at "+at);validateWindowInstruction(instruction,window);return instruction;
    }
    private void validateCallerEntryEvidence(CallerTailPlan plan)throws Exception { // SPRUFE8B 3.8.10, 3.10.2.2, 4.2.6: issued packet plus counted implicit NOP advances.
        var proof=plan.entryEvidence();long pc=proof.finalIssuedPacketPc();if(!C6000ExecutionPackets.issuePrefix(program,entry.getNewAddress(pc)).isEmpty())throw fail("caller-entry evidence starts inside an execute packet");
        var packet=new ArrayList<Instruction>();int idle=0;Instruction generator=null;
        while(true){var instruction=entryEvidenceInstruction(pc,proof.setup());packet.add(instruction);if(packet.size()>8)throw fail("caller-entry oversized execute packet");String name=base(instruction);int inserted=0;
            if(name.equals("CALLP"))inserted=5;else if(name.equals("NOP"))inserted=Math.max(0,(int)instruction.getScalar(0).getValue()-1);else if(name.equals("BNOP"))inserted=C6000ExecutionPackets.bnopCount(program,instruction);else if(name.equals("ADDKPC"))inserted=(int)instruction.getScalar(2).getValue();else if(C6000ExecutionPackets.protectedLoad(program,instruction))inserted=4;
            boolean generates=inserted>0||Set.of("CALLP","BNOP","ADDKPC").contains(name);
            if(generates){if(generator!=null&&!C6000ExecutionPackets.sameMulticycleNop(generator,instruction))throw fail("caller-entry conflicting NOP generators");generator=instruction;}idle=Math.max(idle,inserted);
            boolean parallel=C6000ExecutionPackets.parallelWithNext(program,instruction);pc=instruction.getMaxAddress().getOffset()+1;
            if((pc&31)==28&&(program.getMemory().getInt(entry.getNewAddress(pc))>>>28)==14)pc+=4;
            if(!parallel)break;
        }
        if(pc!=proof.setup().end()||idle!=proof.trailingIdleAdvances())throw fail("caller-entry source span/idle evidence mismatch");
        if(packet.size()==8)for(var instruction:packet)if(C6000PacketContext.physicalDecodeFields(program,instruction.getAddress()).get("c_hdrpkt")==1)throw fail("caller-entry eight-instruction header-based execute packet");
        Set<String> actual=new TreeSet<>();if(idle==0)for(var instruction:packet){String name=base(instruction);
            if(instruction.getMnemonicString().contains("["))throw fail("caller-entry conditional E1 inventory requires a path proof");
            if(!SINGLE.contains(name)&&!Set.of("NOP","B","BNOP","ADDKPC").contains(name))throw fail("caller-entry unsupported E1 inventory instruction "+instruction);
            for(var operation:instruction.getPcode()){var output=operation.getOutput();if(output==null||!output.isRegister())continue;
                for(String bank:List.of("A","B"))for(int index=0;index<32;index++){var register=program.getRegister(bank+index);long offset=register.getAddress().getOffset();if(output.getOffset()<offset+4&&offset<output.getOffset()+output.getSize())actual.add(register.getName());}
            }
        }
        if(!actual.equals(new TreeSet<>(plan.continuation().entry().previousE1Writes())))throw fail("caller-entry E1 inventory mismatch: source="+actual+", declared="+plan.continuation().entry().previousE1Writes());
    }
    private void validateWindowMetadata(TraceWindow window)throws Exception {
        if(program.getFunctionManager().getFunctionAt(entry.getNewAddress(window.ownerEntry()))==null)throw fail("closed-call owner identity missing");
        long first=window.start()&~31L,last=(window.end()+31)&~31L;byte[] bytes=new byte[(int)(last-first)];
        if(program.getMemory().getBytes(entry.getNewAddress(first),bytes)!=bytes.length)throw fail("closed-call short byte window");
        if(!java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes)).equals(window.fetchBytesSha256()))throw fail("closed-call byte hash mismatch");
        for(var gap:window.unownedSpans())for(long pc=gap.start();pc<gap.end();pc++){
            var at=entry.getNewAddress(pc);if(program.getFunctionManager().getFunctionContaining(at)!=null)throw fail("closed-call unowned span overlaps an owner at "+at);
            if(program.getListing().getDefinedDataContaining(at)!=null)throw fail("closed-call unowned span overlaps defined data at "+at);
        }
        if(callerTail!=null){
            physicalBoundary(window.start(),false);physicalBoundary(window.end(),true);
            for(var gap:window.unownedSpans()){physicalBoundary(gap.start(),true);physicalBoundary(gap.end(),true);}
        }
    }
    private void physicalBoundary(long pc,boolean allowHeader)throws Exception {
        if((pc&31)==0)return;
        var at=entry.getNewAddress(pc);
        if(allowHeader&&(pc&31)==28&&(program.getMemory().getInt(at)>>>28)==14)return;
        closedPhysicalLength(at);
    }
    private void validateWindow(TraceWindow window)throws Exception {
        validateWindowMetadata(window);
        var boundaries=new HashSet<Long>();long pc=window.start();while(pc<window.end()){
            closedPhysicalLength(entry.getNewAddress(pc));if(!C6000ExecutionPackets.issuePrefix(program,entry.getNewAddress(pc)).isEmpty())throw fail("closed-call declared packet start has a parallel prefix at "+entry.getNewAddress(pc));
            if(!closedPackets.add(pc))throw fail("closed-call overlapping execute packets");var packet=packet(pc);if(packet.get(0).instruction().getAddress().getOffset()!=pc)throw fail("closed-call declared packet start skips a fetch header");if(packet.size()==8)for(var instruction:packet)if(C6000PacketContext.physicalDecodeFields(program,instruction.instruction().getAddress()).get("c_hdrpkt")==1)throw fail("closed-call eight-instruction header-based execute packet");for(var instruction:packet){closedInstructionPackets.put(instruction.instruction().getAddress().getOffset(),pc);boundaries.add(instruction.instruction().getAddress().getOffset());boundaries.add(instruction.instruction().getMaxAddress().getOffset()+1);}long next=after(packet.get(packet.size()-1));if(next>window.end()||next<=pc)throw fail("closed-call window cuts an execute packet");
            for(var insn:packet){long at=insn.instruction().getAddress().getOffset();for(var gap:window.unownedSpans())if(gap.contains(at)&&at+insn.instruction().getLength()>gap.end())throw fail("closed-call unowned span cuts an instruction");boolean branch=Set.of("B","BNOP","BDEC","BPOS","CALLP").contains(insn.name());
                if(insn.name().startsWith("SPLOOP")||Set.of("SPKERNEL","SPMASK","IDLE").contains(insn.name()))throw fail("closed-call scope excludes software-loop/idle control");
                if(branch&&!closedCalls.containsKey(at)&&!declaredCalleeReturn(at)&&!Objects.equals(at,closedCall.callerReturnPc())){
                    var target=insn.instruction().getAddress(0);
                    if(window.equals(closedCall.caller())||insn.name().equals("CALLP")||insn.instruction().getRegister(0)!=null||target==null||!window.contains(target.getOffset()))throw fail("closed-call undeclared control edge");
                    closedInternalBranches.add(at);
                }
                if(branch&&!closedInternalBranches.contains(at)&&insn.predicate()!=null)throw fail("closed-call control edge must be unconditional");
                if(!window.equals(closedCall.caller()))for(var plan:closedCalls.values())if(plan.callee().equals(window)){
                    var link=callLinkRegister(decode(plan.callPc()));long offset=link.getAddress().getOffset();for(var dest:insn.outputs())if(dest.offset()<offset+4&&offset<dest.offset()+dest.size())throw fail("closed-call callee changes "+link.getName());
                }
            }pc=next;
        }if(pc!=window.end())throw fail("closed-call window is not exact");for(var gap:window.unownedSpans())if(!boundaries.contains(gap.start())||!boundaries.contains(gap.end()))throw fail("closed-call unowned span boundary is not an instruction boundary");
    }
    private void validateCallerTailTarget(long pc){try{validateClosedTargetPacket(pc);}catch(IllegalArgumentException invalid){throw invalid;}catch(Exception invalid){throw fail("caller-tail invalid branch target: "+invalid.getMessage());}}
    private void validateClosedTargetPacket(long pc)throws Exception {
        var target=packet(pc);long fetch=pc&~31L;
        for(var instruction:target)if((instruction.instruction().getMinAddress().getOffset()&~31L)!=fetch||(instruction.instruction().getMaxAddress().getOffset()&~31L)!=fetch)throw fail("closed-call branch-target execute packet spans fetch packets at "+entry.getNewAddress(pc));
    }
    private Register validateReturn(long pc)throws Exception {
        var insn=decode(pc);var register=insn.instruction().getRegister(0);
        if(!Set.of("B","BNOP").contains(insn.name())||register==null||!register.getName().matches("[AB]([0-9]|[12][0-9]|3[01])")||insn.predicate()!=null)throw fail("closed-call expected unconditional register return");return register;
    }
    private Register callLinkRegister(Insn call){
        if(!call.name().equals("CALLP"))return program.getRegister("B3");
        var outputs=call.outputs().stream().filter(d->d.size()==4&&d.phase()==1).toList();
        if(outputs.size()!=1)throw fail("CALLP must have one exact E1 link output");var register=program.getRegister(program.getAddressFactory().getRegisterSpace().getAddress(outputs.get(0).offset()),4);
        if(register==null||!Set.of("A3","B3").contains(register.getName()))throw fail("invalid CALLP link register");return register;
    }
    private void validateClosedCall()throws Exception {
        if(!closedCall.entry().drained())throw fail("closed-call requires explicit drained entry");
        if(!program.getLanguageID().getIdAsString().equals(closedCall.languageId())||function.getEntryPoint().getOffset()!=closedCall.caller().ownerEntry())throw fail("closed-call language/owner identity mismatch");
        var windows=new LinkedHashSet<TraceWindow>();windows.add(closedCall.caller());
        for(var plan:closedCalls.values()){if(plan.callee().start()!=plan.callee().ownerEntry())throw fail("closed-call callee must enter at its owner entry");windows.add(plan.callee());}
        var ordered=new ArrayList<>(windows);for(int a=0;a<ordered.size();a++)for(int b=a+1;b<ordered.size();b++)if(ordered.get(a).start()<ordered.get(b).end()&&ordered.get(b).start()<ordered.get(a).end())throw fail("closed-call overlapping or inconsistent owner windows");
        for(var window:windows)validateWindow(window);
        if(!closedPackets.contains(closedCall.startPc())||closedCall.stopPc()!=null&&closedCall.stopPc()<=closedCall.startPc())throw fail("closed-call start/continuation is not a packet boundary");
        for(long at:closedInternalBranches){long target=decode(at).instruction().getAddress(0).getOffset();if(!closedPackets.contains(target))throw fail("closed-call internal target is not a packet boundary");validateClosedTargetPacket(target);}
        validateClosedTargetPacket(closedCall.startPc());if(closedCall.callerReturnPc()!=null)validateReturn(closedCall.callerReturnPc());
        var plans=new ArrayList<>(closedCalls.values());plans.sort(Comparator.comparingLong(ClosedCallPlan::callPc));
        var constants=new C6000LoopCounterProof(program.getLanguage());var shadows=new ArrayList<C6000LoopCounterProof.UnknownWrite>();long pc=closedCall.startPc();
        for(var plan:plans){
            Long callPacket=closedInstructionPackets.get(plan.callPc());if(callPacket==null||!closedPackets.contains(plan.continuation())||callPacket<pc)throw fail("closed-call start/continuation is not a packet boundary");
            while(pc<callPacket){var pack=packet(pc);if(pack.stream().anyMatch(i->Set.of("B","BNOP","BDEC","BPOS","CALLP").contains(i.name())))throw fail("closed-call target prefix is not straight-line");proofPacket(constants,pack,shadows);pc=after(pack.get(pack.size()-1));}
            var call=decode(plan.callPc());var targetRegister=call.instruction().getRegister(0);
            if(!Set.of("B","CALLP").contains(call.name())||call.predicate()!=null)throw fail("closed-call target must be an unconditional B or CALLP");
            Long destination=targetRegister==null?(call.instruction().getAddress(0)==null?null:call.instruction().getAddress(0).getOffset()):constants.registerValue(targetRegister.getAddress().getOffset(),4);
            if(pc!=callPacket||destination==null||(destination&0xffffffffL)!=plan.callee().start())throw fail("closed-call target lacks exact packet-old constant proof");
            var linkRegister=callLinkRegister(call);long linkOffset=linkRegister.getAddress().getOffset();
            if(!validateReturn(plan.calleeReturnPc()).equals(linkRegister))throw fail("closed-call callee return does not use the proved link register");
            validateClosedTargetPacket(plan.callee().start());validateClosedTargetPacket(plan.continuation());
            // SPRUFE8B 3.5/3.7, CALLP p.172 and 4.2.6: six advances,
            // packet-old target, E1 links. An early correct link remains valid.
            int elapsed=0;long lastWriter=-1;var writers=new ArrayList<Long>();
            while(elapsed<6){var pack=packet(pc);int span=pack.stream().mapToInt(Insn::span).max().orElse(1);
                for(var i:pack){long at=i.instruction().getAddress().getOffset();if(at!=plan.callPc()&&Set.of("B","BNOP","BDEC","BPOS","CALLP").contains(i.name()))throw fail("closed-call control edge in call delay window");
                    for(var d:i.outputs())if(d.offset()<linkOffset+4&&linkOffset<d.offset()+d.size()){
                        if(!Set.of("ADDKPC","MVK","MVKL","MVKH","CALLP").contains(i.name())||i.predicate()!=null||d.offset()!=linkOffset||d.size()!=4||d.phase()!=1||(!Set.of("CALLP","ADDKPC").contains(i.name())&&i.span()!=1))throw fail("closed-call link lacks exact unconditional E1 "+linkRegister.getName()+" proof at "+i.instruction().getAddress());
                        writers.add(at);lastWriter=at;
                    }
                }proofPacket(constants,pack,shadows);elapsed+=span;pc=after(pack.get(pack.size()-1));
            }
            Long link=constants.registerValue(linkOffset,4);
            if(elapsed!=6||pc!=plan.continuation()||lastWriter!=plan.linkPc()||link==null||(link&0xffffffffL)!=plan.continuation())throw fail("closed-call link lacks exact continuation proof");
            for(var i:instructions.values())if(plan.caller().contains(i.instruction().getAddress().getOffset())&&i.instruction().getAddress().getOffset()<plan.continuation())for(var d:i.outputs())if(d.offset()<linkOffset+4&&linkOffset<d.offset()+d.size()&&d.phase()!=1)throw fail("closed-call pre-link late register writer");
            closedProofs.put(plan.callPc(),new ClosedCallProof(plan.callPc(),targetRegister==null?null:targetRegister.getName(),destination&0xffffffffL,plan.continuation(),List.copyOf(writers),slot("call_target",plan.callPc(),5,0,4)));
            var outputs=new ArrayList<C6000LoopCounterProof.Output>();for(var i:instructions.values())if(plan.callee().contains(i.instruction().getAddress().getOffset()))for(var d:i.outputs())outputs.add(new C6000LoopCounterProof.Output(d.offset(),d.size(),d.valueOffset(),d.phase(),true));
            shadows.addAll(constants.returnFromCall(outputs));
        }
    }
    private void proofPacket(C6000LoopCounterProof constants,List<Insn> pack,List<C6000LoopCounterProof.UnknownWrite> shadows){
        int span=pack.stream().mapToInt(Insn::span).max().orElse(1);for(int cycle=0;cycle<span;cycle++){
            var operations=new ArrayList<C6000LoopCounterProof.Operation>(cycle==0?proofOperations(pack):List.of());var outputs=new ArrayList<C6000LoopCounterProof.Output>();
            for(var shadow:shadows)outputs.add(new C6000LoopCounterProof.Output(shadow.offset(),shadow.size(),shadow.offset(),1,true));
            if(!outputs.isEmpty())operations.add(new C6000LoopCounterProof.Operation(new PcodeOp[0],outputs,null,false));constants.packet(operations);
            shadows.replaceAll(w->new C6000LoopCounterProof.UnknownWrite(w.offset(),w.size(),w.advances()-1));shadows.removeIf(w->w.advances()<=0);
        }
    }
    private void closedBoundary(String kind,Branch landing,List<Flight> flights,List<Hazard> hazards,ClosedCallPlan plan)throws Exception {
        var effects=new ArrayList<PendingEffect>();var stores=new ArrayList<PendingStore>();var recent=new ArrayList<BoundaryHazard>();
        for(var flight:flights){var i=decode(flight.pc());effects.add(new PendingEffect(flight.pc(),flight.age(),i.latency()-flight.age(),slot("predicate",flight.pc(),flight.age(),0,1),java.util.HexFormat.of().formatHex(i.instruction().getBytes())));if(i.name().equals("STW")){var inputs=new LinkedHashMap<String,Varnode>();for(long offset:i.regs()){var register=program.getRegister(program.getAddressFactory().getRegisterSpace().getAddress(offset),4);if(register!=null)inputs.put(register.getName(),slot("input",flight.pc(),flight.age(),offset,4));}stores.add(new PendingStore(flight.pc(),flight.age(),3-flight.age(),slot("predicate",flight.pc(),flight.age(),0,1),slot("store_address",flight.pc(),flight.age(),0,4),slot("store_value",flight.pc(),flight.age(),0,4),Map.copyOf(inputs),java.util.HexFormat.of().formatHex(i.instruction().getBytes())));}}
        for(var hazard:hazards)for(long offset:hazard.registers()){var register=program.getRegister(program.getAddressFactory().getRegisterSpace().getAddress(offset),4);if(register!=null)recent.add(new BoundaryHazard(register.getName(),slot("hazard",hazard.pc(),0,0,1)));}
        int marker=b.code.size();b.op(PcodeOp.COPY,temp(1),c(0,1));Varnode target=landing.returns()?slot("target",landing.pc(),landing.age(),0,4):arch(callLinkRegister(decode(plan.callPc())).getAddress().getOffset(),4);
        closedBoundaries.add(new ClosedCallBoundary(marker,kind,landing.pc(),target,kind.equals("CALLER_RETURN")?null:plan.continuation(),List.copyOf(effects),List.copyOf(stores),List.copyOf(recent)));
    }
    private Set<String> closedHazards(List<Hazard> hazards)throws Exception {
        Set<String> writes=new TreeSet<>();for(var hazard:hazards){if(decode(hazard.pc()).predicate()!=null)throw fail("closed-call exit has a conditional hazard");for(long offset:hazard.registers()){var register=program.getRegister(program.getAddressFactory().getRegisterSpace().getAddress(offset),4);if(register==null)throw fail("closed-call exit hazard is unknown");writes.add(register.getName());}}return Set.copyOf(writes);
    }
    private void closeClosedTrace(State state)throws Exception {
        if(state.idle()!=0||!state.flights().isEmpty()||!state.branches().isEmpty()||state.loop()!=null)throw fail("closed-call endpoint still has pending effects");
        var writes=closedHazards(state.hazards());if(closedExitWrites!=null&&!closedExitWrites.equals(writes))throw fail("closed-call incompatible exit hazards");closedExitWrites=writes;
        b.op(PcodeOp.COPY,new Varnode(program.getRegister("C6000_PIPE_RET").getAddress(),4),c(closedCall.stopPc(),4));b.jump(PcodeOp.BRANCH,"exit",null);
    }

    private record Flight(long pc,int age,int predicateTruth){
    }

    private record Branch(long pc,int age,long target,boolean returns){
    }

    private record Hazard(long pc,List<Long> registers,boolean predicateUnchanged){
        // Unknown external/legacy history cannot establish sampled-predicate
        // identity. Ordinary compile captures this from all committed writes.
        Hazard(long pc,List<Long> registers){this(pc,registers,false);}
    }

    private record LoopFrame(long start,int time,int drain,boolean zero,boolean refill,boolean abrupt) {}
    private record LoopCell(List<Insn> source,List<Insn> buffered,int mask,long nextPc) {}
    private record LoopPlan(long start,String kind,int ii,int fetchDelay,int cap,List<LoopCell> cells,long postPc) {}
    private static final long NO_CALL=-1,ENTRY_LINK=-2;
    private record ReturnFlow(long activeCall,Map<Long,Long> links) {}
    private record State(long pc,int idle,List<Flight> flights,List<Branch> branches,List<Hazard> hazards,LoopFrame loop,PredicateFacts facts,ReturnFlow returns){
    }

    // Zero/nonzero facts refer only to the six architectural predicate GPRs.
    // Tokens identify copies of the same pre-E1 value; they are canonicalized
    // after every transfer, so no unbounded register-version counter enters State.
    private record PredicateValue(int token,int truth) {} // -1 unknown, 0 zero, 1 nonzero
    private record PredicateFacts(List<PredicateValue> values) {
        static PredicateFacts unknown(){var values=new ArrayList<PredicateValue>();for(int k=0;k<6;k++)values.add(new PredicateValue(k,-1));return new PredicateFacts(List.copyOf(values));}
        PredicateFacts constrain(int index,int truth){
            var value=values.get(index);if(value.truth()>=0&&value.truth()!=truth)return null;
            var narrowed=new ArrayList<PredicateValue>();for(var old:values)narrowed.add(old.token()==value.token()?new PredicateValue(old.token(),truth):old);
            return new PredicateFacts(List.copyOf(narrowed));
        }
        PredicateFacts canonical(){
            var names=new LinkedHashMap<Integer,Integer>();var canonical=new ArrayList<PredicateValue>();
            for(var value:values)canonical.add(new PredicateValue(names.computeIfAbsent(value.token(),k->names.size()),value.truth()));
            return new PredicateFacts(List.copyOf(canonical));
        }
    }

    private record Dest(long offset,int size,boolean flags,int phase,long valueOffset,long mask,int sourceWrite){
        Dest(long offset,int size,boolean flags,int phase,long valueOffset,long mask){this(offset,size,flags,phase,valueOffset,mask,-1);}
    }

    private record Read(long offset,int first,int last,int phases) {}

    private record Insn(Instruction instruction,String name,PcodeOp[] raw,List<Long> regs,List<Dest> outputs,int latency,int ready,List<Read> reads,int guard,int span,boolean load,boolean store,Register predicate,boolean inverted){
    }

    private record Eval(long image,Varnode predicate,Map<Long,Varnode> flags,Varnode transferTaken,Map<Integer,Varnode> writes,Map<Integer,Varnode> written){
        Eval(long image,Varnode predicate,Map<Long,Varnode> flags,Varnode transferTaken){this(image,predicate,flags,transferTaken,Map.of(),Map.of());}
    }
    private final Program program;
    private final Function function;
    private final Address entry;
    private final List<Long> entryWrites;
    private final AddressSpace unique,constant;
    private final Builder b;
    private final Map<Long,Insn> instructions=new HashMap<>();
    private final Map<Long,LoopPlan> loopPlans=new HashMap<>();
    private final Map<Long,C6000LoopCounterProof.Proof> loadingCountProofs=new HashMap<>();
    private final LinkedHashMap<State,Integer> states=new LinkedHashMap<>();
    private final Map<String,Varnode> slots=new HashMap<>();
    private final AddressSet covered=new AddressSet();

    private long nextUnique=0x10000000;

    private int packets;
    private final Map<Integer,Long> cycleStarts=new LinkedHashMap<>();
    private final Map<Integer,String> stallLabels=new LinkedHashMap<>();
    private final boolean crossPathStalls;
    private TaskMonitor monitor=TaskMonitor.DUMMY;
    // SPRUFE8B ANDN pp.145-146: .L/.S/.D read both inputs and write dst in E1.
    // SPRUFE8B PACK2 pp.397-398 / PACKL4 pp.407-408: E1 source reads and dst write.
    private static final Set<String> SINGLE=Set.of("ADD","ADDK","ADDAW","ADDAD","ADDAH","ADDAB","SUBAW","SUBAH","SUBAB","SUB","AND","ANDN","OR","XOR","NOT","MV","MVK","MVKH","MVKL","MVKLH","SHL","SHR","SHRU","EXT","EXTU","SET","CLR","CMPEQ","CMPGT","CMPLT","CMPEQSP","CMPGTSP","CMPLTSP","CMPGTU","CMPLTU","ZERO","NEG","ABS","NORM","LMBD","ABSSP","DINT","RINT","PACK2","PACKL4");

    public C6000PipelineCompiler(Program p,Function f){
        this(p,f,Set.of());
    }

    public C6000PipelineCompiler(Program p,Function f,Set<String> previousE1Writes){
        this(p,f,previousE1Writes,f.getEntryPoint().getOffset());
    }
    private C6000PipelineCompiler(Program p,Function f,Set<String> previousE1Writes,long startPc){
        program=p;
        String variant=p.getLanguage().getLanguageDescription().getVariant();
        // SPRU198K 6.3.2.2: C64x cross-path stalls do not occur on C67x.
        // The language identity also binds this choice in reviewed contracts.
        crossPathStalls=!Set.of("c67x","c67x-analysis").contains(variant);
        function=f;
        entry=f.getEntryPoint().getNewAddress(startPc);
        unique=p.getAddressFactory().getUniqueSpace();
        constant=p.getAddressFactory().getConstantSpace();
        b=new Builder();
        TreeSet<Long> writes=new TreeSet<>();
        for(String name:previousE1Writes){
            if(!name.matches("[AB]([0-9]|[12][0-9]|3[01])"))throw fail("entry hazard must name a 32-bit GPR: "+name);
            writes.add(p.getRegister(name).getAddress().getOffset());
        }
        entryWrites=List.copyOf(writes);
    }

    private Varnode temp(int size){
        long at=nextUnique;
        nextUnique+=(size+15)&~15;
        return new Varnode(unique.getAddress(at),size);
    }

    private long image(){
        long at=nextUnique;
        nextUnique+=0x4000;
        return at;
    }

    private Varnode im(long base,long off,int size){
        return new Varnode(unique.getAddress(base+off),size);
    }

    private Varnode c(long value,int size){
        return new Varnode(constant.getAddress(value),size);
    }

    private Varnode arch(long off,int size){
        return new Varnode(program.getAddressFactory().getRegisterSpace().getAddress(off),size);
    }

    private Varnode slot(String kind,long pc,int age,long off,int size){
        return slots.computeIfAbsent(kind+":"+pc+":"+age+":"+off+":"+size,k->temp(size));
    }

    private int state(State s){
        Integer n=states.get(s);
        if(n!=null)return n;
        if(states.size()>=4096)throw fail("schedule exceeds 4096 distinct pipeline states");
        int i=states.size();
        states.put(s,i);
        return i;
    }

    private IllegalArgumentException fail(String message){
        return new IllegalArgumentException("C6000 schedule "+entry+": "+message);
    }

    private static String base(Instruction i){
        String n=i.getMnemonicString().trim();
        int j=n.indexOf(']');
        if(n.startsWith("[")&&j>=0)n=n.substring(j+1).trim();
        if(n.startsWith("_"))n=n.substring(1).trim();
        int dot=n.indexOf('.');
        return dot<0?n:n.substring(0,dot);
    }

    private Insn decode(long pc)throws Exception{
        if(instructions.containsKey(pc))return instructions.get(pc);
        Address at=entry.getNewAddress(pc);
        var owner=program.getFunctionManager().getFunctionContaining(at);
        var window=closedWindow(pc);
        if(strictScope()){if(window==null)throw fail("closed-call flow leaves declared ownership at "+at);if(window.unowned(pc)?owner!=null:owner==null||owner.getEntryPoint().getOffset()!=window.ownerEntry()||!owner.getBody().contains(at))throw fail("closed-call flow leaves declared ownership at "+at);}
        if(callerPc(pc)&&callerTail==null){
            if(owner!=null&&owner.getEntryPoint().getOffset()!=traceContract.callerFunctionEntry())throw fail("caller continuation has conflicting ownership at "+at);
            if(owner==null&&!traceContract.allowUnownedWindow())throw fail("caller continuation has unowned code at "+at);
        }
        if(program.getListing().getDefinedDataContaining(at)!=null)throw fail("scheduled code conflicts with defined data at "+at);
        if(owner!=null&&!owner.equals(function)&&!callerPc(pc)&&!strictScope())throw fail("flow enters another function at "+at);
        if(!strictScope()&&!callerPc(pc)&&(pc>function.getBody().getMaxAddress().getOffset()+254||pc<function.getBody().getMinAddress().getOffset()))throw fail("flow leaves owned code at "+at);
        int physicalLength=!strictScope()?0:closedPhysicalLength(at);
        var context=new ProcessorContextImpl(program.getLanguage());
        var value=program.getProgramContext().getRegisterValue(program.getLanguage().getContextBaseRegister(),at);
        if(value!=null)context.setRegisterValue(value);
        if(strictScope())for(var field:C6000PacketContext.physicalDecodeFields(program,at).entrySet())context.setRegisterValue(new RegisterValue(program.getRegister(field.getKey()),BigInteger.valueOf(field.getValue())));
        if(callerPc(pc)&&callerTail==null)for(String name:List.of("c_is16","c_rs","c_dsz","c_sat","c_br","c_prot","c_isheader","c_pfollow","c_hdrpkt"))context.setRegisterValue(new RegisterValue(program.getRegister(name),BigInteger.ZERO));
        context.setRegisterValue(new RegisterValue(program.getRegister("c_flow_delay"),BigInteger.ZERO));
        context.setRegisterValue(new RegisterValue(program.getRegister("c_schedule_entry"),BigInteger.ZERO));
        context.setRegisterValue(new RegisterValue(program.getRegister("c_branch_terminal"),BigInteger.ONE));
        var memory=new DumbMemBufferImpl(program.getMemory(),at);
        var prototype=program.getLanguage().parse(memory,context,false);
        var ins=new PseudoInstruction(program,at,prototype,memory,context);
        if(strictScope()){if(ins.getLength()!=physicalLength)throw fail("closed-call decoder width conflicts with physical fetch layout at "+at);validateClosedInstruction(ins);}
        String name=base(ins);
        boolean load=name.startsWith("LD"),store=name.startsWith("ST");
        int latency;
        if(name.equals("CPKT"))latency=0;
        else if(load)latency=5;
        else if(store)latency=3;
        // SPRUFE8B MPYLI pp.344--345: E1 reads, simultaneous pair write E4, .M use E1.
        else if(Set.of("MPYLI","ADDSP","SUBSP","MPYSP","MVD","DPSP","DPINT","DPTRUNC","INTSP","SPINT","SPTRUNC").contains(name))latency=4;
        // SPRUFE8B ROTL pipeline, pp.414--415: both sources in E1, dst in E2.
        else if(Set.of("ROTL","MPY","MPYSU","MPYU","MPYUS","SPDP","ABSDP","RCPDP","RSQRDP","CMPEQDP","CMPLTDP","CMPGTDP").contains(name))latency=2;
        else if(Set.of("ADDDP","SUBDP","MPYSPDP").contains(name))latency=7;
        else if(Set.of("INTDP","INTDPU","MPYSP2DP").contains(name))latency=5;
        else if(name.equals("MPYDP"))latency=10;
        else if(name.equals("MVC")){
            latency=1;
            Set<String> ordinary=Set.of("AMR","CSR","FADCR","FAUCR","FMCR","ILC","RILC","TSR");
            for(int operand=0;operand<ins.getNumOperands();operand++) {
                for(Object object:ins.getOpObjects(operand)) if(object instanceof Register register) {
                    String registerName=register.getName();
                    if(!registerName.matches("[AB]([0-9]|[12][0-9]|3[01])")&&!ordinary.contains(registerName))                         throw fail("unimplemented control-register phase contract at "+at+": "+registerName);
                }
            }
        }
        else if(SINGLE.contains(name)||Set.of("NOP","B","BNOP","BDEC","BPOS","CALLP","ADDKPC","SPLOOP","SPLOOPD","SPLOOPW","SPMASK","SPKERNEL").contains(name))latency=1;
        else throw fail("unimplemented phase contract "+ins+" at "+at);
        var raw=Set.of("SPLOOP","SPLOOPD","SPLOOPW","SPMASK","SPKERNEL").contains(name)?new PcodeOp[0]:ins.getPcode(false);
        if(name.equals("CALLP")){
            long next;try{next=ins.getMaxAddress().getOffset()+1+C6000ExecutionPackets.parallelBytes(program,at);}
            catch(ghidra.program.model.mem.MemoryAccessException invalid){throw fail("CALLP invalid execute packet: "+invalid.getMessage());}
            if((next&31)==28&&program.getMemory().contains(entry.getNewAddress(next+3))&&(program.getMemory().getInt(entry.getNewAddress(next))>>>28)==14)next+=4;
            raw=Arrays.copyOf(raw,raw.length);int links=0;
            for(int k=0;k<raw.length;k++){var op=raw[k];var out=op.getOutput();if(out!=null&&out.isRegister()){
                var register=program.getRegister(out.getAddress(),out.getSize());if(op.getOpcode()!=PcodeOp.COPY||register==null||!Set.of("A3","B3").contains(register.getName())||!op.getInput(0).isConstant())throw fail("unexpected raw CALLP link");
                raw[k]=new PcodeOp(at,k,PcodeOp.COPY,new Varnode[]{c(next,4)},out);links++;
            }}if(links!=1)throw fail("missing raw CALLP E1 link");
        }
        TreeSet<Long> regs=new TreeSet<>();
        Map<String,Dest> destinations=new LinkedHashMap<>();
        Set<Integer> loadWrites=load?C6000MemoryWritePhases.loadWrites(raw):Set.of();
        for(int rawIndex=0;rawIndex<raw.length;rawIndex++){
            var op=raw[rawIndex];
            if(op.getOpcode()==PcodeOp.UNIMPLEMENTED||op.getOpcode()==PcodeOp.CALLOTHER)throw fail("opaque semantics at "+at);
            List<Varnode> nodes=new ArrayList<>(Arrays.asList(op.getInputs()));
            if(op.getOutput()!=null)nodes.add(op.getOutput());
            for(var v:nodes)if(v.isRegister()){
                long off=v.getOffset()&~3L;
                for(long k=off;k<v.getOffset()+v.getSize();k+=4)regs.add(k);
            }
            var out=op.getOutput();
            if(out!=null&&out.isRegister()){
                var reg=program.getRegister(out.getAddress(),out.getSize());
                if(reg==null)throw fail("unknown architectural output at "+at);
                boolean flags=(Set.of("FADCR","FAUCR","FMCR").contains(reg.getName())&&!name.equals("MVC")) || (name.equals("ABS")&&Set.of("CSR","SSR").contains(reg.getName()));
                int phase=load||store?(loadWrites.contains(rawIndex)?5:1):latency;
                var destination=new Dest(out.getOffset(),out.getSize(),flags,phase,out.getOffset(),-1,load||store?rawIndex:-1);
                if(load&&phase==5&&!isLoadData(ins,destination))throw fail("load-derived non-destination write at "+at);
                destinations.put(out.getOffset()+":"+out.getSize()+(load||store?":"+rawIndex:""),destination);
            }
        }
        if(traceContract!=null||callerTail!=null){long b3=program.getRegister("B3").getAddress().getOffset();for(var destination:destinations.values())if(destination.offset()<b3+4&&b3<destination.offset()+destination.size())throw fail("caller continuation requires unchanged entry B3");}
        // SPRUFE8B 4.2.7--4.2.16: semantic read words and independent write phases.
        List<Read> reads=new ArrayList<>();int ready=1;
        if(Set.of("ADDDP","SUBDP","CMPEQDP","CMPLTDP","CMPGTDP","MPYSPDP").contains(name)){
            ready=2;
            if(name.equals("MPYSPDP")){
                addRead(reads,ins.getRegister(0),false,1,2);
                addRead(reads,ins.getRegister(1),true,2,2);
            }else{
                // SPRUFE8B Table 4-16 / SPRU733A Table 4-12: ADDDP,
                // SUBDP and DP compares sample BOTH upper words in E2.
                // Reversed SUBDP spelling changes operand order, not phases.
                addRead(reads,ins.getRegister(0),true,2,2);
                addRead(reads,ins.getRegister(1),true,2,2);
            }
        }
        if(name.equals("MPYDP")){
            ready=4;
            addRead(reads,ins.getRegister(0),false,1,2);addRead(reads,ins.getRegister(0),true,3,4);
            addRead(reads,ins.getRegister(1),false,1,3);addRead(reads,ins.getRegister(1),true,2,4);
        }
        Map<String,Dest> phased=new LinkedHashMap<>();
        for(var d:destinations.values()){
            int phase=d.phase();
            if(load||store)phase=d.phase();
            if(Set.of("SPDP","ABSDP","RCPDP","RSQRDP").contains(name))phase=1;
            if(Set.of("ADDDP","SUBDP","MPYSPDP").contains(name))phase=6;
            if(Set.of("INTDP","INTDPU","MPYSP2DP").contains(name))phase=4;
            if(name.equals("MPYDP"))phase=9;
            if(d.size()==8&&Set.of("SPDP","ABSDP","RCPDP","RSQRDP","ADDDP","SUBDP","MPYSPDP","INTDP","INTDPU","MPYSP2DP","MPYDP").contains(name)){
                long low=d.offset()+(program.getLanguage().isBigEndian()?4:0),high=d.offset()+(program.getLanguage().isBigEndian()?0:4);
                phased.put(low+":4",new Dest(low,4,false,phase,low,-1));phased.put(high+":4",new Dest(high,4,false,phase+1,high,-1));
            }else phased.put(d.offset()+":"+d.size()+(d.sourceWrite()<0?"":":"+d.sourceWrite()),new Dest(d.offset(),d.size(),d.flags(),phase,d.valueOffset(),d.mask(),d.sourceWrite()));
        }
        // MVC's explicitly named register changes in E1 (2.8.2), but the loop
        // counter interface observes ILC/RILC loads four cycles later (7.4.3--4).
        if(name.equals("MVC"))for(String counter:List.of("ILC","RILC")){
            long offset=program.getRegister(counter).getAddress().getOffset();
            if(phased.containsKey(offset+":4")){
                long target=program.getRegister("C6000_PIPE_"+counter).getAddress().getOffset();
                phased.put(target+":4",new Dest(target,4,false,4,offset,-1));latency=4;
            }
        }
        if(name.equals("DINT")||name.equals("RINT"))for(String control:List.of("CSR","TSR")){
            long offset=program.getRegister(control).getAddress().getOffset();var d=phased.get(offset+":4");if(d==null)throw fail("missing interrupt-control output");
            phased.put(offset+":4",new Dest(offset,4,false,1,offset,control.equals("CSR")?1:3));
        }
        destinations=phased;
        if(load||store){var events=new ArrayList<>(destinations.values());for(int x=0;x<events.size();x++)for(int y=x+1;y<events.size();y++){
            var left=events.get(x);var right=events.get(y);
            if(left.phase()==right.phase()&&left.offset()<right.offset()+right.size()&&right.offset()<left.offset()+left.size())throw fail("ambiguous raw memory writes in one phase at "+at);
        }}
        int span=1;
        if(name.equals("CALLP"))span=6;
        if(name.equals("NOP"))span=Math.max(1,(int)ins.getScalar(0).getValue());
        if(name.equals("BNOP"))span=1+C6000ExecutionPackets.bnopCount(program,ins);
        if(name.equals("ADDKPC"))span=1+(int)ins.getScalar(2).getValue();
        if(load&&C6000ExecutionPackets.protectedLoad(program,ins))span=5;
        Register pred=null;
        boolean inverted=false;
        Matcher pm=Pattern.compile("\\[(!?)([AB][012])\\]").matcher(ins.getMnemonicString());
        if(pm.find()){
            pred=program.getRegister(pm.group(2));
            inverted=!pm.group(1).isEmpty();
            regs.add(pred.getAddress().getOffset());
        }
        int guard=-1;
        if(pred!=null&&ready>1){
            // Recognize the dominating instruction predicate guard, not an arithmetic branch.
            for(int n=0;n<raw.length;n++){
                var op=raw[n];
                if(op.getOutput()!=null&&op.getOutput().isRegister())break;
                boolean otherRegister=Arrays.stream(op.getInputs()).anyMatch(v->v.isRegister()&&v.getOffset()!=predOffset(ins));
                if(otherRegister)break;
                if(op.getOpcode()==PcodeOp.CBRANCH){
                    if(op.getInput(0).isConstant()&&n+(int)op.getInput(0).getOffset()==raw.length)guard=n;
                    break;
                }
            }
            if(guard<0)throw fail("cannot prove delayed predicate guard at "+at);
        }
        var desc=new Insn(ins,name,raw,List.copyOf(regs),List.copyOf(destinations.values()),latency,ready,List.copyOf(reads),guard,span,load,store,pred,inverted);
        instructions.put(pc,desc);
        return desc;
    }

    private long predOffset(Instruction instruction){
        Matcher predicate=Pattern.compile("\\[!?([AB][012])\\]").matcher(instruction.getMnemonicString());
        if(!predicate.find())throw fail("predicate disappeared");
        return program.getRegister(predicate.group(1)).getAddress().getOffset();
    }

    private void addRead(List<Read> reads,Register register,boolean high,int first,int last){
        if(register==null)throw fail("missing DP source register");
        long offset=register.getAddress().getOffset();
        if(high){if(register.getMinimumByteSize()!=8)throw fail("DP source is not a pair");offset+=program.getLanguage().isBigEndian()?0:4;}
        else if(register.getMinimumByteSize()==8)offset+=program.getLanguage().isBigEndian()?4:0;
        int phases=((1<<last)-1)^((1<<(first-1))-1);
        if(first==1&&last==3)phases=5;if(first==2&&last==4)phases=10;
        reads.add(new Read(offset,first,last,phases));
    }

    private boolean isLoadData(Instruction ins,Dest d){
        var r=ins.getRegister(ins.getNumOperands()-1);
        if(r==null)throw fail("load destination missing at "+ins.getAddress());
        return d.offset()<r.getAddress().getOffset()+r.getMinimumByteSize()&&d.offset()+d.size()>r.getAddress().getOffset();
    }

    private long after(Insn i)throws Exception{
        long pc=i.instruction().getMaxAddress().getOffset()+1;
        Address at=entry.getNewAddress(pc);
        if((pc&31)==28&&program.getMemory().contains(at.add(3))&&(program.getMemory().getInt(at)>>>28)==0xe){
            covered.add(at,at.add(3));
            pc+=4;
        }
        return pc;
    }

    private List<Insn> packet(long pc)throws Exception{
        if(callerTail!=null){closedPhysicalLength(entry.getNewAddress(pc));if(!C6000ExecutionPackets.issuePrefix(program,entry.getNewAddress(pc)).isEmpty())throw fail("caller-tail packet start has a parallel prefix at "+entry.getNewAddress(pc));}
        List<Insn> result=new ArrayList<>();
        Insn i=decode(pc);
        while(i.name().equals("CPKT"))i=decode(after(i));
        while(true){
            result.add(i);
            covered.add(i.instruction().getMinAddress(),i.instruction().getMaxAddress());
            if(result.size()>8)throw fail("oversized execute packet");
            if(!C6000ExecutionPackets.parallelWithNext(program,i.instruction()))break;
            i=decode(after(i));
        }
        if(callerTail!=null){if(result.get(0).instruction().getAddress().getOffset()!=pc)throw fail("caller-tail packet start skips a header");if(result.size()==8)for(var instruction:result)if(C6000PacketContext.physicalDecodeFields(program,instruction.instruction().getAddress()).get("c_hdrpkt")==1)throw fail("caller-tail eight-instruction header-based execute packet");}
        return result;
    }

    private boolean dataDest(Insn i,Dest d){
        if(!i.load())return !i.store();
        var r=i.instruction().getRegister(i.instruction().getNumOperands()-1);
        if(r==null)throw fail("load destination missing at "+i.instruction().getAddress());
        return d.offset()<r.getAddress().getOffset()+r.getMinimumByteSize()&&d.offset()+d.size()>r.getAddress().getOffset();
    }

    private Eval evaluate(Insn i,Integer age,boolean actualMemory,Map<Long,Varnode> late)throws Exception{
        long pc=i.instruction().getAddress().getOffset(),img=image();
        for(long off:i.regs())b.op(PcodeOp.COPY,im(img,off,4),late.containsKey(off)?late.get(off):age==null?arch(off,4):slot("input",pc,age,off,4));
        Varnode predicate=age==null?temp(1):slot("predicate",pc,age,0,1);
        if(age==null){
            if(i.predicate()==null)b.op(PcodeOp.COPY,predicate,c(1,1));
            else b.op(i.inverted()?PcodeOp.INT_EQUAL:PcodeOp.INT_NOTEQUAL,predicate,arch(i.predicate().getAddress().getOffset(),4),c(0,4));
        }
        // SPRUFE8B BDEC/BPOS pp.159-160/170-171: retain the raw
        // predicate AND signed-counter condition, without duplicating arithmetic.
        Varnode transferTaken=Set.of("BDEC","BPOS").contains(i.name())?temp(1):null;
        if(transferTaken!=null)b.op(PcodeOp.COPY,transferTaken,c(0,1));
        Map<Long,Varnode> flags=new LinkedHashMap<>();
        Map<Integer,Varnode> writes=new LinkedHashMap<>(),written=new LinkedHashMap<>();
        for(var d:i.outputs())if(d.sourceWrite()>=0){var value=temp(d.size());var active=temp(1);writes.put(d.sourceWrite(),value);written.put(d.sourceWrite(),active);b.op(PcodeOp.COPY,value,c(0,d.size()));b.op(PcodeOp.COPY,active,c(0,1));}
        for(var d:i.outputs())if(d.flags()){
            var flag=temp(d.size());
            flags.put(d.offset(),flag);
            b.op(PcodeOp.COPY,flag,c(0,d.size()));
        }
        String prefix="raw"+b.labelCounter++ +"_";
        PcodeOp[] raw=i.raw();
        // Relocate connected unique-space byte intervals, preserving overlapping
        // subpieces. Raw unique offsets are not register-image offsets.
        TreeSet<Long> bytes=new TreeSet<>();
        for(var op:raw){
            List<Varnode> all=new ArrayList<>(Arrays.asList(op.getInputs()));
            if(op.getOutput()!=null)all.add(op.getOutput());
            for(var v:all)if(v.isUnique())for(long k=v.getOffset();k<v.getOffset()+v.getSize();k++)bytes.add(k);
        }
        TreeMap<Long,Long> translations=new TreeMap<>();
        Long first=null,last=null;
        for(long at:bytes){
            if(first==null)first=at;
            else if(at!=last+1){
                translations.put(first,temp((int)(last-first+1)).getOffset());
                first=at;
            }
            last=at;
        }
        if(first!=null)translations.put(first,temp((int)(last-first+1)).getOffset());
        java.util.function.Function<Varnode,Varnode> mapper=v->{
            if(v.isRegister())return im(img,v.getOffset(),v.getSize());
            if(v.isUnique()){
                var tr=translations.floorEntry(v.getOffset());
                return new Varnode(unique.getAddress(tr.getValue()+v.getOffset()-tr.getKey()),v.getSize());
            }
            return v;
        };
        // Capture the exact address/data already produced by native store
        // p-code in E1. This observes temporaries, never performs memory early.
        StoreCapture traceStore=null;
        if(observesStores()&&i.name().equals("STW")&&!actualMemory){
            var address=temp(4);var value=temp(4);b.op(PcodeOp.COPY,address,c(0,4));b.op(PcodeOp.COPY,value,c(0,4));traceStore=new StoreCapture(address,value);traceEvaluatedStores.put(pc,traceStore);
        }
        int traceStoreCount=0;
        Map<Integer,StoreTailWrite> tailCaptures=new HashMap<>();
        if(storeTailContract!=null&&i.store()&&!actualMemory)for(var capture:storeTailWrites(i,0)){
            tailCaptures.put(capture.rawIndex(),capture);
            b.op(PcodeOp.COPY,capture.address(),c(0,4));
            b.op(PcodeOp.COPY,capture.value(),c(0,capture.value().getSize()));
            b.op(PcodeOp.COPY,capture.enabled(),c(0,1));
        }
        for(int n=0;n<raw.length;n++){
            b.label(prefix+n);
            var op=raw[n];
            int opcode=op.getOpcode();
            if(n==i.guard()){
                b.jump(PcodeOp.CBRANCH,prefix+raw.length,not(predicate));continue;
            }
            if(opcode==PcodeOp.LOAD&&!actualMemory){
                b.op(PcodeOp.COPY,mapper.apply(op.getOutput()),c(0,op.getOutput().getSize()));
                captureWrite(i,n,img,writes,written);continue;
            }
            if(opcode==PcodeOp.STORE&&!actualMemory){
                var tail=tailCaptures.get(n);
                if(tail!=null){b.op(PcodeOp.COPY,tail.address(),mapper.apply(op.getInput(1)));b.op(PcodeOp.COPY,tail.value(),mapper.apply(op.getInput(2)));b.op(PcodeOp.COPY,tail.enabled(),c(1,1));}
                if(traceStore!=null){if(++traceStoreCount!=1||op.getInput(1).getSize()!=4||op.getInput(2).getSize()!=4)throw fail("trace STW is not one scalar memory effect");b.op(PcodeOp.COPY,traceStore.address(),mapper.apply(op.getInput(1)));b.op(PcodeOp.COPY,traceStore.value(),mapper.apply(op.getInput(2)));}
                continue;
            }
            if(opcode==PcodeOp.BRANCHIND||opcode==PcodeOp.RETURN||opcode==PcodeOp.CALL||opcode==PcodeOp.CALLIND)continue;
            Varnode[] inputs=Arrays.stream(op.getInputs()).map(mapper).toArray(Varnode[]::new);
            Varnode output=op.getOutput()==null?null:mapper.apply(op.getOutput());
            if(opcode==PcodeOp.BRANCH||opcode==PcodeOp.CBRANCH){
                var target=op.getInput(0);
                if(target.isConstant())b.jump(opcode,prefix+(n+(int)target.getOffset()),opcode==PcodeOp.CBRANCH?inputs[1]:null);
                else if(opcode==PcodeOp.CBRANCH){
                    if(transferTaken!=null)b.op(PcodeOp.COPY,transferTaken,inputs[1]);
                    b.jump(opcode,prefix+raw.length,inputs[1]);
                }else{
                    if(transferTaken!=null)b.op(PcodeOp.COPY,transferTaken,c(1,1));
                    b.jump(PcodeOp.BRANCH,prefix+raw.length,null);
                }
                continue;
            }
            var out=op.getOutput();
            if(out!=null&&out.isRegister()&&flags.containsKey(out.getOffset())){
                // Keep the event bits, including already-set bits. Merging a
                // computed old|flags value at E4 would undo an intervening MVC.
                if(opcode!=PcodeOp.INT_OR)throw fail("unsupported sticky status update at "+i.instruction().getAddress());
                int other=op.getInput(0).isRegister()&&op.getInput(0).getOffset()==out.getOffset()?1:op.getInput(1).isRegister()&&op.getInput(1).getOffset()==out.getOffset()?0:-1;
                if(other<0)throw fail("sticky status update does not expose event flags");
                b.op(PcodeOp.INT_OR,flags.get(out.getOffset()),flags.get(out.getOffset()),inputs[other]);
            }
            b.op(opcode,output,inputs);
            captureWrite(i,n,img,writes,written);
        }
        b.label(prefix+raw.length);
        return new Eval(img,predicate,flags,transferTaken,Map.copyOf(writes),Map.copyOf(written));
    }

    // Snapshot the value at its raw write, before an aliased write can replace it.
    // The same raw address calculation is replayed from captured E1 inputs at E3.
    private void captureWrite(Insn instruction,int rawIndex,long image,Map<Integer,Varnode> writes,Map<Integer,Varnode> written){
        for(var d:instruction.outputs())if(d.sourceWrite()==rawIndex){b.op(PcodeOp.COPY,writes.get(rawIndex),im(image,d.valueOffset(),d.size()));b.op(PcodeOp.COPY,written.get(rawIndex),c(1,1));}
    }
    private Varnode outputValue(Eval eval,Dest destination){
        return destination.flags()?eval.flags().get(destination.offset()):destination.sourceWrite()>=0?eval.writes().get(destination.sourceWrite()):im(eval.image(),destination.valueOffset(),destination.size());
    }
    private Varnode outputSlot(long pc,int age,Dest destination){return slot(destination.sourceWrite()<0?"output":"output#"+destination.sourceWrite(),pc,age,destination.offset(),destination.size());}
    private Varnode writtenSlot(long pc,int age,Dest destination){return slot("written#"+destination.sourceWrite(),pc,age,0,1);}

    private void commit(Insn i,Eval eval,int phase)throws Exception{
        String end="commit"+b.labelCounter++;
        // BDEC writes only when its raw counter test actually takes the branch.
        b.jump(PcodeOp.CBRANCH,end,not(writesWhen(i,eval)));
        for(var d:i.outputs())if(d.phase()==phase){
            String skip="raw_write_"+b.labelCounter++;
            if(d.sourceWrite()>=0)b.jump(PcodeOp.CBRANCH,skip,not(eval.written().get(d.sourceWrite())));
            Varnode value=outputValue(eval,d);
            if (d.flags()) b.op(PcodeOp.INT_OR, arch(d.offset(),d.size()), arch(d.offset(),d.size()), value);
            else if(d.mask()==-1)b.op(PcodeOp.COPY, arch(d.offset(),d.size()), value);
            else{var keep=temp(d.size());var bits=temp(d.size());b.op(PcodeOp.INT_AND,keep,arch(d.offset(),d.size()),c(~d.mask(),d.size()));b.op(PcodeOp.INT_AND,bits,value,c(d.mask(),d.size()));b.op(PcodeOp.INT_OR,arch(d.offset(),d.size()),keep,bits);}
            if(d.sourceWrite()>=0)b.label(skip);
        }
        b.label(end);
    }

    private Varnode writesWhen(Insn instruction,Eval eval){
        return instruction.name().equals("BDEC")?eval.transferTaken():eval.predicate();
    }

    private Varnode not(Varnode v){
        var result=temp(1);
        b.op(PcodeOp.BOOL_NEGATE,result,v);
        return result;
    }

    private List<Long> e1Outputs(Insn i){
        List<Long> r=new ArrayList<>();
        for(var d:i.outputs())if(!d.flags()&&d.phase()==1)for(long off=d.offset()&~3L;off<d.offset()+d.size();off+=4)if(off<0x2000||off==program.getRegister("AMR").getAddress().getOffset())r.add(off);
        return List.copyOf(r);
    }

    private Set<Long> crossStallReads(List<Insn> packet){
        Set<Long> r=new HashSet<>();
        if(!crossPathStalls)return r;
        for(var i:packet){
            if(i.load()||i.store())continue;
            String mn=i.instruction().getMnemonicString();
            int side=mn.matches(".*\\.[LSDM]1.*")?0:mn.matches(".*\\.[LSDM]2.*")?1:-1;
            if(side<0)continue;
            int count=i.instruction().getNumOperands()-(i.name().equals("B")||i.name().equals("BNOP")?0:1);
            for(int k=0;k<count;k++){
                // Pair operands can expose an empty getOpObjects array while
                // getRegister identifies their full read port (3.8.4, 4.2.7--16).
                Set<Register> registers=new HashSet<>();var direct=i.instruction().getRegister(k);if(direct!=null)registers.add(direct);
                for(Object object:i.instruction().getOpObjects(k))if(object instanceof Register register)registers.add(register);
                for(var register:registers){long off=register.getAddress().getOffset();
                    if(off<0x2000&&((off>=0x1000)?1:0)!=side)for(long x=off;x<off+register.getMinimumByteSize();x+=4)r.add(x);
                }
            }
        }
        return r;
    }

    private boolean usesAmr(Insn instruction){
        if(!instruction.load()&&!instruction.store())return false;
        int operand=instruction.load()?0:1;
        for(Object object:instruction.instruction().getOpObjects(operand))if(object instanceof Register register&&register.getName().matches("[AB][4-7]"))return true;
        return false;
    }
    private boolean harmlessPredicates(Hazard hazard,Insn reader,State state){
        if(predicateTruth(reader,state.facts())==0)return true;
        if(hazard.pc()<0)return false;
        var writer=decodeKnown(hazard.pc());
        if(!hazard.predicateUnchanged())return false;
        if(predicateTruth(writer,state.facts())==0)return true;
        // 7.15.2 explicitly permits complementary predicates when their sampled
        // value is unchanged. Do not infer this after a predicate register write.
        return writer.predicate()!=null&&writer.predicate().equals(reader.predicate())&&writer.inverted()!=reader.inverted();
    }

    public Result compile()throws Exception{
        if(traceContract!=null||closedCall!=null||callerTail!=null||storeTailContract!=null)throw fail("trace compiler is not an ordinary function schedule");
        return compileInternal();
    }
    public Result compile(TaskMonitor monitor)throws Exception{
        this.monitor=Objects.requireNonNull(monitor);
        monitor.checkCancelled();
        return compile();
    }
    private Result compileInternal()throws Exception{
        for(String counter:List.of("ILC","RILC"))b.op(PcodeOp.COPY,new Varnode(program.getRegister("C6000_PIPE_"+counter).getAddress(),4),new Varnode(program.getRegister(counter).getAddress(),4));
        List<Hazard> incoming=List.of();
        if(!entryWrites.isEmpty()){
            // The preceding E1 packet is outside this function. Its writes are already
            // visible, but an X-path reader can still incur one pipeline-wide stall.
            incoming=List.of(new Hazard(-1,entryWrites));
            b.op(PcodeOp.COPY,slot("hazard",-1,0,0,1),c(1,1));
        }
        State start=new State(entry.getOffset(),0,List.of(),List.of(),incoming,null,PredicateFacts.unknown(),new ReturnFlow(NO_CALL,Map.of(program.getRegister("B3").getAddress().getOffset(),ENTRY_LINK)));
        state(start);
        int processed=0;
        while(processed<states.size()){
            monitor.checkCancelled();
            var iterator=states.entrySet().iterator();
            Map.Entry<State,Integer> selected=null;
            for(int k=0;k<=processed;k++)selected=iterator.next();
            State s=selected.getKey();
            int id=selected.getValue();
            b.label("node"+id);
            processed++;
            if(storeTailContract!=null&&s.pc()==POST_RETURN_IDLE_PC&&s.idle()==0){
                if(!s.flights().isEmpty()||!s.branches().isEmpty()||s.loop()!=null)throw fail("store-tail endpoint still has pending effects");
                b.jump(PcodeOp.BRANCH,"exit",null);continue;
            }
            if(closedCall!=null&&closedCall.stopPc()!=null&&s.pc()==closedCall.stopPc()&&s.idle()==0){closeClosedTrace(s);continue;}
            if(closedCall!=null&&s.idle()==0&&!closedPackets.contains(s.pc()))throw fail("closed-call entered undeclared packet");
            if(traceContract!=null&&s.pc()==traceContract.stopPc()&&s.idle()==0){closeTrace(s);continue;}
            if(callerPc(s.pc())&&s.idle()==0&&!traceContract.callerPackets().contains(s.pc()))throw fail("caller continuation entered an undeclared packet");
            LoopPlan loop=s.loop()==null?null:loopPlans.get(s.loop().start());
            boolean sourceFetch=loop!=null&&s.loop().time()<loop.cells().size();
            boolean fetch=loop==null||sourceFetch||postFetch(loop,s.loop());
            List<Insn> fetched=!fetch||s.idle()>0?List.of():sourceFetch?loop.cells().get(s.loop().time()).source():packet(s.pc());
            long fetchNext=fetched.isEmpty()?s.pc():sourceFetch?loop.cells().get(s.loop().time()).nextPc():after(fetched.get(fetched.size()-1));
            List<Insn> pack=loop==null?fetched:loopOperations(loop,s.loop(),fetched);
            Insn loopStart=null;
            for(var instruction:fetched)if(instruction.name().equals("SPLOOP")||instruction.name().equals("SPLOOPD")||instruction.name().equals("SPLOOPW")){
                if(loop!=null||loopStart!=null)throw fail("overlapping loop invocation requires a reload contract");
                if(instruction.predicate()!=null&&!instruction.name().equals("SPLOOPW"))throw fail("predicated loop start requires reload state");
                // SPRUFE8B 7.9.7: an ILC load in parallel with, or in the
                // three cycles before SPLOOP is not a normal counter read.
                if(instruction.name().equals("SPLOOP")){
                    long counter=program.getRegister("ILC").getAddress().getOffset();
                    for(var peer:fetched)if(peer.name().equals("MVC")&&peer.outputs().stream().anyMatch(d->d.offset()==counter))throw fail("ILC load too close to SPLOOP");
                    for(var flight:s.flights()){var old=decode(flight.pc());if(old.name().equals("MVC")&&old.outputs().stream().anyMatch(d->d.offset()==counter))throw fail("ILC load too close to SPLOOP");}
                }
                loopStart=instruction;planLoop(instruction);
            }
            Varnode whileSample=null;
            if(loop!=null&&loop.kind().equals("SPLOOPW")&&!s.loop().abrupt()){
                var instruction=decode(loop.start());whileSample=temp(1);b.op(instruction.inverted()?PcodeOp.INT_EQUAL:PcodeOp.INT_NOTEQUAL,whileSample,arch(instruction.predicate().getAddress().getOffset(),4),c(0,4));
            }
            Varnode counterBefore=temp(4);b.op(PcodeOp.COPY,counterBefore,ilc());
            Varnode ilcBefore=null;if(loopStart!=null&&loopStart.name().equals("SPLOOP")){ilcBefore=temp(4);b.op(PcodeOp.COPY,ilcBefore,ilc());}
            int fetchSpan=1;for(var instruction:fetched)fetchSpan=Math.max(fetchSpan,instruction.span());
            if(sourceFetch)fetchSpan=1;
            validateNopGenerators(fetched);
            try{validateUnits(pack);}catch(IllegalArgumentException error){throw fail(error.getMessage()+" frame="+s.loop()+" pc="+Long.toHexString(s.pc()));}
            for(var flight:s.flights()){
                var old=decode(flight.pc());int latency=Set.of("ADDDP","SUBDP","CMPEQDP","CMPLTDP","CMPGTDP","MPYSP2DP").contains(old.name())?2:old.name().equals("MPYDP")?4:old.name().equals("MPYSPDP")?3:1;
                if(flight.age()<latency)for(var instruction:pack)if(unit(old)!=0&&unit(old)==unit(instruction))throw fail("functional unit still occupied by "+old.instruction());
            }
            if(!pack.isEmpty())packets++;
            Set<Long> fetchedPcs=new HashSet<>();for(var instruction:fetched)fetchedPcs.add(instruction.instruction().getAddress().getOffset());
            Set<Long> crosses=new HashSet<>();
            for(var instruction:fetched){Set<Long> ports=crossStallReads(List.of(instruction));for(var read:instruction.reads())if(read.first()>1)ports.remove(read.offset());crosses.addAll(ports);}
            for(var flight:s.flights()){
                var instruction=decode(flight.pc());Set<Long> ports=crossStallReads(List.of(instruction));
                for(var read:instruction.reads())if((read.phases()&(1<<flight.age()))!=0&&ports.contains(read.offset())){
                    boolean buffered=false;
                    for(var candidate:loopPlans.values())for(int k=0;k<candidate.cells().size();k++)for(var old:candidate.cells().get(k).buffered())if(old.instruction().getAddress().getOffset()==flight.pc())buffered=loop==null||candidate!=loop||s.loop().time()-flight.age()!=k;
                    if(buffered){for(var hazard:s.hazards())if(hazard.registers().contains(read.offset())&&flight.predicateTruth()!=0){
                        // This reader sampled its predicate in an earlier E1;
                        // current facts/complementarity do not describe it.
                        boolean disabled=hazard.pc()>=0&&hazard.predicateUnchanged()&&predicateTruth(decodeKnown(hazard.pc()),s.facts())==0;
                        if(!disabled)throw fail("buffered late port may require a missed X-path stall (LBX/MSX): "+instruction.instruction());
                    }}
                    else crosses.add(read.offset());
                }
            }
            // SPRUFE8B 7.15.2, 7.16--17: PM instructions retain automatic
            // stalls, but a required stall for a buffer instruction is LBX/MSX,
            // not permission to insert a global cycle. Refuse possible missed
            // stalls rather than approximate exception state.
            long amr=program.getRegister("AMR").getAddress().getOffset();
            for(var instruction:pack){
                boolean amrRead=usesAmr(instruction);Set<Long> ports=crossStallReads(List.of(instruction));
                for(var read:instruction.reads())if(read.first()>1)ports.remove(read.offset());
                if(fetchedPcs.contains(instruction.instruction().getAddress().getOffset())){if(amrRead)crosses.add(amr);continue;}
                for(var hazard:s.hazards())if((amrRead&&hazard.registers().contains(amr)||hazard.registers().stream().anyMatch(ports::contains))&&!harmlessPredicates(hazard,instruction,s))throw fail("buffered instruction may require a missed X-path/AMR stall (LBX/MSX): "+instruction.instruction());
            }
            Varnode stall=null;
            for(var h:s.hazards())if(h.registers().stream().anyMatch(crosses::contains)){
                var v=slot("hazard",h.pc(),0,0,1);
                if(stall==null)stall=v;
                else{
                    var sum=temp(1);
                    b.op(PcodeOp.BOOL_OR,sum,stall,v);
                    stall=sum;
                }
            }
            if(stall!=null){
                String target="node"+state(new State(s.pc(),s.idle(),s.flights(),s.branches(),List.of(),s.loop(),s.facts(),s.returns()));
                stallLabels.put(b.code.size(),target);
                b.jump(PcodeOp.CBRANCH,target,stall);
            }
            cycleStarts.put(b.code.size(),s.pc());
            b.op(PcodeOp.COPY,temp(1),c(0,1));
            // removable trace anchor, no architectural effect
            Map<Long,Eval> issued=new LinkedHashMap<>();
            Map<Long,Map<Long,Varnode>> captured=new LinkedHashMap<>();
            Insn issueBranch=null;
            int span=1;
            for(var i:pack){
                long pc=i.instruction().getAddress().getOffset();
                Map<Long,Varnode> input=new LinkedHashMap<>();
                for(long off:i.regs()){
                    var value=temp(4);
                    b.op(PcodeOp.COPY,value,arch(off,4));
                    input.put(off,value);
                }
                captured.put(pc,input);
                Eval e;
                if(i.ready()==1)e=evaluate(i,null,false,Map.of());
                else{var pred=temp(1);if(i.predicate()==null)b.op(PcodeOp.COPY,pred,c(1,1));else b.op(i.inverted()?PcodeOp.INT_EQUAL:PcodeOp.INT_NOTEQUAL,pred,arch(i.predicate().getAddress().getOffset(),4),c(0,4));e=new Eval(0,pred,Map.of(),null);}
                issued.put(pc,e);
                span=Math.max(span,i.span());
                if(Set.of("B","BNOP","BDEC","BPOS","CALLP").contains(i.name())){
                    if(issueBranch!=null)throw fail("multiple branches in a packet");
                    if(i.name().equals("CALLP")&&(!s.branches().isEmpty()||s.returns().activeCall()!=NO_CALL||loop!=null))throw fail("CALLP requires no pending branch or nested invocation");
                    issueBranch=i;
                }
            }
            // Capture late ports before any writeback in this cycle. A repeated port
            // read requires a stable word across its documented read window; reject
            // a potential intervening writer rather than choosing an arbitrary sample.
            Map<Flight,Map<Long,Varnode>> lateInputs=new LinkedHashMap<>();
            for(var f:s.flights()){
                var i=decode(f.pc());Map<Long,Varnode> late=new LinkedHashMap<>();
                for(var read:i.reads())if(read.first()==f.age()+1){var value=temp(4);b.op(PcodeOp.COPY,value,arch(read.offset(),4));late.put(read.offset(),value);}
                lateInputs.put(f,late);
            }
            List<Dest> writesThisCycle=new ArrayList<>();
            for(var i:pack)for(var d:i.outputs())if(d.phase()==1)writesThisCycle.add(d);
            for(var f:s.flights())for(var d:decode(f.pc()).outputs())if(d.phase()==f.age()+1)writesThisCycle.add(d);
            for(var i:pack)if(i.name().equals("CALLP")){long link=callLinkRegister(i).getAddress().getOffset();if(writesThisCycle.stream().filter(d->d.offset()<link+4&&link<d.offset()+d.size()).count()>1)throw fail("CALLP link has a potential simultaneous E1 writer");}
            validateMemoryWriteCollisions(s,pack);
            validateMpyliWritePorts(s,pack);
            for(var i:pack)checkStable(i,1,writesThisCycle);
            for(var f:s.flights())checkStable(decode(f.pc()),f.age()+1,writesThisCycle);
            Map<Flight,Eval> mature=new LinkedHashMap<>();
            for(var f:s.flights()){
                var i=decode(f.pc());if(i.load()&&f.age()==2||!i.load()&&!i.store()&&i.ready()>1&&f.age()==i.ready()-1)
                    mature.put(f,evaluate(i,f.age(),true,lateInputs.get(f)));
            }
            for(var f:s.flights())if(f.age()==2&&decode(f.pc()).store())mature.put(f,evaluate(decode(f.pc()),f.age(),true,lateInputs.get(f)));
            for(var f:s.flights()){
                var i=decode(f.pc());int phase=f.age()+1;
                if(i.outputs().stream().noneMatch(d->d.phase()==phase))continue;
                var e=mature.get(f);
                if(e==null){Map<Long,Varnode> flags=new LinkedHashMap<>();Map<Integer,Varnode> writes=new LinkedHashMap<>(),written=new LinkedHashMap<>();long img=image();for(var d:i.outputs())if(d.phase()==phase){var value=outputSlot(f.pc(),f.age(),d);if(d.flags())flags.put(d.offset(),value);else if(d.sourceWrite()>=0){writes.put(d.sourceWrite(),value);written.put(d.sourceWrite(),writtenSlot(f.pc(),f.age(),d));}else b.op(PcodeOp.COPY,im(img,d.valueOffset(),d.size()),value);}e=new Eval(img,slot("predicate",f.pc(),f.age(),0,1),flags,null,Map.copyOf(writes),Map.copyOf(written));}
                commit(i,e,phase);
            }
            for(var i:pack)if(i.outputs().stream().anyMatch(d->d.phase()==1))commit(i,issued.get(i.instruction().getAddress().getOffset()),1);
            List<Flight> nextFlights=new ArrayList<>();
            List<Runnable> moves=new ArrayList<>();
            for(var f:s.flights()){
                var i=decode(f.pc());
                if(f.age()>=i.latency()-1)continue;
                int age=f.age()+1;
                nextFlights.add(new Flight(f.pc(),age,f.predicateTruth()));
                copy(moves,slot("predicate",f.pc(),age,0,1),slot("predicate",f.pc(),f.age(),0,1));
                if(observesStores()&&i.name().equals("STW")){copy(moves,slot("store_address",f.pc(),age,0,4),slot("store_address",f.pc(),f.age(),0,4));copy(moves,slot("store_value",f.pc(),age,0,4),slot("store_value",f.pc(),f.age(),0,4));}
                if(storeTailContract!=null&&i.store())moveStoreTail(moves,i,f.age(),age);
                for(long off:i.regs())copy(moves,slot("input",f.pc(),age,off,4),lateInputs.get(f).getOrDefault(off,slot("input",f.pc(),f.age(),off,4)));
                for(var d:i.outputs())if(d.phase()>age&&!i.store()&&f.age()>=(i.load()?3:i.ready())-1){
                    var e=mature.get(f);
                    Varnode from=e==null?outputSlot(f.pc(),f.age(),d):outputValue(e,d);
                    copy(moves,outputSlot(f.pc(),age,d),from);
                    if(d.sourceWrite()>=0)copy(moves,writtenSlot(f.pc(),age,d),e==null?writtenSlot(f.pc(),f.age(),d):e.written().get(d.sourceWrite()));
                }
            }
            List<Hazard> hazards=new ArrayList<>();
            for(var i:pack){
                long pc=i.instruction().getAddress().getOffset();
                var e=issued.get(pc);
                var writes=e1Outputs(i);
                if(!writes.isEmpty()){
                    // The next packet must know whether this writer's E1
                    // predicate sample still denotes the same value. Include
                    // ALL writes at this commit, even a final-phase flight
                    // that disappears from nextFlights (3.5, 7.15.2).
                    long predicate=i.predicate()==null?-1:i.predicate().getAddress().getOffset();
                    boolean unchanged=predicate<0||writesThisCycle.stream().noneMatch(d->d.offset()<predicate+4&&predicate<d.offset()+d.size());
                    hazards.add(new Hazard(pc,writes,unchanged));
                    copy(moves,slot("hazard",pc,0,0,1),writesWhen(i,e));
                }
                if(i.latency()>1){
                    nextFlights.add(new Flight(pc,1,-1));
                    copy(moves,slot("predicate",pc,1,0,1),e.predicate());
                    if(observesStores()&&i.name().equals("STW")){var store=traceEvaluatedStores.get(pc);if(store==null)throw fail("trace STW capture missing");copy(moves,slot("store_address",pc,1,0,4),store.address());copy(moves,slot("store_value",pc,1,0,4),store.value());}
                    if(storeTailContract!=null&&i.store())moveStoreTail(moves,i,0,1);
                    for(var v:captured.get(pc).entrySet())copy(moves,slot("input",pc,1,v.getKey(),4),v.getValue());
                    if(!i.load()&&!i.store()&&i.ready()==1)for(var d:i.outputs())if(d.phase()>1)copy(moves,outputSlot(pc,1,d),outputValue(e,d));
                }
            }
            long nextPc=fetchNext;
            int idle=s.idle()>0?s.idle()-1:fetchSpan-1;
            Branch landing=null;
            List<Branch> nextBranches=new ArrayList<>();
            for(var branch:s.branches()){
                if(branch.age()==5){
                    if(landing!=null)throw fail("simultaneous branch landings");
                    landing=branch;
                }
                else{
                    nextBranches.add(new Branch(branch.pc(),branch.age()+1,branch.target(),branch.returns()));
                    if(branch.returns())copy(moves,slot("target",branch.pc(),branch.age()+1,0,4),slot("target",branch.pc(),branch.age(),0,4));
                    if(closedCall!=null&&closedCalls.containsKey(branch.pc()))copy(moves,slot("call_target",branch.pc(),branch.age()+1,0,4),slot("call_target",branch.pc(),branch.age(),0,4));
                }
            }
            for(var move:moves)move.run();
            ReturnFlow returnFlow=advanceReturnFlow(s,pack);
            if(landing!=null){
                idle=0;
                if(landing.returns()){
                    if(s.returns().activeCall()!=NO_CALL){
                        if(loop!=null||!nextBranches.isEmpty()||issueBranch!=null)throw fail("closed-call callee return has unresolved control effects");
                        long site=s.returns().activeCall();var plan=closedCalls.get(site);
                        if(plan!=null){if(landing.pc()!=plan.calleeReturnPc())throw fail("closed-call undeclared callee return");closedBoundary("CALL_RETURN",landing,nextFlights,hazards,plan);nextPc=plan.continuation();}
                        else nextPc=callpContinuation(decode(site));
                        returnFlow=new ReturnFlow(NO_CALL,returnFlow.links());
                    }
                    else if(traceContract!=null)nextPc=continueReturn(landing,nextFlights,nextBranches,issueBranch,loop);
                    else if(storeTailContract!=null){storeTailReturn(s,landing,nextFlights,nextBranches,issueBranch,loop,hazards);continue;}
                    else {
                        if(!nextFlights.isEmpty()||!nextBranches.isEmpty()||issueBranch!=null)throw fail("return leaves architectural pipeline effects pending; source="+s+"; next="+nextFlights);
                        if(closedCall!=null){if(!Objects.equals(landing.pc(),closedCall.callerReturnPc()))throw fail("closed-call undeclared return");closedBoundary("CALLER_RETURN",landing,nextFlights,hazards,closedCall);var writes=closedHazards(hazards);if(closedExitWrites!=null&&!closedExitWrites.equals(writes))throw fail("closed-call incompatible return hazards");closedExitWrites=writes;}
                        b.op(PcodeOp.COPY,new Varnode(program.getRegister("C6000_PIPE_RET").getAddress(),4),slot("target",landing.pc(),landing.age(),0,4));
                        if(loop!=null){var tsr=program.getRegister("TSR");b.op(PcodeOp.INT_AND,new Varnode(tsr.getAddress(),4),new Varnode(tsr.getAddress(),4),c(0xffffbfffL,4));}
                        b.jump(PcodeOp.BRANCH,"exit",null);continue;
                    }
                } else {
                    var plan=closedCalls.get(landing.pc());boolean call=plan!=null||decode(landing.pc()).name().equals("CALLP");
                    if(call){
                        if(s.returns().activeCall()!=NO_CALL)throw fail("nested closed call requires a call-stack contract");
                        if(plan!=null)closedBoundary("CALL_ENTER",landing,nextFlights,hazards,plan);
                        var links=new HashMap<>(returnFlow.links());if(plan!=null&&!decode(landing.pc()).name().equals("CALLP"))links.put(callLinkRegister(decode(landing.pc())).getAddress().getOffset(),landing.pc());returnFlow=new ReturnFlow(landing.pc(),Map.copyOf(links));
                    }else if(closedCall!=null&&!closedInternalBranches.contains(landing.pc()))throw fail("closed-call undeclared direct landing");
                    nextPc=landing.target();
                }
            }
            // SPRUFE8B 7.14: a taken branch idles a non-reloading buffer
            // after its five delay slots. Effects already issued still mature.
            boolean loopRedirect=landing!=null;
            LoopFrame normal=null,stopped=null;Varnode loopTest=null;boolean decrementOnContinue=true;long stoppedPc=nextPc;
            if(loopStart!=null){long startPc=loopStart.instruction().getAddress().getOffset();normal=new LoopFrame(startPc,0,-1,false,false,false);
                if(loopStart.name().equals("SPLOOP")){loopTest=ilcBefore;stopped=new LoopFrame(startPc,0,0,true,false,false);}
                if(loopStart.name().equals("SPLOOPW"))for(int age=0;age<3;age++)b.op(PcodeOp.COPY,slot("while_condition",startPc,age,0,1),c(0,1));
            }else if(loop!=null&&!loopRedirect){
                int time=loopNextTime(loop,s.loop().time());int drain=s.loop().drain()<0?-1:s.loop().drain()+1;
                normal=loopFinished(loop,s.loop())?null:new LoopFrame(loop.start(),time,drain,s.loop().zero(),s.loop().refill()||s.loop().drain()<0&&s.loop().time()>=loop.cells().size()-1,s.loop().abrupt());
                if(!loop.kind().equals("SPLOOPW")&&s.loop().drain()<0&&(s.loop().time()+1)%loop.ii()==0&&(loop.kind().equals("SPLOOP")||s.loop().time()>=3)){
                    loopTest=counterBefore;stopped=new LoopFrame(loop.start(),time,1,false,s.loop().refill(),false);
                    if(loopFinished(loop,new LoopFrame(loop.start(),s.loop().time(),0,false,s.loop().refill(),false)))stopped=null;
                }
            }
            if(loop!=null&&!loopRedirect&&loop.kind().equals("SPLOOPW")&&!s.loop().abrupt()){
                // SPRUFE8B 7.10.2: sample the register visible before E1, three advances ago.
                var oldest=temp(1);b.op(PcodeOp.COPY,oldest,slot("while_condition",loop.start(),2,0,1));
                var one=temp(1);var two=temp(1);b.op(PcodeOp.COPY,one,slot("while_condition",loop.start(),0,0,1));b.op(PcodeOp.COPY,two,slot("while_condition",loop.start(),1,0,1));
                b.op(PcodeOp.COPY,slot("while_condition",loop.start(),0,0,1),whileSample);
                b.op(PcodeOp.COPY,slot("while_condition",loop.start(),1,0,1),one);b.op(PcodeOp.COPY,slot("while_condition",loop.start(),2,0,1),two);
                // Section 7.10 expressly says ILC/RILC are neither read nor modified.
                if((s.loop().time()+1)%loop.ii()==0&&s.loop().time()>=3){loopTest=oldest;decrementOnContinue=false;stopped=s.loop().refill()||s.loop().time()<loop.cells().size()-1?new LoopFrame(loop.start(),loopNextTime(loop,s.loop().time()),1,false,s.loop().refill(),true):null;stoppedPc=sourceFetch?nextPc:loop.postPc();}
            }
            if(loopRedirect){normal=null;stopped=null;}
            if(loopTest!=null&&provedLoadingContinue(loop,s.loop(),loopStart)){
                // Proven positive ILC removes only the impossible stop edge. Keep
                // the exact decrement, and retain every post-loading/refill state.
                if(decrementOnContinue){b.op(PcodeOp.INT_SUB,ilc(),loopTest,c(1,4));b.op(PcodeOp.COPY,new Varnode(program.getRegister("ILC").getAddress(),4),ilc());}
                emitTransfer(s,returnFlow,pack,nextPc,idle,nextFlights,nextBranches,hazards,normal,issueBranch,captured,issued,loop!=null||loopStart!=null,loop!=null&&bufferFinished(loop,s.loop()));
            }else if(loopTest!=null){
                String stop="loop_stop_"+b.labelCounter++;var zero=temp(1);b.op(PcodeOp.INT_EQUAL,zero,loopTest,c(0,loopTest.getSize()));b.jump(PcodeOp.CBRANCH,stop,zero);if(decrementOnContinue){b.op(PcodeOp.INT_SUB,ilc(),loopTest,c(1,4));b.op(PcodeOp.COPY,new Varnode(program.getRegister("ILC").getAddress(),4),ilc());}
                emitTransfer(s,returnFlow,pack,nextPc,idle,nextFlights,nextBranches,hazards,normal,issueBranch,captured,issued,loop!=null||loopStart!=null,loop!=null&&bufferFinished(loop,s.loop()));
                b.label(stop);emitTransfer(s,returnFlow,pack,stoppedPc,idle,nextFlights,nextBranches,hazards,stopped,issueBranch,captured,issued,loop!=null||loopStart!=null,loop!=null&&bufferFinished(loop,s.loop()));
            }else emitTransfer(s,returnFlow,pack,nextPc,idle,nextFlights,nextBranches,hazards,normal,issueBranch,captured,issued,loop!=null||loopStart!=null,loop!=null&&bufferFinished(loop,s.loop()));

        }
        b.label("exit");
        b.op(PcodeOp.RETURN,null,new Varnode(program.getRegister("C6000_PIPE_RET").getAddress(),4));
        var code=b.finish();
        Map<Integer,Integer> stalls=new LinkedHashMap<>();
        for(var e:stallLabels.entrySet())stalls.put(e.getKey(),b.labels.get(e.getValue()));
        return new Result(code,states.size(),packets,covered,Map.copyOf(cycleStarts),Map.copyOf(stalls));
    }

    private Varnode ilc(){return new Varnode(program.getRegister("C6000_PIPE_ILC").getAddress(),4);}

    private void emitTransfer(State source,ReturnFlow returnFlow,List<Insn> pack,long pc,int idle,List<Flight> flights,List<Branch> branches,List<Hazard> hazards,LoopFrame loop,Insn issueBranch,Map<Long,Map<Long,Varnode>> captured,Map<Long,Eval> issued,boolean updateLoopStatus,boolean finishedCurrentBuffer){
        if(updateLoopStatus){var tsr=new Varnode(program.getRegister("TSR").getAddress(),4);boolean active=loop!=null&&!loop.abrupt()&&!finishedCurrentBuffer;b.op(active?PcodeOp.INT_OR:PcodeOp.INT_AND,tsr,tsr,c(active?0x4000:0xffffbfffL,4));}
        if(issueBranch==null){emitFactTransfer(source,returnFlow,pack,pc,idle,flights,branches,hazards,loop,source.facts());return;}
        var instruction=issueBranch.instruction();long at=instruction.getAddress().getOffset();var register=instruction.getRegister(0);var plan=closedCalls.get(at);boolean call=plan!=null||issueBranch.name().equals("CALLP");
        Long origin=register==null?null:source.returns().links().get(register.getAddress().getOffset());
        boolean returns=!call&&register!=null&&(source.returns().activeCall()!=NO_CALL?origin!=null&&origin==source.returns().activeCall():origin!=null&&origin==ENTRY_LINK||register.getName().equals("B3"));
        if(closedCall!=null&&!call&&register!=null){var active=closedCalls.get(source.returns().activeCall());if(active!=null&&at!=active.calleeReturnPc()||active==null&&!Objects.equals(at,closedCall.callerReturnPc()))throw fail("closed-call undeclared register edge");}
        if(register!=null&&!returns&&!call)throw fail("unresolved register branch "+instruction);
        long target=plan!=null?plan.callee().start():returns?0:instruction.getAddress(0).getOffset();
        if(call)b.op(PcodeOp.COPY,slot("call_target",at,1,0,4),register==null?c(target,4):captured.get(at).get(register.getAddress().getOffset()));
        if(callerTail!=null&&!returns){if(!callerTail.callee().contains(target))throw fail("caller-tail callee branch leaves declared scope");validateCallerTailTarget(target);}
        if(returns)b.op(PcodeOp.COPY,slot("target",at,1,0,4),captured.get(at).get(register.getAddress().getOffset()));
        List<Branch> yes=new ArrayList<>(branches);yes.add(new Branch(at,1,target,returns));
        if(Set.of("BDEC","BPOS").contains(issueBranch.name())) {
            // A failed counter test says nothing about the instruction predicate.
            // Preserve raw transfer truth and leave these fact partitions broad.
            String no="counter_not_taken_"+b.labelCounter++;
            b.jump(PcodeOp.CBRANCH,no,invert(issued.get(at).transferTaken()));
            emitFactTransfer(source,returnFlow,pack,pc,idle,flights,yes,hazards,loop,source.facts());
            b.label(no);emitFactTransfer(source,returnFlow,pack,pc,idle,flights,branches,hazards,loop,source.facts());
            return;
        }
        if(issueBranch.predicate()==null){emitFactTransfer(source,returnFlow,pack,pc,idle,flights,yes,hazards,loop,source.facts());return;}
        int index=Set.of("B","BNOP").contains(issueBranch.name())?predicateIndex(issueBranch.predicate().getAddress().getOffset()):-1;
        // Fork the E1 snapshot before evaluating any same-packet writes. A copied
        // old predicate and a changed predicate must never be conflated here.
        PredicateFacts taken=index<0?source.facts():source.facts().constrain(index,issueBranch.inverted()?0:1);
        PredicateFacts skipped=index<0?source.facts():source.facts().constrain(index,issueBranch.inverted()?1:0);
        if(taken==null){emitFactTransfer(source,returnFlow,pack,pc,idle,flights,branches,hazards,loop,skipped);return;}
        if(skipped==null){emitFactTransfer(source,returnFlow,pack,pc,idle,flights,yes,hazards,loop,taken);return;}
        String no="predicate_not_taken_"+b.labelCounter++;b.jump(PcodeOp.CBRANCH,no,invert(issued.get(at).predicate()));
        emitFactTransfer(source,returnFlow,pack,pc,idle,flights,yes,hazards,loop,taken);b.label(no);
        emitFactTransfer(source,returnFlow,pack,pc,idle,flights,branches,hazards,loop,skipped);
    }

    private long callpContinuation(Insn call){
        var link=callLinkRegister(call);Long value=C6000LoopCounterProof.constantOutput(program.getLanguage(),call.raw(),link.getAddress().getOffset(),4);
        if(value==null)throw fail("CALLP lacks exact E1 link proof");return value&0xffffffffL;
    }
    private ReturnFlow advanceReturnFlow(State source,List<Insn> pack){
        var before=source.returns().links();var after=new HashMap<>(before);var written=new HashSet<Long>();
        for(var flight:source.flights())if(flight.predicateTruth()!=0){var instruction=decodeKnown(flight.pc());for(var d:instruction.outputs())if(d.phase()==flight.age()+1)forgetReturnOutput(after,written,d,null,false);}
        for(var instruction:pack){int truth=predicateTruth(instruction,source.facts());if(truth==0)continue;var copied=copiedSource(instruction);Long origin=copied==null?null:before.get(copied.getAddress().getOffset());if(instruction.name().equals("CALLP"))origin=instruction.instruction().getAddress().getOffset();
            for(var d:instruction.outputs())if(d.phase()==1){Long value=d.size()==4&&d.mask()==-1&&d.sourceWrite()<0?origin:null;if(truth<0&&!Objects.equals(before.get(d.offset()),value))value=null;forgetReturnOutput(after,written,d,value,true);}
        }
        return new ReturnFlow(source.returns().activeCall(),Map.copyOf(after));
    }
    private void forgetReturnOutput(Map<Long,Long> links,Set<Long> written,Dest output,Long value,boolean exact){
        for(String bank:List.of("A","B"))for(int k=0;k<32;k++){long offset=program.getRegister(bank+k).getAddress().getOffset();if(output.offset()>=offset+4||offset>=output.offset()+output.size())continue;
            if(!written.add(offset)||!exact||output.offset()!=offset||output.size()!=4||value==null)links.remove(offset);else links.put(offset,value);
        }
    }

    private Varnode invert(Varnode value){var inverted=temp(1);b.op(PcodeOp.BOOL_NEGATE,inverted,value);return inverted;}
    private int predicateIndex(long offset){for(int k=0;k<6;k++){String name=(k<3?"A":"B")+(k%3);if(program.getRegister(name).getAddress().getOffset()==offset)return k;}return -1;}
    private int predicateTruth(Insn instruction,PredicateFacts facts){
        if(instruction.predicate()==null)return 1;int index=predicateIndex(instruction.predicate().getAddress().getOffset());
        if(index<0)return -1;int truth=facts.values().get(index).truth();return truth<0?-1:instruction.inverted()?1-truth:truth;
    }
    private Register copiedSource(Insn instruction){
        var ins=instruction.instruction();int n=ins.getNumOperands();
        if(instruction.name().equals("MV")&&n==2)return ins.getRegister(0);
        if(Set.of("ADD","OR").contains(instruction.name())&&n==3)for(int zero=0;zero<2;zero++){var scalar=ins.getScalar(zero);if(scalar!=null&&scalar.getValue()==0)return ins.getRegister(1-zero);}
        return null;
    }
    private PredicateValue outputFact(Insn instruction,PredicateFacts facts,int token){
        var ins=instruction.instruction();var copied=copiedSource(instruction);
        if(copied!=null&&copied.getMinimumByteSize()==4){int index=predicateIndex(copied.getAddress().getOffset());if(index>=0)return facts.values().get(index);}
        if(instruction.name().equals("ZERO"))return new PredicateValue(token,0);
        if(instruction.name().equals("SUB")&&ins.getNumOperands()==3&&ins.getRegister(0)!=null&&ins.getRegister(0).equals(ins.getRegister(1)))return new PredicateValue(token,0);
        if(Set.of("MVK","MVKL").contains(instruction.name())){var value=ins.getScalar(0);if(value!=null)return new PredicateValue(token,value.getValue()==0?0:1);}
        return new PredicateValue(token,-1);
    }
    private PredicateFacts advanceFacts(State source,List<Insn> pack,PredicateFacts before){
        var after=new ArrayList<>(before.values());Set<Integer> written=new HashSet<>();int token=6;
        for(var flight:source.flights()){
            Insn instruction=instructions.get(flight.pc());if(flight.predicateTruth()==0)continue;
            for(var destination:instruction.outputs())if(destination.phase()==flight.age()+1&&!destination.flags())for(int index=0;index<6;index++){
                long offset=program.getRegister((index<3?"A":"B")+(index%3)).getAddress().getOffset();
                if(offset<destination.offset()+destination.size()&&destination.offset()<offset+4){after.set(index,new PredicateValue(token++,-1));written.add(index);}
            }
        }
        for(var instruction:pack){int truth=predicateTruth(instruction,before);if(truth==0)continue;
            for(var destination:instruction.outputs())if(destination.phase()==1&&!destination.flags())for(int index=0;index<6;index++){
                long offset=program.getRegister((index<3?"A":"B")+(index%3)).getAddress().getOffset();
                if(offset>=destination.offset()+destination.size()||destination.offset()>=offset+4)continue;
                var value=destination.sourceWrite()<0&&destination.size()==4&&destination.offset()==offset&&destination.mask()==-1?outputFact(instruction,before,token++):new PredicateValue(token++,-1);
                if(written.contains(index)||truth<0&&!value.equals(before.values().get(index)))value=new PredicateValue(token++,-1);
                after.set(index,value);written.add(index);
            }
        }
        return new PredicateFacts(List.copyOf(after));
    }
    private void emitFactTransfer(State source,ReturnFlow returnFlow,List<Insn> pack,long pc,int idle,List<Flight> flights,List<Branch> branches,List<Hazard> hazards,LoopFrame loop,PredicateFacts before){
        var facts=advanceFacts(source,pack,before);
        List<Flight> captured=new ArrayList<>();for(var flight:flights){var instruction=instructions.get(flight.pc());boolean fresh=flight.age()==1&&pack.contains(instruction);captured.add(new Flight(flight.pc(),flight.age(),fresh?predicateTruth(instruction,before):flight.predicateTruth()));}
        // A backward redirect or buffered time wrap must not turn an entry fact
        // into a loop invariant. Widen to independent unknown values there.
        if(pc<source.pc()||loop!=null&&source.loop()!=null&&loop.time()<source.loop().time())facts=PredicateFacts.unknown();
        State target=new State(pc,idle,List.copyOf(captured),List.copyOf(branches),List.copyOf(hazards),loop,facts.canonical(),returnFlow);
        b.jump(PcodeOp.BRANCH,"node"+state(target),null);
    }

    private record MultiplyPortWrite(int owner,Insn instruction,int age) {}
    private void validateMpyliWritePorts(State state,List<Insn> packet){
        var writes=new ArrayList<MultiplyPortWrite>();int owner=0;
        for(var instruction:packet){if(predicateTruth(instruction,state.facts())!=0&&instruction.outputs().stream().anyMatch(d->d.phase()==1&&!d.flags()&&d.offset()<0x2000))writes.add(new MultiplyPortWrite(owner,instruction,0));owner++;}
        for(var flight:state.flights()){var instruction=decodeKnown(flight.pc());if(flight.predicateTruth()!=0&&instruction.outputs().stream().anyMatch(d->d.phase()==flight.age()+1&&!d.flags()&&d.offset()<0x2000))writes.add(new MultiplyPortWrite(owner,instruction,flight.age()));owner++;}
        // SPRUFE8B 3.8.2: a 64-bit .M result uses both register write ports.
        for(var left:writes)if(left.instruction().name().equals("MPYLI"))for(var right:writes){
            if(left.owner()==right.owner()||unit(left.instruction())!=unit(right.instruction()))continue;
            if(left.age()==right.age()&&left.instruction().predicate()!=null&&left.instruction().predicate().equals(right.instruction().predicate())&&left.instruction().inverted()!=right.instruction().inverted())continue;
            throw fail("MPYLI result write-port conflict with "+right.instruction().instruction());
        }
    }

    private record WriteEvent(int owner,Insn instruction,Dest destination,int truth,boolean fresh) {}
    private void validateMemoryWriteCollisions(State state,List<Insn> packet){
        var events=new ArrayList<WriteEvent>();int owner=0;
        for(var instruction:packet){int truth=predicateTruth(instruction,state.facts());for(var d:instruction.outputs())if(d.phase()==1&&!d.flags()&&truth!=0)events.add(new WriteEvent(owner,instruction,d,truth,true));owner++;}
        for(var flight:state.flights()){var instruction=decodeKnown(flight.pc());for(var d:instruction.outputs())if(d.phase()==flight.age()+1&&!d.flags()&&flight.predicateTruth()!=0)events.add(new WriteEvent(owner,instruction,d,flight.predicateTruth(),false));owner++;}
        for(int x=0;x<events.size();x++)for(int y=x+1;y<events.size();y++){
            var left=events.get(x);var right=events.get(y);if(left.owner()==right.owner())continue;
            if(left.destination().sourceWrite()<0&&right.destination().sourceWrite()<0)continue;
            var a=left.destination();var b=right.destination();if(a.offset()>=b.offset()+b.size()||b.offset()>=a.offset()+a.size())continue;
            if(left.fresh()&&right.fresh()&&left.instruction().predicate()!=null&&left.instruction().predicate().equals(right.instruction().predicate())&&left.instruction().inverted()!=right.instruction().inverted())continue;
            throw fail("potential simultaneous memory/register writes between "+left.instruction().instruction()+" and "+right.instruction().instruction());
        }
    }
    private Insn decodeKnown(long pc){var instruction=instructions.get(pc);if(instruction==null)throw fail("missing in-flight instruction");return instruction;}

    private void validateNopGenerators(List<Insn> fetched){
        // Buffered NOP spans have already become individual loop cells. Only
        // program-memory instructions can initiate another frontend NOP span.
        Instruction generator=null;
        for(var instruction:fetched)if(C6000ExecutionPackets.startsMulticycleNop(instruction.instruction())) {
            if(generator!=null&&!C6000ExecutionPackets.sameMulticycleNop(generator,instruction.instruction()))throw fail("multiple multicycle NOP generators in execute packet");
            generator=instruction.instruction();
        }
    }

    private void validateUnits(List<Insn> packet){
        // SPRUFE8B BDEC/BPOS notes prohibit ADDKPC in the same execute packet.
        if(packet.stream().anyMatch(i->Set.of("BDEC","BPOS").contains(i.name()))&&
            packet.stream().anyMatch(i->i.name().equals("ADDKPC")))
            throw fail("BDEC/BPOS cannot share an execute packet with ADDKPC");
        // Section3.8.8 leaves simultaneous writes undefined. BDEC's conditional
        // E1 decrement must not acquire an invented priority over a companion.
        for(var branch:packet)if(branch.name().equals("BDEC")){
            Register counter=branch.instruction().getRegister(1);
            if(counter==null)throw fail("BDEC counter missing");
            long lo=counter.getAddress().getOffset(),hi=lo+counter.getMinimumByteSize();
            for(var other:packet)if(other!=branch&&other.outputs().stream().anyMatch(d->
                d.phase()==1&&!d.flags()&&d.offset()<hi&&lo<d.offset()+d.size())){
                if(branch.predicate()!=null&&branch.predicate().equals(other.predicate())&&
                    branch.inverted()!=other.inverted())continue;
                throw fail("BDEC counter has a potential simultaneous E1 writer");
            }
        }
        Map<Integer,Insn> used=new HashMap<>();
        for(var instruction:packet){int unit=unit(instruction);if(unit==0)continue;var prior=used.putIfAbsent(unit,instruction);if(prior==null)continue;
            if(prior.predicate()!=null&&prior.predicate().equals(instruction.predicate())&&prior.inverted()!=instruction.inverted())continue;
            throw fail("functional-unit collision between "+prior.instruction()+" and "+instruction.instruction());
        }
    }

    private int unit(Insn instruction){
        // Displacement BNOP has no functional unit (SPRUFE8B 7.7.3.3).
        if(instruction.name().equals("BNOP")&&instruction.instruction().getAddress(0)!=null)return 0;
        Matcher match=Pattern.compile("\\.([LSDM])([12])").matcher(instruction.instruction().getMnemonicString());
        if(!match.find())return 0;return 1<<("LSDM".indexOf(match.group(1))*2+Integer.parseInt(match.group(2))-1);
    }

    private LoopPlan planLoop(Insn start)throws Exception{
        long at=start.instruction().getAddress().getOffset();if(loopPlans.containsKey(at))return loopPlans.get(at);
        int ii=(int)start.instruction().getScalar(0).getValue();if(ii<1||ii>14)throw fail("invalid loop interval");
        List<Insn> entryPacket=packet(at);long pc=after(entryPacket.get(entryPacket.size()-1));List<LoopCell> cells=new ArrayList<>();boolean found=false;int fetchDelay=0;
        while(cells.size()<48){
            monitor.checkCancelled();
            List<Insn> instructions=packet(pc);int mask=0,duration=1;boolean kernel=false;
            for(var instruction:instructions){
                if(instruction.name().startsWith("SPLOOP"))throw fail("nested loop source without SPKERNEL");
                // Do not choose one implementation's ILC value during loading
                // (SPRUFE8B 7.9.7). SPLOOPW does not use the counter interface.
                if(!start.name().equals("SPLOOPW")&&instruction.name().equals("MVC")&&instruction.regs().contains(program.getRegister("ILC").getAddress().getOffset()))throw fail("ILC access inside counted loop body");
                if(instruction.name().equals("SPMASK"))mask|=(int)instruction.instruction().getScalar(0).getValue();
                if(instruction.name().equals("SPKERNEL")){
                    kernel=true;int raw=(int)instruction.instruction().getScalar(0).getValue();int bits=ii==1?0:ii==2?1:ii<=4?2:ii<=8?3:4;int cycle=raw&((1<<bits)-1),stage=0;
                    for(int bit=0;bit<6-bits;bit++)stage|=((raw>>>(5-bit))&1)<<bit;fetchDelay=stage*ii+cycle;
                }
                duration=Math.max(duration,instruction.span());
            }
            List<Insn> buffered=new ArrayList<>();for(var instruction:instructions)if(!Set.of("SPKERNEL","SPMASK").contains(instruction.name())&&(unit(instruction)&mask)==0&&!instruction.name().equals("BNOP")){
                if(Set.of("B","CALLP","MVC","ADDKPC").contains(instruction.name()))throw fail("unmasked control instruction in software loop buffer");buffered.add(instruction);
            }
            long next=after(instructions.get(instructions.size()-1));cells.add(new LoopCell(List.copyOf(instructions),List.copyOf(buffered),mask,next));for(int t=1;t<duration;t++)cells.add(new LoopCell(List.of(),List.of(),0,next));pc=next;
            if(kernel){found=true;break;}
        }
        if(!found||cells.size()>48)throw fail("loop source exceeds 48 dynamic cycles or lacks SPKERNEL");
        if(cells.size()<(start.name().equals("SPLOOPW")?ii:ii+1))throw fail("loop dynamic length below documented minimum");
        int cap=((Math.max(cells.size(),4)+ii-1)/ii)*ii;var plan=new LoopPlan(at,start.name(),ii,fetchDelay,cap,List.copyOf(cells),pc);loopPlans.put(at,plan);
        var proof=proveLoadingCount(start,plan);
        if(!proof.noLoadingExit())proof=proveLoadingSuffix(start,plan);
        loadingCountProofs.put(at,proof);return plan;
    }

    private List<C6000LoopCounterProof.Operation> proofOperations(List<Insn> packet){
        List<C6000LoopCounterProof.Operation> result=new ArrayList<>();
        for(var instruction:packet){
            List<C6000LoopCounterProof.Output> outputs=new ArrayList<>();
            for(var d:instruction.outputs())outputs.add(new C6000LoopCounterProof.Output(d.offset(),d.size(),d.valueOffset(),d.phase(),d.flags()||d.mask()!=-1||d.sourceWrite()>=0));
            result.add(new C6000LoopCounterProof.Operation(instruction.raw(),List.copyOf(outputs),instruction.predicate()==null?null:instruction.predicate().getAddress().getOffset(),instruction.inverted()));
        }
        return result;
    }

    private C6000LoopCounterProof.Proof proveLoadingCount(Insn start,LoopPlan plan){
        if(!Set.of("SPLOOP","SPLOOPD").contains(start.name())||start.predicate()!=null)return C6000LoopCounterProof.Proof.unknown("not an unconditional counted loop");
        var constants=new C6000LoopCounterProof(program.getLanguage());long pc=entry.getOffset();
        try{
            for(int packets=0;packets<256;packets++){
                var fetched=packet(pc);var first=fetched.get(0);boolean target=false;int span=1;
                for(var instruction:fetched){
                    span=Math.max(span,instruction.span());
                    if(instruction.instruction().getAddress().equals(start.instruction().getAddress()))target=true;
                    else if(instruction.instruction().getFlowType().isJump()||instruction.instruction().getFlowType().isCall()||instruction.instruction().getFlowType().isTerminal()||Set.of("B","BNOP","CALLP","SPLOOP","SPLOOPD","SPLOOPW","SPKERNEL","SPMASK").contains(instruction.name()))return C6000LoopCounterProof.Proof.unknown("prefix is not straight-line");
                }
                if(target){
                    if(first!=start||span!=1)return C6000LoopCounterProof.Proof.unknown("unsupported loop-start packet");
                    return constants.finish(start.name(),plan.ii(),plan.cells().size(),program.getRegister("C6000_PIPE_ILC").getAddress().getOffset(),proofOperations(fetched));
                }
                constants.packet(proofOperations(fetched));for(int t=1;t<span;t++)constants.packet(List.of());
                pc=after(fetched.get(fetched.size()-1));
            }
        }catch(Exception unknown){return C6000LoopCounterProof.Proof.unknown("prefix proof unavailable: "+unknown.getMessage());}
        return C6000LoopCounterProof.Proof.unknown("prefix proof packet bound");
    }

    private record ProofPacket(long pc,long next,int span,List<Insn> instructions) {}
    private boolean proofControl(Insn instruction){
        var flow=instruction.instruction().getFlowType();
        return flow.isJump()||flow.isCall()||flow.isTerminal()||Set.of("B","BNOP","BDEC","BPOS","CALLP","SPLOOP","SPLOOPD","SPLOOPW","SPKERNEL","SPMASK").contains(instruction.name());
    }
    private int proofCycles(List<ProofPacket> packets,int first,int last){int cycles=0;for(int k=first;k<last;k++)cycles+=packets.get(k).span();return cycles;}
    private int proofDistance(List<ProofPacket> packets,Map<Long,Integer> indices,Map<Long,Set<Long>> edges,long after,long target){
        Map<Long,Integer> distances=new HashMap<>();var queue=new PriorityQueue<long[]>(Comparator.comparingLong(x->x[1]));
        for(long next:edges.getOrDefault(after,Set.of())){distances.put(next,0);queue.add(new long[]{next,0});}
        while(!queue.isEmpty()){var item=queue.remove();long at=item[0];int distance=(int)item[1];if(distance!=distances.get(at))continue;if(at==target)return distance;
            int nextDistance=distance+packets.get(indices.get(at)).span();for(long next:edges.getOrDefault(at,Set.of()))if(nextDistance<distances.getOrDefault(next,Integer.MAX_VALUE)){distances.put(next,nextDistance);queue.add(new long[]{next,nextDistance});}}
        return -1;
    }
    /** Conservative suffix proof across earlier loops: raw CFG dominance, not
     * analysis references, and no guessed predecessor register values. This
     * changes only the proof of impossible loading exits, never issue timing. */
    private C6000LoopCounterProof.Proof proveLoadingSuffix(Insn start,LoopPlan plan){
        try{
            if(!Set.of("SPLOOP","SPLOOPD").contains(start.name())||start.predicate()!=null)return C6000LoopCounterProof.Proof.unknown("not an unconditional counted loop");
            List<ProofPacket> packets=new ArrayList<>();Map<Long,Integer> indices=new HashMap<>();
            long pc=entry.getOffset(),end=function.getBody().getMaxAddress().getOffset();int delay=-1,maxLatency=1;
            for(int count=0;count<1000;count++){
                var decoded=packet(pc);int span=1;boolean returns=false;
                for(var item:decoded){span=Math.max(span,item.span());maxLatency=Math.max(maxLatency,item.latency());if(Set.of("B","BNOP").contains(item.name())&&item.instruction().getRegister(0)!=null&&item.instruction().getRegister(0).getName().equals("B3"))returns=true;}
                long next=after(decoded.get(decoded.size()-1));indices.put(pc,packets.size());packets.add(new ProofPacket(pc,next,span,decoded));
                if(delay>=0)delay-=span;if(returns)delay=6-span;pc=next;if(delay==0||delay<0&&pc>end)break;
                if(count==999)return C6000LoopCounterProof.Proof.unknown("suffix raw packet bound");
            }
            Integer target=indices.get(plan.start());if(target==null)return C6000LoopCounterProof.Proof.unknown("loop not at packet boundary");
            Map<Long,Set<Long>> edges=new HashMap<>();List<LoopPlan> previous=new ArrayList<>();
            for(var pack:packets){
                Set<Long> next=new HashSet<>();if(indices.containsKey(pack.next()))next.add(pack.next());
                for(var item:pack.instructions()){
                    var flow=item.instruction().getFlowType();
                    if(flow.isJump()||flow.isCall()||Set.of("B","BNOP","BDEC","BPOS","CALLP").contains(item.name())){
                        var destination=item.instruction().getAddress(0);
                        if(destination!=null){if(!indices.containsKey(destination.getOffset()))return C6000LoopCounterProof.Proof.unknown("raw CFG leaves scope");next.add(destination.getOffset());}
                        else if(item.instruction().getRegister(0)==null||!item.instruction().getRegister(0).getName().equals("B3"))return C6000LoopCounterProof.Proof.unknown("unresolved raw CFG target");
                    }
                    if(item.instruction().getAddress().getOffset()<plan.start()&&Set.of("SPLOOP","SPLOOPD","SPLOOPW").contains(item.name()))previous.add(planLoop(item));
                }
                edges.put(pack.pc(),next);
            }
            for(var old:previous){
                int position=indices.get(old.start());long body=packets.get(position).next();var oldProof=loadingCountProofs.get(old.start());if((oldProof==null||!oldProof.noLoadingExit())&&indices.containsKey(old.postPc()))edges.get(old.start()).add(old.postPc());
                for(var cell:old.cells())for(var item:cell.source())if(item.name().equals("SPKERNEL"))for(var pack:packets)if(pack.instructions().contains(item))edges.get(pack.pc()).add(body);
            }
            // Include the target loop's possible skip/backedges too: a later raw
            // edge into the candidate suffix may not be ignored.
            if(indices.containsKey(plan.postPc()))edges.get(plan.start()).add(plan.postPc());
            for(var cell:plan.cells())for(var item:cell.source())if(item.name().equals("SPKERNEL"))for(var pack:packets)if(pack.instructions().contains(item))edges.get(pack.pc()).add(packets.get(target).next());
            Set<Long> reachable=new HashSet<>();var queue=new ArrayDeque<Long>();queue.add(entry.getOffset());while(!queue.isEmpty()){long at=queue.remove();if(reachable.add(at))queue.addAll(edges.getOrDefault(at,Set.of()));}
            Map<Long,Set<Long>> dominators=new HashMap<>();for(long at:reachable)dominators.put(at,new HashSet<>(at==entry.getOffset()?Set.of(at):reachable));
            boolean changed;do{changed=false;for(long at:reachable){if(at==entry.getOffset())continue;Set<Long> common=null;for(var edge:edges.entrySet())if(reachable.contains(edge.getKey())&&edge.getValue().contains(at)){if(common==null)common=new HashSet<>(dominators.get(edge.getKey()));else common.retainAll(dominators.get(edge.getKey()));}if(common==null)common=new HashSet<>();common.add(at);if(!common.equals(dominators.get(at))){dominators.put(at,common);changed=true;}}}while(changed);
            int lastControl=-1;for(int k=0;k<target;k++)for(var item:packets.get(k).instructions())if(proofControl(item))lastControl=k;
            if(lastControl<0)return C6000LoopCounterProof.Proof.unknown("no suffix boundary");
            int anchor=lastControl+1,slots=5;while(anchor<target&&slots>0){slots-=packets.get(anchor).span();anchor++;}
            if(slots!=0||anchor>=target||!dominators.getOrDefault(plan.start(),Set.of()).contains(packets.get(anchor).pc()))return C6000LoopCounterProof.Proof.unknown("suffix does not dominate loop after delay work");
            long begin=packets.get(anchor).pc();for(var edge:edges.entrySet())for(long destination:edge.getValue())if(destination>begin&&destination<=plan.start()&&!(edge.getKey()>=begin&&edge.getKey()<plan.start()&&packets.get(indices.get(edge.getKey())).next()==destination))return C6000LoopCounterProof.Proof.unknown("nonlinear edge enters suffix");
            for(var old:previous){
                int kernel=-1;for(int k=0;k<anchor;k++)for(var item:packets.get(k).instructions())if(item.name().equals("SPKERNEL")&&old.cells().stream().anyMatch(cell->cell.source().contains(item)))kernel=k;
                var proof=loadingCountProofs.get(old.start());int bound=old.cells().size()+6+maxLatency-1;
                if(kernel<0||proof==null||!proof.noLoadingExit()||!dominators.getOrDefault(begin,Set.of()).contains(packets.get(kernel).pc())||proofDistance(packets,indices,edges,packets.get(kernel).pc(),begin)<bound)return C6000LoopCounterProof.Proof.unknown("earlier loop not proved quiescent on every raw CFG path");
            }
            var constants=new C6000LoopCounterProof(program.getLanguage());int warmup=maxLatency-1;
            for(int k=anchor;k<target;k++){var pack=packets.get(k);for(int t=0;t<pack.span();t++){if(warmup>0)constants.forgetRegisters();constants.packet(t==0?proofOperations(pack.instructions()):List.of());if(warmup>0){constants.forgetRegisters();warmup--;}}}
            return constants.finish(start.name(),plan.ii(),plan.cells().size(),program.getRegister("C6000_PIPE_ILC").getAddress().getOffset(),proofOperations(packets.get(target).instructions()));
        }catch(Exception unknown){return C6000LoopCounterProof.Proof.unknown("suffix proof unavailable: "+unknown.getMessage());}
    }

    private boolean provedLoadingContinue(LoopPlan loop,LoopFrame frame,Insn start){
        long address=start==null?loop.start():start.instruction().getAddress().getOffset();
        var proof=loadingCountProofs.get(address);
        return proof!=null&&proof.noLoadingExit()&&(start!=null&&start.name().equals("SPLOOP")||frame!=null&&frame.time()<loop.cells().size()-1);
    }

    private int loopNextTime(LoopPlan plan,int time){int next=time+1;return next>=plan.cap()+plan.ii()?next-plan.ii():next;}
    private int lastLoadingBoundary(LoopPlan plan){return ((plan.cells().size()+plan.ii()-1)/plan.ii())*plan.ii()-1;}
    // SPRUFE8B 7.9.5: both zero- and one-iteration invocations remain
    // active through the final loading stage boundary, even after SPKERNEL.
    private boolean singleIteration(LoopPlan plan,LoopFrame frame){return frame.drain()>=0&&frame.time()-frame.drain()<plan.ii();}
    private boolean bufferFinished(LoopPlan plan,LoopFrame frame){
        if(frame.abrupt())return true;if(frame.drain()<0)return false;
        if(frame.zero()||singleIteration(plan,frame))return frame.time()>=lastLoadingBoundary(plan);
        return frame.time()>=plan.cells().size()-1&&frame.drain()>=Math.max(0,plan.cells().size()-plan.ii());
    }
    private boolean loopFinished(LoopPlan plan,LoopFrame frame){
        if(frame.abrupt()&&!frame.refill())return frame.time()>=plan.cells().size()-1;
        if(!bufferFinished(plan,frame))return false;
        if(frame.zero())return true;
        var next=new LoopFrame(frame.start(),loopNextTime(plan,frame.time()),frame.drain()+1,false,frame.refill(),frame.abrupt());
        return postFetch(plan,frame)||postFetch(plan,next);
    }
    private boolean postFetch(LoopPlan plan,LoopFrame frame){
        if(frame.zero()||frame.drain()<0||singleIteration(plan,frame)&&frame.time()<=lastLoadingBoundary(plan))return false;
        // SPRUFE8B SPKERNEL p.481 and 7.9.4/7.12 specify when execution of
        // sequential post-loop packets resumes. A suspended PM stream is not a
        // new branch target: do not infer six extra E1 cycles from 4.1.4's
        // general fetch pipeline. Abrupt branch-like exit remains separate.
        if(frame.abrupt())return frame.drain()>=7;
        int delay=Math.min(plan.fetchDelay(),Math.max(0,plan.cells().size()-plan.ii()));
        return frame.time()>=plan.cells().size()&&frame.drain()>=1+delay;
    }
    private List<Insn> loopOperations(LoopPlan plan,LoopFrame frame,List<Insn> fetched){
        if(frame.abrupt())return fetched;
        List<Insn> result=new ArrayList<>();int mask=0;for(var instruction:fetched)if(instruction.name().equals("SPMASK"))mask|=(int)instruction.instruction().getScalar(0).getValue();
        for(var instruction:fetched)if(!frame.zero()||(unit(instruction)&mask)!=0||instruction.name().equals("BNOP")&&instruction.instruction().getAddress(0)!=null)result.add(instruction);
        for(int source=frame.time()%plan.ii();source<=frame.time()&&source<plan.cells().size();source+=plan.ii()){
            if(frame.zero()||source==frame.time()||frame.drain()>=0&&source<frame.drain())continue;
            for(var instruction:plan.cells().get(source).buffered())if((unit(instruction)&mask)==0)result.add(instruction);
        }
        return result;
    }

    private void checkStable(Insn instruction,int phase,List<Dest> writes){
        for(var read:instruction.reads())if(phase>=read.first()&&phase<read.last())for(var write:writes)
            if(write.offset()<read.offset()+4&&write.offset()+write.size()>read.offset())
                throw fail("writer violates repeated DP source-read stability at "+instruction.instruction().getAddress());
    }

    private void copy(List<Runnable> moves,Varnode to,Varnode from){
        var snapshot=temp(from.getSize());
        b.op(PcodeOp.COPY,snapshot,from);
        moves.add(()->b.op(PcodeOp.COPY,to,snapshot));
    }
    private final class Builder {
        List<PcodeOp> code=new ArrayList<>();
        Map<String,Integer> labels=new HashMap<>();
        Map<Integer,String> patches=new HashMap<>();
        int labelCounter;
        void op(int opcode,Varnode out,Varnode... inputs){
            if (code.size() >= 1000000) throw fail("scheduled p-code exceeds one million operations");
            code.add(new PcodeOp(entry,code.size(),opcode,inputs,out));
        }
        void label(String label){
            if(labels.put(label,code.size())!=null)throw fail("duplicate p-code label "+label);
        }
        void jump(int opcode,String target,Varnode condition){
            patches.put(code.size(),target);
            if(condition==null)op(opcode,null,c(0,4));
            else op(opcode,null,c(0,4),condition);
        }
        PcodeOp[] finish(){
            for(var p:patches.entrySet()){
                Integer target=labels.get(p.getValue());
                if(target==null)throw fail("missing p-code label "+p.getValue());
                code.get(p.getKey()).setInput(c(target-p.getKey(),4),0);
            }
            return code.toArray(PcodeOp[]::new);
        }
    }
}
