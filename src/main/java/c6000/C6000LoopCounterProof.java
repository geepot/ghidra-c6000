// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.util.*;
import ghidra.pcode.exec.BytesPcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.program.model.lang.Language;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/** Conservative constants for an unconditional counted loop's straight-line prefix.
 * SPRUFE8B 3.7: packet operands see old values; 7.4.3: ILC reaches the loop
 * interface four cycles after MVC; 7.9.1--3: exact initial/stage counter tests.
 * This proves unreachable loading exits; it never changes the loop timing model.
 */
public final class C6000LoopCounterProof {
    public record Output(long offset, int size, long valueOffset, int phase, boolean opaque) {}
    public record Operation(PcodeOp[] code, List<Output> outputs, Long predicate, boolean inverted) {}
    public record Proof(boolean noLoadingExit, Long counter, int required, String reason) {
        public static Proof unknown(String reason) { return new Proof(false, null, 0, reason); }
    }
    private record Write(int cycle, long offset, int size, byte[] value) {}
    private final BytesPcodeArithmetic arithmetic;
    private final Map<Long,Byte> registers = new HashMap<>();
    private final List<Write> pending = new ArrayList<>();
    private int cycle;

    public C6000LoopCounterProof(Language language) {
        arithmetic = BytesPcodeArithmetic.forLanguage(language);
    }

    /** Constant-only raw p-code proof; unknown architectural inputs never get defaults. */
    static Long constantOutput(Language language,PcodeOp[] code,long offset,int size) {
        var proof=new C6000LoopCounterProof(language);
        var image=proof.evaluate(new Operation(code,List.of(),null,false));
        if(image==null)return null;var value=proof.read(image,offset,size);
        return value==null?null:proof.arithmetic.toLong(value,PcodeArithmetic.Purpose.INSPECT);
    }

    /** constantOutput with one register known first, such as the predicate that lets the code run. */
    static Long constantOutput(Language language,PcodeOp[] code,long offset,int size,long knownOffset,int knownSize,long knownValue) {
        return constantOutput(language,code,offset,size,List.of(new long[]{knownOffset,knownSize,knownValue}));
    }

    /** constantOutput with registers known first, each {offset, size, value}. */
    static Long constantOutput(Language language,PcodeOp[] code,long offset,int size,List<long[]> known) {
        var proof=new C6000LoopCounterProof(language);
        for(long[] k:known)proof.write(proof.registers,k[0],(int)k[1],proof.arithmetic.fromConst(k[2],(int)k[1]));
        var image=proof.evaluate(new Operation(code,List.of(),null,false));
        if(image==null)return null;var value=proof.read(image,offset,size);
        return value==null?null:proof.arithmetic.toLong(value,PcodeArithmetic.Purpose.INSPECT);
    }

    /** Value visible to the next packet, before any of its E1 writes. */
    public Long registerValue(long offset,int size) {
        var value=read(registers,offset,size);
        return value==null?null:arithmetic.toLong(value,PcodeArithmetic.Purpose.INSPECT);
    }

    private byte[] read(Map<Long,Byte> bytes, long at, int size) {
        var result = new byte[size];
        for (int k=0;k<size;k++) {
            Byte value = bytes.get(at+k);
            if (value == null) return null;
            result[k] = value;
        }
        return result;
    }
    private void write(Map<Long,Byte> bytes, long at, int size, byte[] value) {
        for (int k=0;k<size;k++) {
            if (value == null) bytes.remove(at+k);
            else bytes.put(at+k,value[k]);
        }
    }
    private byte[] read(Varnode node, Map<Long,Byte> image, Map<Long,Byte> unique) {
        if (node.isConstant()) return arithmetic.fromConst(node.getOffset(),node.getSize());
        if (node.isRegister()) return read(image,node.getOffset(),node.getSize());
        if (node.isUnique()) return read(unique,node.getOffset(),node.getSize());
        return null;
    }
    private boolean nonzero(byte[] value) {
        for (byte b:value) if (b!=0) return true;
        return false;
    }

    // Use Ghidra's integer p-code arithmetic, rather than a second interpretation
    // of narrow/sign/shift operations. Memory and floating results stay unknown.
    private static final Set<Integer> INTEGER = Set.of(
        PcodeOp.COPY,PcodeOp.INT_ZEXT,PcodeOp.INT_SEXT,PcodeOp.INT_ADD,PcodeOp.INT_SUB,
        PcodeOp.INT_CARRY,PcodeOp.INT_SCARRY,PcodeOp.INT_SBORROW,PcodeOp.INT_2COMP,
        PcodeOp.INT_NEGATE,PcodeOp.INT_XOR,PcodeOp.INT_AND,PcodeOp.INT_OR,
        PcodeOp.INT_LEFT,PcodeOp.INT_RIGHT,PcodeOp.INT_SRIGHT,PcodeOp.INT_MULT,
        PcodeOp.INT_EQUAL,PcodeOp.INT_NOTEQUAL,PcodeOp.INT_LESS,PcodeOp.INT_SLESS,
        PcodeOp.INT_LESSEQUAL,PcodeOp.INT_SLESSEQUAL,PcodeOp.BOOL_NEGATE,
        PcodeOp.BOOL_XOR,PcodeOp.BOOL_AND,PcodeOp.BOOL_OR,PcodeOp.PIECE,PcodeOp.SUBPIECE);

    private Map<Long,Byte> evaluate(Operation operation) {
        var image = new HashMap<>(registers);
        var unique = new HashMap<Long,Byte>();
        int index=0,steps=0;
        while (index<operation.code().length && steps++<10000) {
            var op=operation.code()[index];int opcode=op.getOpcode();
            if (opcode==PcodeOp.BRANCH || opcode==PcodeOp.CBRANCH) {
                if (!op.getInput(0).isConstant()) return null;
                boolean take=true;
                if (opcode==PcodeOp.CBRANCH) {
                    var condition=read(op.getInput(1),image,unique);
                    if (condition==null) return null;
                    take=nonzero(condition);
                }
                int next=take?index+(int)op.getInput(0).getOffset():index+1;
                if (next<0 || next>operation.code().length) return null;
                index=next;continue;
            }
            if (opcode==PcodeOp.CALL) return image; // CALLP has already written its E1 link.
            if (opcode==PcodeOp.BRANCHIND ||
                opcode==PcodeOp.CALLIND || opcode==PcodeOp.RETURN ||
                opcode==PcodeOp.CALLOTHER || opcode==PcodeOp.UNIMPLEMENTED) return null;
            var output=op.getOutput();
            if (output!=null) {
                byte[] value=null;
                // x - x and x ^ x are zero whatever x holds.
                if ((opcode==PcodeOp.INT_SUB || opcode==PcodeOp.INT_XOR) && op.getNumInputs()==2 &&
                    op.getInput(0).equals(op.getInput(1)) && !op.getInput(0).isConstant()) {
                    value=new byte[output.getSize()];
                }
                else if (INTEGER.contains(opcode) && op.getNumInputs()<=2) {
                    byte[] first=read(op.getInput(0),image,unique);
                    byte[] second=op.getNumInputs()==2?read(op.getInput(1),image,unique):null;
                    if (first!=null && (op.getNumInputs()==1 || second!=null)) {
                        try {
                            value=op.getNumInputs()==1?
                                arithmetic.unaryOp(opcode,output.getSize(),op.getInput(0).getSize(),first):
                                arithmetic.binaryOp(opcode,output.getSize(),op.getInput(0).getSize(),first,
                                    op.getInput(1).getSize(),second);
                        } catch (RuntimeException unsupported) { value=null; }
                    }
                }
                if (output.isRegister()) write(image,output.getOffset(),output.getSize(),value);
                else if (output.isUnique()) write(unique,output.getOffset(),output.getSize(),value);
            }
            index++;
        }
        return index==operation.code().length?image:null;
    }

    /** Forget incoming register knowledge without discarding writes captured in
     * this proof's own packets. Used while unknown predecessor effects drain. */
    public void forgetRegisters(){registers.clear();}

    public record UnknownWrite(long offset,int size,int advances) {}
    /** A leaf call may change any of its outputs. Retain only unaffected constants.
     * Late callee/caller writes remain unknown hazards after the return; no drain
     * or ABI-preservation assumption is introduced into the constant proof. */
    public List<UnknownWrite> returnFromCall(List<Output> outputs) {
        var unknown=new ArrayList<UnknownWrite>();
        for(var out:outputs){write(registers,out.offset(),out.size(),null);if(out.phase()>1)unknown.add(new UnknownWrite(out.offset(),out.size(),out.phase()-1));}
        for(var event:pending){write(registers,event.offset(),event.size(),null);unknown.add(new UnknownWrite(event.offset(),event.size(),Math.max(1,event.cycle()-cycle+1)));}
        pending.clear();return List.copyOf(unknown);
    }

    /** Capture all sources before applying any writeback in this cycle. */
    public void packet(List<Operation> operations) {
        for (var operation:operations) {
            boolean enabled=true,known=true;
            if (operation.predicate()!=null) {
                var predicate=read(registers,operation.predicate(),4);
                known=predicate!=null;
                enabled=!known || (nonzero(predicate)!=operation.inverted());
            }
            if (!enabled) continue;
            var result=known?evaluate(operation):null;
            for (var output:operation.outputs()) {
                var value=result==null || output.opaque()?null:
                    read(result,output.valueOffset(),output.size());
                pending.add(new Write(cycle+output.phase()-1,output.offset(),output.size(),value));
            }
        }
        // Simultaneous possible writers destroy the proof, even if their values
        // happen to agree. Do not invent a priority for an undefined collision.
        var writes=new HashMap<Long,Byte>();var touched=new HashSet<Long>();var collisions=new HashSet<Long>();
        for (var event:pending) if (event.cycle()==cycle) {
            for (int k=0;k<event.size();k++) {
                long at=event.offset()+k;
                if (!touched.add(at)) collisions.add(at);
                if (event.value()!=null) writes.put(at,event.value()[k]);else writes.remove(at);
            }
        }
        for (long at:touched) {
            if (collisions.contains(at) || !writes.containsKey(at)) registers.remove(at);
            else registers.put(at,writes.get(at));
        }
        pending.removeIf(event->event.cycle()==cycle);
        cycle++;
    }

    public Proof finish(String kind, int ii, int dynamicLength, long counterOffset,
            List<Operation> startPacket) {
        int startCycle=cycle;
        if (kind.equals("SPLOOP")) {
            var value=read(registers,counterOffset,4);
            if (value==null) return Proof.unknown("unknown initial ILC");
            // A later interface write would invalidate the monotone decrement.
            if (pending.stream().anyMatch(w->w.offset()<counterOffset+4 && w.offset()+w.size()>counterOffset))
                return Proof.unknown("pending ILC interface write");
            long counter=arithmetic.toLong(value,PcodeArithmetic.Purpose.INSPECT)&0xffffffffL;
            int boundaries=(dynamicLength-1)/ii;
            int required=1+boundaries;
            return new Proof(counter>=required,counter,required,"initial test and loading-stage boundaries");
        }
        if (!kind.equals("SPLOOPD")) return Proof.unknown("uncounted loop");
        packet(startPacket);
        int firstBoundary=((4+ii-1)/ii)*ii-1;
        // SPLOOPD suppresses its initial test and the first three body cycles.
        // MVC in its EP reaches the interface before the first eligible test.
        while (cycle<startCycle+1+firstBoundary) packet(List.of());
        var value=read(registers,counterOffset,4);
        if (value==null) return Proof.unknown("unknown first stage-boundary ILC");
        if (pending.stream().anyMatch(w->w.offset()<counterOffset+4 && w.offset()+w.size()>counterOffset))
            return Proof.unknown("later ILC interface write");
        long counter=arithmetic.toLong(value,PcodeArithmetic.Purpose.INSPECT)&0xffffffffL;
        int boundaries=firstBoundary<dynamicLength-1?
            1+(dynamicLength-2-firstBoundary)/ii:0;
        return new Proof(counter>=boundaries,counter,boundaries,"SPLOOPD eligible loading-stage boundaries");
    }
}
