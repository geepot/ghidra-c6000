// SPDX-License-Identifier: Apache-2.0
package c6000;

import ghidra.program.model.address.Address;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

/** Physical packet boundaries, SPRUFE8B 3.5 and 3.10.2.3 / Table 3-16. */
public final class C6000ExecutionPackets {
    private C6000ExecutionPackets() { }

    /** Inserted NOP advances, SPRUFE8B Figures F-17/F-18/F-20/F-21/F-32.
     * Sbu8/Sbu8c encode a fixed five, rendered by SLEIGH as literal text
     * rather than a Scalar. Other BNOP forms expose their encoded count.
     */
    static int bnopCount(Program program, Instruction instruction) throws MemoryAccessException {
        var count = instruction.getScalar(1);
        if (count != null) return (int) count.getUnsignedValue();
        if (instruction.getLength() == 2 &&
                C6000CallAnalyzer.baseName(instruction).startsWith("BNOP.")) {
            int word = Short.toUnsignedInt(program.getMemory().getShort(instruction.getAddress()));
            // Fixed-five Sbu8 and Sbu8c only; do not guess for other forms.
            if ((word & 0xc03e) == 0xc00a || (word & 0xc02e) == 0xc02a) return 5;
        }
        throw new IllegalArgumentException("missing BNOP NOP count at " + instruction.getAddress());
    }

    public static boolean parallelWithNext(Program program, Instruction instruction)
            throws MemoryAccessException {
        Address at = instruction.getAddress();
        if (instruction.getLength() == 4) return (program.getMemory().getInt(at) & 1) != 0;
        long base = at.getOffset() & ~31L;
        int header = program.getMemory().getInt(at.getNewAddress(base + 28));
        if ((header >>> 28) != 0xe) throw new MemoryAccessException("No compact header");
        return ((header >>> ((at.getOffset() - base) / 2)) & 1) != 0;
    }

    /** SPRUFE8B 3.8.10: only one such generator may occupy an execute packet. */
    static boolean startsMulticycleNop(Instruction instruction) {
        String name = C6000CallAnalyzer.baseName(instruction);
        if (name.equals("IDLE") || name.startsWith("CALLP") || name.startsWith("BNOP") || name.startsWith("ADDKPC")) return true;
        if (!name.equals("NOP")) return false;
        var count = instruction.getScalar(0);
        return count != null && count.getUnsignedValue() > 1;
    }

    /** Specific equal-count NOP exception, SPRUFE8B 3.8.11.5. */
    static boolean sameMulticycleNop(Instruction first, Instruction second) {
        if (!C6000CallAnalyzer.baseName(first).equals("NOP") ||
                !C6000CallAnalyzer.baseName(second).equals("NOP")) return false;
        var a = first.getScalar(0); var b = second.getScalar(0);
        return a != null && b != null && a.getUnsignedValue() > 1 &&
            a.getUnsignedValue() == b.getUnsignedValue();
    }

    /** PROT adds four NOP cycles to either load width: SPRUFE8B 3.10.2.2. */
    static boolean protectedLoad(Program program, Instruction instruction)
            throws MemoryAccessException {
        if (!C6000CallAnalyzer.baseName(instruction).startsWith("LD")) return false;
        long base = instruction.getAddress().getOffset() & ~31L;
        Address at = instruction.getAddress().getNewAddress(base + 28);
        if (!program.getMemory().contains(at.add(3))) return false;
        int header = program.getMemory().getInt(at);
        return (header >>> 28) == 0xe && (header & (1 << 20)) != 0;
    }

    /** Minimal physical instruction shape; headers occupy bytes but no execute cycle. */
    private record Slot(Address at, int length, boolean parallel, boolean header) { }

    private static Slot slot(Program program, Address at) throws MemoryAccessException {
        var memory = program.getMemory();
        long base = at.getOffset() & ~31L;
        int offset = (int) (at.getOffset() - base);
        if ((offset & 1) != 0) throw new MemoryAccessException("Odd instruction address");
        Address ha = at.getNewAddress(base + 28);
        var block = memory.getBlock(at);
        if (block == null || !block.isInitialized()) throw new MemoryAccessException("Uninitialized code");
        boolean compactPacket = false;
        int header = 0;
        if (memory.getAllInitializedAddressSet().contains(ha, ha.add(3))) {
            header = memory.getInt(ha);
            compactPacket = (header >>> 28) == 0xe;
        }
        if (compactPacket && offset == 28) return new Slot(at, 4, false, true);
        boolean compact = compactPacket && ((header >>> (21 + offset / 4)) & 1) != 0;
        if (!compact && (offset & 3) != 0) throw new MemoryAccessException("Not an instruction boundary");
        int length = compact ? 2 : 4;
        if (!memory.contains(at.add(length - 1))) throw new MemoryAccessException("Truncated instruction");
        boolean parallel = compact ? ((header >>> (offset / 2)) & 1) != 0 :
            (memory.getInt(at) & 1) != 0;
        return new Slot(at, length, parallel, false);
    }

    /** Raw fetch-layout shape for explicit trace scopes, independent of listing context. */
    static int instructionLengthAt(Program program,Address at)throws MemoryAccessException {
        var instruction=slot(program,at);
        if(instruction.header())throw new MemoryAccessException("Fetch-packet header is not an instruction start");
        return instruction.length();
    }

    /** Physical generator recognition before SLEIGH context is primed.
     * SPRUFE8B 3.8.10/3.8.11.5; F-10/F-11, ADDKPC format,
     * compact F-17/F-18/F-20/F-21/F-32 and H-9.
     * Positive values are NOP counts; -1 is a distinct generator; zero is none.
     */
    private static int nopGenerator(Program program, Slot instruction) throws MemoryAccessException {
        if (instruction.length() == 4) {
            int word=program.getMemory().getInt(instruction.at());
            if ((word & ~1) == 0x1e000) return -1; // IDLE, before the NOP family
            if ((word & 0xfffe1ffe) == 0) {
                int count=((word >>> 13) & 15)+1;
                return count>1?count:0;
            }
            if ((word & 0xf000007c) == 0x10000010) return -1; // CALLP, SPRUFE8B p.172
            if ((word & 0x1ffc) == 0x120 || // displacement BNOP
                (word & 0x0f830ffe) == 0x00800362 || // register BNOP
                (word & 0x1ffe) == 0x162) return -1; // ADDKPC
            return 0;
        }
        int word=Short.toUnsignedInt(program.getMemory().getShort(instruction.at()));
        if ((word & 0x1fff) == 0xc6e) {
            int count=(word >>> 13)+1;return count>1?count:0;
        }
        if ((word & 0x187e) == 0x6e) return -1; // register BNOP, independent of BR
        long base=instruction.at().getOffset() & ~31L;
        int header=program.getMemory().getInt(instruction.at().getNewAddress(base+28));
        if ((header & (1<<15)) != 0 &&
            ((word & 0x3e)==0xa || (word & 0x2e)==0x2a || (word & 0x3e)==0x1a)) return -1;
        return 0;
    }

    private static Slot previous(Program program, Address at) throws MemoryAccessException {
        if(at.getOffset()<2)return null;
        Slot prior;
        try { prior=slot(program,at.subtract(2)); }
        catch (MemoryAccessException first) {
            if(at.getOffset()<4||!program.getMemory().contains(at.subtract(4)))return null;
            prior=slot(program,at.subtract(4));
        }
        return prior.header()?previous(program,prior.at()):prior;
    }

    /** Earlier instructions in this same execute packet, in issue order. */
    static List<Address> issuePrefix(Program program, Address at) throws MemoryAccessException {
        List<Address> result=new ArrayList<>();
        Slot current=slot(program,at);
        while(true) {
            Slot prior=previous(program,current.at());
            if(prior==null||!prior.parallel())break;
            if(result.size()==7)throw new MemoryAccessException("Oversized execute packet");
            result.add(prior.at());current=prior;
        }
        Collections.reverse(result);return result;
    }

    private static int mergeGenerator(int first,int second) throws MemoryAccessException {
        if(first!=0&&second!=0&&(first<0||second<0||first!=second))
            throw new MemoryAccessException("Conflicting multicycle NOP generators");
        return second!=0?second:first;
    }

    private static Address following(Slot slot) throws MemoryAccessException {
        try { return slot.at().addNoWrap(slot.length()); }
        catch (ghidra.program.model.address.AddressOverflowException end) {
            throw new MemoryAccessException("Execute packet extends beyond the address space");
        }
    }

    /** Bytes after this instruction through its execute-packet end, including crossed headers. */
    public static int parallelBytes(Program program, Address at) throws MemoryAccessException {
        Slot current = slot(program, at);
        if (current.header()) return 0;
        long firstEnd = at.getOffset() + current.length();
        var prefix=issuePrefix(program,at);
        int instructions = 1+prefix.size();
        int generator=0;
        for(var prior:prefix)generator=mergeGenerator(generator,nopGenerator(program,slot(program,prior)));
        generator=mergeGenerator(generator,nopGenerator(program,current));
        while (current.parallel()) {
            if (++instructions > 8) throw new MemoryAccessException("Oversized execute packet");
            Slot next = slot(program, following(current));
            if (next.header()) next = slot(program, following(next));
            int other=nopGenerator(program,next);
            generator=mergeGenerator(generator,other);
            current = next;
        }
        return (int) (current.at().getOffset() + current.length() - firstEnd);
    }
}
