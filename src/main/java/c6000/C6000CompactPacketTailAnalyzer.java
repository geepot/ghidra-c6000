// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.util.*;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Complete proved execute-packet peers. Retain the historical option name. */
public class C6000CompactPacketTailAnalyzer extends AbstractAnalyzer {
    public C6000CompactPacketTailAnalyzer() {
        super("C6000 Compact Packet Tails",
            "Complete physically proved compact and full-width execute-packet peers",
            AnalyzerType.INSTRUCTION_ANALYZER);
        setDefaultEnablement(true);
        setPriority(AnalysisPriority.CODE_ANALYSIS.after());
    }
    @Override
    public boolean canAnalyze(Program program) { return C6000PacketContext.isC6000(program); }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        var roots = new ArrayList<Address>();
        var instructions = program.getListing().getInstructions(set, true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            roots.add(instructions.next().getAddress());
        }
        int created = 0;
        for (var root : roots) {
            monitor.checkCancelled();
            try { created += recover(program, root, monitor); }
            catch (CancelledException cancelled) { throw cancelled; }
            catch (Exception failure) { log.appendException(failure); return false; }
        }
        if (created > 0) Msg.info(this, getName() + "> decoded " + created + " proved parallel peer(s)");
        return true;
    }

    private int recover(Program program, Address root, TaskMonitor monitor) throws Exception {
        // The source-bound proof currently models the default 32-bit memory space.
        // Never prove bytes in the default space and insert them into an overlay.
        if (!root.getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace()))
            return 0;
        long pc = root.getOffset();
        if (pc < 0 || pc >= 0x100000000L) return 0;
        // Eight physical instructions plus crossed headers fit in this bounded window.
        long start = Math.max(0, (pc & ~31L) - 64);
        long end = Math.min(0x100000000L, (pc & ~31L) + 96);
        var proof = new C6000ParallelPeers(program, monitor, start, end);
        proof.inspect(pc, Math.min(pc + 64, end));
        var plan = proof.candidates();
        if (plan.isEmpty()) return 0;
        int transaction = program.startTransaction("Complete proved C6000 execute packet");
        boolean commit = false;
        try {
            for (var value : plan) {
                monitor.checkCancelled();
                var row = value.row();
                Address at = root.getNewAddress(row.address());
                if (!Objects.equals(proof.owner(row.address()), row.owner()))
                    throw new IllegalStateException("peer owner changed");
                proof.undefined(row.address(), row.width(), row.owner());
                if (!HexFormat.of().formatHex(proof.bytes(row.address(), row.width())).equals(row.bytes()))
                    throw new IllegalStateException("peer bytes changed");
                var fresh = proof.parse(row.address(), true, true);
                var stored = proof.parse(row.address(), false, true);
                if (!stored.contextSha().equals(row.contextSha()) ||
                        !stored.pcodeSha().equals(row.pcodeSha()) ||
                        !fresh.pcodeSha().equals(stored.pcodeSha()))
                    throw new IllegalStateException("peer decode changed");
                var contextBefore = program.getProgramContext().getRegisterValue(
                    program.getLanguage().getContextBaseRegister(), at);
                var instruction = program.getListing().createInstruction(at, stored.prototype(),
                    new DumbMemBufferImpl(program.getMemory(), at), stored.context(), 0);
                if (instruction.getLength() != row.width() ||
                        !instruction.toString().equals(row.listing()) ||
                        !proof.pcode(instruction).equals(row.pcodeSha()) ||
                        !Objects.equals(contextBefore, program.getProgramContext().getRegisterValue(
                            program.getLanguage().getContextBaseRegister(), at)))
                    throw new IllegalStateException("created peer differs from proof at " + at);
            }
            commit = true;
            return plan.size();
        }
        finally { program.endTransaction(transaction, commit); }
    }
}
