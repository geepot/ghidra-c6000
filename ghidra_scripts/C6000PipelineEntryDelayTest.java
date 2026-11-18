// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Exact schedule whose entry packet issues a jump, in a tests/fixtures/pipeline-entry-delay.py image.
// Run after C6000PipelineEntryDelayTest.java prepare CASES.json.
import c6000.C6000PacketContext;
import c6000.C6000PipelineCompiler;
import c6000.C6000PipelineContracts;
import c6000.C6000PipelineSchedules;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.*;
import ghidra.pcode.exec.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;

public class C6000PipelineEntryDelayTest extends GhidraScript {
    private static final String EVIDENCE = "Fixture entry: drained pipeline, caller return link in B3";

    private static final class Fixture {
        long entry;
        long body_end;
        long window_end;
        long slot;
        long inside;
        long outside;
    }

    private interface Action { void run() throws Exception; }

    private Fixture fixture;

    private void prepare() throws Exception {
        C6000PacketContext.prime(currentProgram, monitor);
        Address entry = toAddr(fixture.entry);
        if (!new DisassembleCommand(entry, new AddressSet(entry, toAddr(fixture.body_end)), false)
                .applyTo(currentProgram, monitor)) {
            throw new IllegalStateException("Could not disassemble entry-delay fixture");
        }
        currentProgram.getSymbolTable().addExternalEntryPoint(entry);
        currentProgram.getFunctionManager().createFunction("entry_delay_jump", entry,
            new AddressSet(entry, toAddr(fixture.body_end)), SourceType.USER_DEFINED);
    }

    private String line(Reference reference) {
        return reference.getFromAddress() + "|" + reference.getToAddress() + "|" + reference.getOperandIndex() + "|" +
            reference.getReferenceType() + "|" + reference.getSource() + "|" + reference.isPrimary() + "|" +
            reference.getSymbolID();
    }

    /** Listing state enable or disable could touch, over the function and outside jump. */
    private String listing() throws Exception {
        var text = new StringBuilder();
        var listing = currentProgram.getListing();
        var references = currentProgram.getReferenceManager();
        var equates = currentProgram.getEquateTable();
        var scope = new AddressSet(toAddr(fixture.entry), toAddr(fixture.body_end));
        scope.add(toAddr(fixture.outside), toAddr(fixture.outside + 7));
        for (Address at : scope.getAddresses(true)) {
            Instruction instruction = listing.getInstructionAt(at);
            if (instruction != null) {
                text.append("I|").append(at).append('|').append(instruction.getLength()).append('|')
                    .append(HexFormat.of().formatHex(getBytes(at, instruction.getLength()))).append('|')
                    .append(instruction).append('|').append(instruction.getFlowType()).append('|')
                    .append(instruction.getFlowOverride()).append('|').append(instruction.getDelaySlotDepth())
                    .append('|').append(instruction.isInDelaySlot()).append('|')
                    .append(instruction.getPrototype().getDelaySlotByteCount()).append('|')
                    .append(instruction.isFallThroughOverridden() ? instruction.getFallThrough() : "default")
                    .append('|').append(instruction.getFallThrough()).append('\n');
            }
            else if (listing.getDefinedDataAt(at) != null) {
                text.append("D|").append(at).append('|').append(listing.getDefinedDataAt(at).getDataType().getName()).append('\n');
            }
            for (CommentType type : CommentType.values()) {
                String comment = listing.getComment(type, at);
                if (comment != null) text.append("C|").append(at).append('|').append(type).append('|').append(comment).append('\n');
            }
            for (Symbol symbol : currentProgram.getSymbolTable().getSymbols(at))
                text.append("S|").append(at).append('|').append(symbol.getName(true)).append('|').append(symbol.isPrimary()).append('\n');
            for (Equate equate : equates.getEquates(at))
                for (var use : equate.getReferences(at))
                    text.append("E|").append(at).append('|').append(equate.getName()).append('|').append(equate.getValue())
                        .append('|').append(use.getOpIndex()).append('\n');
            for (Reference reference : references.getReferencesFrom(at)) text.append("R|").append(line(reference)).append('\n');
            for (Reference reference : references.getReferencesTo(at)) text.append("T|").append(line(reference)).append('\n');
        }
        text.append("F|").append(currentProgram.getFunctionManager().getFunctionAt(toAddr(fixture.entry)).getBody()).append('\n');
        // Unset and zero select the same ordinary decode.
        text.append("X|").append(BigInteger.ONE.equals(selector())).append('\n');
        return text.toString();
    }

    private BigInteger selector() {
        return currentProgram.getProgramContext().getValue(currentProgram.getRegister("c_schedule_entry"),
            toAddr(fixture.entry), false);
    }

    private C6000PipelineCompiler.Result activate(Function function) throws Exception {
        long start = fixture.entry & ~31L;
        var sources = List.of(new C6000PipelineContracts.SourceWindow(start, 0x40,
            C6000PipelineContracts.sha256(getBytes(toAddr(start), 0x40))));
        var review = C6000PipelineContracts.review(currentProgram, function, EVIDENCE, Set.of(), sources, monitor);
        C6000PipelineContracts.record(currentProgram, function, review, monitor);
        return C6000PipelineContracts.activate(currentProgram, function, monitor);
    }

    /** Runs the schedule; it must make no call. */
    private void execute(C6000PipelineCompiler.Result schedule) throws Exception {
        var language = (SleighLanguage) currentProgram.getLanguage();
        var arithmetic = BytesPcodeArithmetic.forLanguage(language);
        var state = new BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE);
        for (var register : language.getRegisters()) {
            if (!register.isProcessorContext() && register.getMinimumByteSize() == 4) state.setVar(register, arithmetic.fromConst(0, 4));
        }
        state.setVar(currentProgram.getRegister("B3"), arithmetic.fromConst(0x9000, 4));
        state.setVar(currentProgram.getRegister("B13"), arithmetic.fromConst(0x77, 4));
        var reason = PcodeExecutorStatePiece.Reason.INSPECT;
        var purpose = PcodeArithmetic.Purpose.INSPECT;
        long[] called = {-1, -1, 0};
        var executor = new PcodeExecutor<byte[]>(language, arithmetic, state, PcodeExecutorStatePiece.Reason.EXECUTE_READ) {
            @Override
            public void executeCall(PcodeOp op, PcodeFrame frame, PcodeUseropLibrary<byte[]> library) {
                called[0] = op.getInput(0).getOffset();
                called[1] = arithmetic.toLong(state.getVar(currentProgram.getRegister("B3"), reason), purpose);
                called[2]++;
            }
        };
        var library = PcodeUseropLibrary.<byte[]>nil();
        var frame = executor.begin(new PcodeProgram(language, Arrays.asList(schedule.code()), library.getSymbols(language)) {});
        int steps = 0;
        while (!frame.isFinished() && steps++ < 100000) executor.step(frame, library);
        if (!frame.isFinished()) throw new AssertionError("Entry-delay schedule exceeded step bound");
        long a4 = arithmetic.toLong(state.getVar(currentProgram.getRegister("A4"), reason), purpose);
        long b3 = arithmetic.toLong(state.getVar(currentProgram.getRegister("B3"), reason), purpose);
        long b13 = arithmetic.toLong(state.getVar(currentProgram.getRegister("B13"), reason), purpose);
        long pc = arithmetic.toLong(state.getVar(currentProgram.getRegister("PC"), reason), purpose);
        if (called[2] != 0) throw new AssertionError(called[2] + " call(s) to " + Long.toHexString(called[0]));
        // The slots run (5 + 1) + (7 + 1); the skipped ADDK would add 1000.
        if (a4 != 14 || b3 != 0x9000 || b13 != 0x77 || pc != 0x9000)
            throw new AssertionError("scheduled result A4=" + a4 + " B3=" + Long.toHexString(b3) + " B13=" + Long.toHexString(b13) +
                " PC=" + Long.toHexString(pc));
    }

    private void refuses(String what, String message, Action action) throws Exception {
        String before = listing();
        try {
            action.run();
            throw new AssertionError("accepted " + what);
        }
        catch (IllegalArgumentException error) {
            if (message != null && !String.valueOf(error.getMessage()).contains(message))
                throw new AssertionError(what + ": wrong refusal " + error, error);
            println("EXPECTED_REFUSAL " + what + ": " + error.getMessage());
        }
        if (!before.equals(listing()) || BigInteger.ONE.equals(selector()))
            throw new AssertionError(what + ": refusal changed the listing");
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        boolean prepare = args.length == 2 && args[0].equals("prepare");
        if (!prepare && args.length != 1) throw new IllegalArgumentException("Expected [prepare] CASES.json");
        fixture = new com.google.gson.Gson().fromJson(Files.readString(Paths.get(args[args.length - 1])), Fixture.class);
        if (prepare) {
            prepare();
            return;
        }
        C6000PacketContext.prime(currentProgram, monitor);
        Function function = currentProgram.getFunctionManager().getFunctionAt(toAddr(fixture.entry));
        if (function == null) throw new AssertionError("Missing entry-delay function");
        Instruction entry = currentProgram.getListing().getInstructionAt(toAddr(fixture.entry));
        if (entry == null || !entry.getFlowType().isJump() || entry.getFlowType().isConditional() || entry.getDelaySlotDepth() != 5 ||
                entry.getMaxAddress().getOffset() + entry.getPrototype().getDelaySlotByteCount() != fixture.window_end)
            throw new AssertionError("Fixture entry is not a native jump with five slots: " + entry);
        int checks = 0;
        // State that clearing code units drops must survive both directions.
        currentProgram.getListing().setComment(toAddr(fixture.slot + 4), CommentType.PRE, "slot annotation");
        currentProgram.getReferenceManager().addMemoryReference(toAddr(fixture.slot + 8), toAddr(0x11f0),
            RefType.DATA, SourceType.USER_DEFINED, 0);
        currentProgram.getEquateTable().createEquate("FIVE", 5).addReference(toAddr(fixture.slot + 8), 0);
        currentProgram.getSymbolTable().createLabel(toAddr(fixture.slot), "entry_slot", SourceType.USER_DEFINED);
        String original = listing();
        var schedule = activate(function);
        for (PcodeOp operation : schedule.code())
            if (operation.getOpcode() == PcodeOp.CALL) throw new AssertionError("Scheduled jump became a call");
        entry = currentProgram.getListing().getInstructionAt(toAddr(fixture.entry));
        if (!BigInteger.ONE.equals(selector()) || entry.getDelaySlotDepth() != 0 || entry.getPrototype().getDelaySlotByteCount() != 0)
            throw new AssertionError("Scheduled entry retained native delay slots");
        for (long at = fixture.slot; at <= fixture.window_end; at += 4) {
            var slot = currentProgram.getListing().getInstructionAt(toAddr(at));
            if (slot == null || slot.isInDelaySlot()) throw new AssertionError("Scheduled slot not ordinary at " + toAddr(at));
        }
        checks++;
        execute(schedule);
        checks++;
        String scheduled = listing();
        if (!scheduled.contains("slot annotation") || !scheduled.contains("|FIVE|5|0") ||
                !scheduled.contains("|" + toAddr(0x11f0) + "|0|DATA|USER_DEFINED"))
            throw new AssertionError("Enable dropped window annotations:\n" + scheduled);
        var again = C6000PipelineContracts.activate(currentProgram, function, monitor);
        C6000PipelineContracts.validate(currentProgram, function, again, monitor);
        if (!scheduled.equals(listing())) throw new AssertionError("Repeated activation changed the listing");
        // Auto-analysis must neither re-lay the entry's former slots nor stale the binding.
        analyzeAll(currentProgram);
        if (!scheduled.equals(listing()))
            throw new AssertionError("Analysis changed the scheduled listing:\n" + scheduled + "---\n" + listing());
        C6000PipelineContracts.validate(currentProgram, function,
            C6000PipelineContracts.activate(currentProgram, function, monitor), monitor);
        checks++;
        C6000PipelineSchedules.disable(currentProgram, function, monitor);
        if (!original.equals(listing()))
            throw new AssertionError("Disable did not restore the listing exactly:\n" + original + "---\n" + listing());
        checks++;

        // Known-bad: the body references a slot, so the window is not the entry's alone.
        Address inside = toAddr(fixture.inside);
        var reference = currentProgram.getReferenceManager().addMemoryReference(inside, toAddr(fixture.slot + 8),
            RefType.DATA, SourceType.USER_DEFINED, 0);
        refuses("a body reference into the entry window", "entry native delay window entered from " + inside,
            () -> C6000PipelineSchedules.enable(currentProgram, function, EVIDENCE, Set.of(), monitor));
        refuses("a reviewed body reference into the entry window", null, () -> activate(function));
        C6000PipelineSchedules.disable(currentProgram, function, monitor);
        currentProgram.getReferenceManager().delete(reference);
        if (!original.equals(listing())) throw new AssertionError("Known-bad cleanup changed the listing");
        checks++;

        // Known-bad: an outside jump enters the entry's slot window.
        Address outside = toAddr(fixture.outside);
        if (!new DisassembleCommand(outside, new AddressSet(outside, outside.add(7)), false).applyTo(currentProgram, monitor))
            throw new IllegalStateException("Could not disassemble outside jump");
        boolean enters = false;
        for (Reference jump : currentProgram.getReferenceManager().getReferencesFrom(outside))
            enters |= jump.getToAddress().equals(toAddr(fixture.slot)) && jump.getReferenceType().isFlow();
        if (!enters) throw new AssertionError("Fixture outside branch does not enter the slot window");
        refuses("an outside jump into the entry window", "entry native delay window entered from " + outside,
            () -> C6000PipelineSchedules.enable(currentProgram, function, EVIDENCE, Set.of(), monitor));
        refuses("a reviewed outside jump into the entry window", null, () -> activate(function));
        checks++;
        println("C6000_PIPELINE_ENTRY_DELAY_OK checks=" + checks);
    }
}
