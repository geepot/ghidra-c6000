// SPDX-License-Identifier: Apache-2.0
// @category C6000
// SPRU198K 6.3.2.2 / SPRUFE8B 3.8.4: identical values, different X-path timing.
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
import c6000.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.symbol.SourceType;

public class C6000PipelineCpuTest extends GhidraScript {
    void equal(long expected, long actual, String label) {
        if (expected != actual) throw new AssertionError(label + " expected=" + expected + " actual=" + actual);
    }

    protected void run() throws Exception {
        C6000PacketContext.prime(currentProgram, monitor);
        String originalId = currentProgram.getLanguageID().getIdAsString();
        String variant = originalId.substring(originalId.lastIndexOf(':') + 1);
        if (!variant.equals(currentProgram.getLanguage().getLanguageDescription().getVariant()))
            throw new AssertionError("Language ID and variant disagree");
        boolean c67x = variant.equals("c67x") || variant.equals("c67x-analysis");
        var language = (SleighLanguage) currentProgram.getLanguage();
        var arithmetic = BytesPcodeArithmetic.forLanguage(language);
        var reason = PcodeExecutorStatePiece.Reason.INSPECT;
        int count = 0;
        for (var element : JsonParser.parseString(Files.readString(Paths.get(getScriptArgs()[0]))).getAsJsonArray()) {
            var row = element.getAsJsonObject();
            String name = row.get("name").getAsString();
            var at = toAddr(row.get("entry").getAsLong());
            var function = currentProgram.getFunctionManager().createFunction(name, at,
                new AddressSet(at, at.add(127)), SourceType.USER_DEFINED);
            Set<String> incoming = new HashSet<>();
            for (var register : row.getAsJsonArray("incoming")) incoming.add(register.getAsString());
            var result = new C6000PipelineCompiler(currentProgram, function, incoming).compile();
            var state = new BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE);
            for (var register : language.getRegisters()) {
                if (!register.isProcessorContext() && register.getMinimumByteSize() == 4)
                    state.setVar(register, arithmetic.fromConst(0, 4));
            }
            state.setVar(currentProgram.getRegister("B3"), arithmetic.fromConst(0x9000, 4));
            for (var input : row.getAsJsonObject("input").entrySet())
                state.setVar(currentProgram.getRegister(input.getKey()), arithmetic.fromConst(input.getValue().getAsLong(), 4));
            for (var memory : row.getAsJsonObject("memory").entrySet())
                state.setVar(toAddr(Long.parseLong(memory.getKey())), 4, false, arithmetic.fromConst(memory.getValue().getAsLong(), 4));
            var executor = new PcodeExecutor<byte[]>(language, arithmetic, state,
                PcodeExecutorStatePiece.Reason.EXECUTE_READ);
            var library = PcodeUseropLibrary.<byte[]>nil();
            var frame = executor.begin(new PcodeProgram(language, Arrays.asList(result.code()), library.getSymbols(language)) {});
            int steps = 0, cycles = 0, stalls = 0;
            while (!frame.isFinished() && steps++ < 100000) {
                int index = frame.index();
                if (result.cycleStarts().containsKey(index)) cycles++;
                executor.step(frame, library);
                if (result.stallTargets().containsKey(index) && frame.index() == result.stallTargets().get(index)) stalls++;
            }
            if (!frame.isFinished()) throw new AssertionError(name + " step bound");
            int expectedStalls = c67x && !row.get("amr").getAsBoolean() ? 0 : row.get("stalls").getAsInt();
            equal(expectedStalls, stalls, name + " stalls");
            equal(row.get("cycles").getAsInt(), cycles, name + " pipeline advances");
            equal(row.get("cycles").getAsInt() + expectedStalls, cycles + stalls, name + " elapsed cycles");
            for (var expected : row.getAsJsonObject("expected").entrySet())
                equal(expected.getValue().getAsLong(), arithmetic.toLong(state.getVar(
                    currentProgram.getRegister(expected.getKey()), reason), PcodeArithmetic.Purpose.INSPECT), name + " " + expected.getKey());
            equal(0x9000, arithmetic.toLong(state.getVar(currentProgram.getRegister("PC"), reason),
                PcodeArithmetic.Purpose.INSPECT), name + " return");
            if (c67x && !row.get("amr").getAsBoolean() && !result.stallTargets().isEmpty())
                throw new AssertionError(name + " has a C64x stall edge in C67x mode");
            println("CPU_CASE " + name + " cycles=" + (cycles + stalls) + " stalls=" + stalls);
            count++;

            if (count == 1) {
                new DisassembleCommand(at, new AddressSet(at, at.add(3)), false).applyTo(currentProgram, monitor);
                function.setReturnType(ghidra.program.model.data.UnsignedIntegerDataType.dataType, SourceType.USER_DEFINED);
                C6000PipelineSchedules.enable(currentProgram, function, "Synthetic drained entry", incoming, monitor);
                var context = new InjectContext();
                context.baseAddr = at;
                var injected = new C6000PipelinePayload("cpu-profile-regression").getPcode(currentProgram, context);
                if (injected.length == 0) throw new AssertionError("Missing injected schedule");
                var decompiler = new DecompInterface();
                try {
                    decompiler.setOptions(new DecompileOptions());
                    if (!decompiler.openProgram(currentProgram)) throw new AssertionError(decompiler.getLastMessage());
                    var decompiled = decompiler.decompileFunction(function, 30, monitor);
                    if (!decompiled.decompileCompleted()) throw new AssertionError(decompiled.getErrorMessage());
                    String code = decompiled.getDecompiledFunction().getC();
                    if (code.contains("c6000_pipeline")) throw new AssertionError("Unresolved schedule injection: " + code);
                } finally { decompiler.dispose(); }
                var bytes = new byte[32];currentProgram.getMemory().getBytes(at, bytes);
                var source = new C6000PipelineContracts.SourceWindow(at.getOffset(), 32, C6000PipelineContracts.sha256(bytes));
                var review = C6000PipelineContracts.review(currentProgram, function, "Synthetic drained entry",
                    incoming, List.of(source), monitor);
                String other = currentProgram.getLanguageID().getIdAsString().replace(":" + variant,
                    c67x ? ":default" : ":c67x");
                var wrong = new C6000PipelineContracts.Review(review.schema(), other, review.entry(), review.evidence(),
                    review.previousE1Writes(), review.entrySources(), review.sourceSha256(), review.scheduleSha256(),
                    review.states(), review.operations());
                try {
                    C6000PipelineContracts.record(currentProgram, function, wrong, monitor);
                    throw new AssertionError("Accepted review from another CPU profile");
                } catch (IllegalArgumentException error) {
                    if (!error.getMessage().contains("schedule identity/evidence mismatch")) throw error;
                }
            }
        }
        // Exercise the real conversion script, including its already-analysis no-op.
        String expectedAnalysisId = originalId.substring(0, originalId.lastIndexOf(':') + 1) +
            (c67x ? "c67x-analysis" : "analysis");
        for (int repeat = 0; repeat < 2; repeat++) {
            runScript("C6000UseAnalysisLanguage.java");
            if (!expectedAnalysisId.equals(currentProgram.getLanguageID().getIdAsString()))
                throw new AssertionError("Analysis conversion changed CPU family");
        }
        var first = currentProgram.getFunctionManager().getFunctionAt(toAddr(0x1000));
        var converted = new C6000PipelineCompiler(currentProgram, first).compile();
        if (c67x != converted.stallTargets().isEmpty()) throw new AssertionError("Analysis conversion changed stall model");
        if (!originalId.equals(expectedAnalysisId)) {
            var context = new InjectContext();context.baseAddr = first.getEntryPoint();
            try {
                new C6000PipelinePayload("stale-language-regression").getPcode(currentProgram, context);
                throw new AssertionError("Conversion reused a review from another language");
            } catch (java.io.IOException error) {
                if (!error.getMessage().contains("schedule identity/evidence mismatch")) throw error;
            }
        }
        println("C6000_PIPELINE_CPU_OK cases=" + count + " language=" + originalId + " conversions=2 decompilations=1");
    }
}
