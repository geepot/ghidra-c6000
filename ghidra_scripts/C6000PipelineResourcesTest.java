// SPDX-License-Identifier: Apache-2.0
// @category C6000
// SPRUFE8B 3.6/3.8.1/3.8.5; SPRU733A 3.6/3.7.1/3.7.4.
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
import c6000.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

public class C6000PipelineResourcesTest extends GhidraScript {
    protected void run() throws Exception {
        C6000PacketContext.prime(currentProgram, monitor);
        var language = (SleighLanguage) currentProgram.getLanguage();
        var arithmetic = BytesPcodeArithmetic.forLanguage(language);
        int executed = 0, refused = 0;
        var records = new JsonArray();
        for (var element : JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonArray()) {
            var row = element.getAsJsonObject();String name = row.get("name").getAsString();
            var at = toAddr(row.get("entry").getAsLong());
            var function = currentProgram.getFunctionManager().createFunction(name, at,
                new AddressSet(at, at.add(127)), SourceType.USER_DEFINED);
            if (!new DisassembleCommand(at, new AddressSet(at, at.add(3)), false).applyTo(currentProgram, monitor))
                throw new AssertionError("Cannot decode " + name);
            if (!row.get("refusal").isJsonNull()) {
                long before = currentProgram.getModificationNumber();
                try {
                    C6000PipelineSchedules.enable(currentProgram, function, "Synthetic drained reset entry", Set.of(), monitor);
                    throw new AssertionError("Invalid physical resource allocation accepted: " + name);
                } catch (IllegalArgumentException expected) {
                    if (!expected.getMessage().contains(row.get("refusal").getAsString()))
                        throw new AssertionError("Wrong refusal for " + name, expected);
                    row.addProperty("observed_refusal", expected.getMessage());
                }
                if (C6000PipelineContracts.isRecorded(currentProgram, function) ||
                    BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(currentProgram.getRegister("c_schedule_entry"), at, false)) ||
                    before != currentProgram.getModificationNumber())
                    throw new AssertionError("Refused allocation changed program: " + name);
                refused++;records.add(row);continue;
            }
            var result = new C6000PipelineCompiler(currentProgram, function).compile(monitor);
            var state = new BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE);
            for (var register : language.getRegisters())
                if (!register.isProcessorContext() && register.getMinimumByteSize() == 4)
                    state.setVar(register, arithmetic.fromConst(0, 4));
            var expected = new HashMap<String, Long>();
            for (String bank : List.of("A", "B")) for (int n = 0; n < 32; n++) expected.put(bank+n, 0L);
            expected.put("B3", 0x9000L);
            for (var input : row.getAsJsonObject("input").entrySet()) expected.put(input.getKey(), input.getValue().getAsLong());
            for (var input : expected.entrySet()) state.setVar(currentProgram.getRegister(input.getKey()), arithmetic.fromConst(input.getValue(), 4));
            for (var input : row.getAsJsonObject("memory").entrySet())
                state.setVar(toAddr(Long.parseLong(input.getKey())), 4, false, arithmetic.fromConst(input.getValue().getAsLong(), 4));
            var executor = new PcodeExecutor<byte[]>(language, arithmetic, state, PcodeExecutorStatePiece.Reason.EXECUTE_READ);
            var library = PcodeUseropLibrary.<byte[]>nil();
            var frame = executor.begin(new PcodeProgram(language, Arrays.asList(result.code()), library.getSymbols(language)) {});
            int steps = 0;
            while (!frame.isFinished() && steps++ < 100000) executor.step(frame, library);
            if (!frame.isFinished()) throw new AssertionError(name + " exceeded step bound");
            for (var output : row.getAsJsonObject("expected").entrySet()) expected.put(output.getKey(), output.getValue().getAsLong());
            expected.put("PC", 0x9000L);
            for (var output : expected.entrySet()) {
                long actual = arithmetic.toLong(state.getVar(currentProgram.getRegister(output.getKey()), PcodeExecutorStatePiece.Reason.INSPECT), PcodeArithmetic.Purpose.INSPECT);
                if (actual != output.getValue()) throw new AssertionError(name + " " + output.getKey() + " expected=" + output.getValue() + " got=" + actual);
            }
            var expectedMemory = row.getAsJsonObject("memory").deepCopy();
            for (var output : row.getAsJsonObject("expected_memory").entrySet()) expectedMemory.add(output.getKey(), output.getValue());
            for (var output : expectedMemory.entrySet()) {
                long actual = arithmetic.toLong(state.getVar(toAddr(Long.parseLong(output.getKey())), 4, false, PcodeExecutorStatePiece.Reason.INSPECT), PcodeArithmetic.Purpose.INSPECT);
                if (actual != output.getValue().getAsLong()) throw new AssertionError(name + " memory " + output.getKey() + " got=" + actual);
            }
            executed++;records.add(row);
        }
        if (executed != 148 || refused != 96) throw new AssertionError("Incomplete resource matrix: " + executed + "/" + refused);
        Files.writeString(Path.of(getScriptArgs()[0] + ".results.json"), new GsonBuilder().setPrettyPrinting().create().toJson(records));
        println("C6000_PIPELINE_RESOURCES_OK cases=" + (executed + refused) + " executed=" + executed + " refused=" + refused);
    }
}
