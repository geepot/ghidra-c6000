// SPDX-License-Identifier: Apache-2.0
// @category C6000
// SPRUFE8B: 16x16 MPY family E2, ADDU/SUBU/SUBC/RCPSP/RSQRSP E1, INTSPU E4; E1 source and predicate capture.
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;

public class C6000PipelineScalarOpsTest extends GhidraScript {
    private BytesPcodeArithmetic arithmetic;

    private BytesPcodeExecutorState initialized(JsonObject row) {
        var state = new BytesPcodeExecutorState(currentProgram.getLanguage(), PcodeStateCallbacks.NONE);
        for (var register : currentProgram.getLanguage().getRegisters()) {
            if (!register.isProcessorContext() && register.getMinimumByteSize() == 4)
                state.setVar(register, arithmetic.fromConst(0, 4));
        }
        state.setVar(currentProgram.getRegister("B3"), arithmetic.fromConst(0x9000, 4));
        for (var item : row.getAsJsonObject("input").entrySet())
            state.setVar(currentProgram.getRegister(item.getKey()), arithmetic.fromConst(item.getValue().getAsLong(), 4));
        return state;
    }

    private void execute(PcodeOp[] code, BytesPcodeExecutorState state, String name) {
        var language = (ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage();
        var executor = new PcodeExecutor<byte[]>(language, BytesPcodeArithmetic.forLanguage(language), state, PcodeExecutorStatePiece.Reason.EXECUTE_READ);
        var library = PcodeUseropLibrary.<byte[]>nil();
        var frame = executor.begin(new PcodeProgram(language, Arrays.asList(code), library.getSymbols(language)) {});
        int steps = 0;
        while (!frame.isFinished() && steps++ < 100000) executor.step(frame, library);
        if (!frame.isFinished()) throw new AssertionError("Step bound: " + name);
    }

    private long value(BytesPcodeExecutorState state, String register) {
        return arithmetic.toLong(state.getVar(currentProgram.getRegister(register),
            PcodeExecutorStatePiece.Reason.INSPECT), PcodeArithmetic.Purpose.INSPECT);
    }

    @Override
    protected void run() throws Exception {
        c6000.C6000PacketContext.prime(currentProgram, monitor);
        arithmetic = BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage());
        var records = new JsonArray();
        int count = 0, rawCount = 0;
        for (var element : JsonParser.parseString(Files.readString(Paths.get(getScriptArgs()[0]))).getAsJsonArray()) {
            var row = element.getAsJsonObject();
            String name = row.get("name").getAsString(), operation = row.get("operation").getAsString();
            var at = toAddr(row.get("entry").getAsLong());
            var function = currentProgram.getFunctionManager().createFunction(name, at,
                new AddressSet(at, at.add(0x7f)), SourceType.USER_DEFINED);
            var packet = at.add(4L * row.get("packet").getAsInt() - 1);
            if (!new DisassembleCommand(at, new AddressSet(at, packet), false).applyTo(currentProgram, monitor))
                throw new AssertionError("Cannot decode " + name);
            Instruction instruction = null;
            for (var candidate : currentProgram.getListing().getInstructions(new AddressSet(at, packet), true)) {
                String mnemonic = candidate.getMnemonicString().replaceFirst("^\\[[^\\]]*\\]", "").trim().replaceFirst("^_", "");
                if (instruction == null && mnemonic.startsWith(operation + ".")) instruction = candidate;
            }
            if (instruction == null) throw new AssertionError("Unexpected decode: " + name);
            row.addProperty("decoded", instruction.toString());

            if (row.has("refused")) {
                boolean refused = false;
                try {
                    c6000.C6000PipelineSchedules.enable(currentProgram, function,
                        "Synthetic drained entry", Set.of(), monitor);
                } catch (IllegalArgumentException error) {
                    if (!error.getMessage().contains(row.get("refused").getAsString())) throw error;
                    refused = true;
                }
                if (!refused) throw new AssertionError("Invalid schedule accepted: " + name);
                var context = currentProgram.getProgramContext().getValue(
                    currentProgram.getRegister("c_schedule_entry"), at, false);
                if (BigInteger.ONE.equals(context)) throw new AssertionError("Refusal mutated entry context");
                count++;
                records.add(row);
                continue;
            }

            // The instruction's own raw p-code against the fixture's independent oracle.
            var rawState = initialized(row);
            execute(instruction.getPcode(false), rawState, name + " raw");
            for (var expected : row.getAsJsonObject("raw").entrySet()) {
                long observed = value(rawState, expected.getKey());
                if (observed != expected.getValue().getAsLong())
                    throw new AssertionError(name + " raw " + expected.getKey() + "=" + Long.toHexString(observed));
            }
            rawCount++;

            var result = new c6000.C6000PipelineCompiler(currentProgram, function).compile();
            var state = initialized(row);
            execute(result.code(), state, name);
            var actual = new JsonObject();
            for (var expected : row.getAsJsonObject("expected").entrySet()) {
                long observed = value(state, expected.getKey());
                if (observed != expected.getValue().getAsLong())
                    throw new AssertionError(name + " " + expected.getKey() + "=" +
                        Long.toHexString(observed) + " expected=" + Long.toHexString(expected.getValue().getAsLong()));
                actual.addProperty(expected.getKey(), observed);
            }
            for (var register : row.getAsJsonArray("match_raw")) {
                String key = register.getAsString();
                if (value(state, key) != value(rawState, key))
                    throw new AssertionError(name + " " + key + "=" + Long.toHexString(value(state, key)) +
                        " raw=" + Long.toHexString(value(rawState, key)));
                actual.addProperty(key, value(state, key));
            }
            row.add("actual", actual);
            row.addProperty("states", result.states());
            row.addProperty("operations", result.code().length);
            records.add(row);
            println("SCALAR_OPS_CASE " + name);
            count++;
        }
        Files.writeString(Paths.get(getScriptArgs()[0] + ".results.json"),
            new GsonBuilder().setPrettyPrinting().create().toJson(records));
        if (count != 333 || rawCount != 330) throw new AssertionError("Incomplete scalar-op matrix");
        println("C6000_PIPELINE_SCALAR_OPS_OK cases=" + count + " raw=" + rawCount);
    }
}
