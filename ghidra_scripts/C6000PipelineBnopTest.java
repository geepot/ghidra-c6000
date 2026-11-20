// SPDX-License-Identifier: Apache-2.0
// @category C6000
// SPRUFE8B 4.2.5-4.2.6 and F-17/F-18/F-20/F-21/F-32.
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

public class C6000PipelineBnopTest extends GhidraScript {
    protected void run() throws Exception {
        c6000.C6000PacketContext.prime(currentProgram, monitor);
        var language = (SleighLanguage) currentProgram.getLanguage();
        var arithmetic = BytesPcodeArithmetic.forLanguage(language);
        var reason = PcodeExecutorStatePiece.Reason.INSPECT;
        int checked = 0, literals = 0;
        for (var element : JsonParser.parseString(Files.readString(Paths.get(getScriptArgs()[0]))).getAsJsonArray()) {
            monitor.checkCancelled();
            var row = element.getAsJsonObject();
            String name = row.get("name").getAsString();
            var at = toAddr(row.get("entry").getAsLong());
            var body = new AddressSet(toAddr(row.get("start").getAsLong()), toAddr(row.get("end").getAsLong()-1));
            if (!new DisassembleCommand(at, body, false).applyTo(currentProgram, monitor))
                throw new AssertionError("Cannot disassemble " + name);
            var branch = getInstructionAt(toAddr(row.get("branch").getAsLong()));
            if (branch == null || !branch.getMnemonicString().contains("BNOP"))
                throw new AssertionError("Wrong BNOP: " + branch);
            if (row.get("literal").getAsBoolean()) {
                if (branch.getScalar(1) != null || !branch.toString().replaceAll("\\s+", "").endsWith(",5"))
                    throw new AssertionError("Fixed-five reproducer lost its literal operand: " + branch + " scalar=" + branch.getScalar(1) + " operand=" + branch.getDefaultOperandRepresentation(1));
                literals++;
            } else if (branch.getScalar(1) == null || branch.getScalar(1).getUnsignedValue() != row.get("count").getAsInt())
                throw new AssertionError("Wrong variable count " + branch);
            var function = currentProgram.getFunctionManager().createFunction(name, at, body, SourceType.USER_DEFINED);
            var result = new c6000.C6000PipelineCompiler(currentProgram, function, Set.of()).compile();
            var state = new BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE);
            state.setVar(currentProgram.getAddressFactory().getRegisterSpace().getAddress(0), 0x2100, false, new byte[0x2100]);
            for (var input : row.getAsJsonObject("input").entrySet())
                state.setVar(currentProgram.getRegister(input.getKey()), arithmetic.fromConst(input.getValue().getAsLong(), 4));
            state.setVar(toAddr(0x20000), 4, false, arithmetic.fromConst(0x89abcdefL, 4));
            var executor = new PcodeExecutor<byte[]>(language, arithmetic, state, PcodeExecutorStatePiece.Reason.EXECUTE_READ);
            var library = PcodeUseropLibrary.<byte[]>nil();
            var frame = executor.begin(new PcodeProgram(language, Arrays.asList(result.code()), library.getSymbols(language)) {});
            int steps = 0, cycles = 0;
            while (!frame.isFinished() && steps++ < 100000) {
                if (result.cycleStarts().containsKey(frame.index())) cycles++;
                executor.step(frame, library);
            }
            if (!frame.isFinished()) throw new AssertionError(name + " execution bound");
            if (cycles != row.get("cycles").getAsInt()) throw new AssertionError(name + " cycles=" + cycles);
            for (var expected : row.getAsJsonObject("expected").entrySet()) {
                long actual = arithmetic.toLong(state.getVar(currentProgram.getRegister(expected.getKey()), reason), PcodeArithmetic.Purpose.INSPECT);
                if (actual != expected.getValue().getAsLong()) throw new AssertionError(name + " " + expected.getKey() + "=" + Long.toHexString(actual));
            }
            checked++;
        }
        if (checked != 142 || literals != 28) throw new AssertionError("Incomplete BNOP matrix");
        println("C6000_PIPELINE_BNOP_OK cases=" + checked + " literal=" + literals);
    }
}
