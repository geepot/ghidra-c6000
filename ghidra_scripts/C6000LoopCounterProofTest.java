// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Prefix proofs may prune impossible exits, never suppress real unit collisions.
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

public class C6000LoopCounterProofTest extends GhidraScript {
    @Override
    protected void run() throws Exception {
        c6000.C6000PacketContext.prime(currentProgram, monitor);
        var arithmetic=BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage());
        var records=new JsonArray();int count=0;
        for(var element:JsonParser.parseString(Files.readString(Paths.get(getScriptArgs()[0]))).getAsJsonArray()) {
            var row=element.getAsJsonObject();String name=row.get("name").getAsString();
            var at=toAddr(row.get("entry").getAsLong());
            var function=currentProgram.getFunctionManager().createFunction(name,at,
                new AddressSet(at,at.add(0x1ff)),SourceType.USER_DEFINED);
            if(row.has("refused")) {
                new DisassembleCommand(at,new AddressSet(at,at.add(3)),false).applyTo(currentProgram,monitor);
                boolean refused=false;
                try {
                    c6000.C6000PipelineSchedules.enable(currentProgram,function,
                        "Synthetic drained entry",Set.of(),monitor);
                } catch(IllegalArgumentException error) {
                    if(!error.getMessage().contains(row.get("refused").getAsString()))throw error;
                    refused=true;
                }
                if(!refused)throw new AssertionError("Invalid schedule accepted: "+name);
                var context=currentProgram.getProgramContext().getValue(
                    currentProgram.getRegister("c_schedule_entry"),at,false);
                if(BigInteger.ONE.equals(context))throw new AssertionError("Refusal mutated entry context");
                records.add(row);count++;continue;
            }
            var result=new c6000.C6000PipelineCompiler(currentProgram,function).compile();
            // the counter comes from memory the executor leaves zero, too many iterations to step
            if(row.has("compile_only")){records.add(row);println("COUNTER_CASE "+name+" compiled");count++;continue;}
            var state=new BytesPcodeExecutorState(currentProgram.getLanguage(),PcodeStateCallbacks.NONE);
            for(var register:currentProgram.getLanguage().getRegisters())
                if(!register.isProcessorContext()&&register.getMinimumByteSize()==4)
                    state.setVar(register,arithmetic.fromConst(0,4));
            state.setVar(currentProgram.getRegister("B3"),arithmetic.fromConst(0x9000,4));
            for(var input:row.getAsJsonObject("input").entrySet())
                state.setVar(currentProgram.getRegister(input.getKey()),arithmetic.fromConst(input.getValue().getAsLong(),4));
            var executor=new PcodeExecutor<byte[]>((ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage(), ghidra.pcode.exec.BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage()), state, PcodeExecutorStatePiece.Reason.EXECUTE_READ);
            var library=PcodeUseropLibrary.<byte[]>nil();
            var frame=executor.begin(new ghidra.pcode.exec.PcodeProgram((ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage(), Arrays.asList(result.code()),library.getSymbols(
                (ghidra.app.plugin.processors.sleigh.SleighLanguage)currentProgram.getLanguage())) {});
            int steps=0,cycles=0,stalls=0;
            while(!frame.isFinished()&&steps++<100000) {
                int index=frame.index();if(result.cycleStarts().containsKey(index))cycles++;
                executor.step(frame,library);
                if(result.stallTargets().containsKey(index)&&frame.index()==result.stallTargets().get(index))stalls++;
            }
            if(!frame.isFinished())throw new AssertionError("Step bound: "+name);
            var actual=new JsonObject();
            for(var expected:row.getAsJsonObject("expected").entrySet()) {
                long value=arithmetic.toLong(state.getVar(currentProgram.getRegister(expected.getKey()),
                    PcodeExecutorStatePiece.Reason.INSPECT),PcodeArithmetic.Purpose.INSPECT);
                if(value!=expected.getValue().getAsLong())throw new AssertionError(name+" "+expected.getKey()+
                    "="+Long.toHexString(value)+" expected="+Long.toHexString(expected.getValue().getAsLong()));
                actual.addProperty(expected.getKey(),value);
            }
            row.add("actual",actual);row.addProperty("cycles",cycles+stalls);
            row.addProperty("states",result.states());row.addProperty("operations",result.code().length);
            records.add(row);println("COUNTER_CASE "+name+" cycles="+(cycles+stalls));count++;
        }
        Files.writeString(Paths.get(getScriptArgs()[0]+".results.json"),
            new GsonBuilder().setPrettyPrinting().create().toJson(records));
        println("C6000_LOOP_COUNTER_PROOF_OK cases="+count);
    }
}
