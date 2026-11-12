// SPDX-License-Identifier: Apache-2.0
// @category C6000
// SPRUFE8B SAT p.437, Table 2-9, 2.9.13: pair read and dst write in E1, CSR.SAT and SSR one cycle later.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.pcode.exec.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
import c6000.*;

public class C6000PipelineSatTest extends GhidraScript {
    BytesPcodeArithmetic arithmetic;
    void equal(Object expected,Object actual,String why){if(!Objects.equals(expected,actual))throw new AssertionError(why+" expected="+expected+" actual="+actual);}
    BytesPcodeExecutorState initial(JsonObject row){var s=new BytesPcodeExecutorState(currentProgram.getLanguage(),PcodeStateCallbacks.NONE);for(var r:currentProgram.getLanguage().getRegisters())if(!r.isProcessorContext()&&r.getMinimumByteSize()==4)s.setVar(r,arithmetic.fromConst(0,4));for(var x:row.getAsJsonObject("input").entrySet())s.setVar(currentProgram.getRegister(x.getKey()),arithmetic.fromConst(x.getValue().getAsLong(),4));return s;}
    long value(BytesPcodeExecutorState s,String name){return arithmetic.toLong(s.getVar(currentProgram.getRegister(name),PcodeExecutorStatePiece.Reason.INSPECT),PcodeArithmetic.Purpose.INSPECT);}
    void execute(PcodeOp[] code,BytesPcodeExecutorState s){var language=(SleighLanguage)currentProgram.getLanguage();var lib=PcodeUseropLibrary.<byte[]>nil();var e=new PcodeExecutor<byte[]>(language,arithmetic,s,PcodeExecutorStatePiece.Reason.EXECUTE_READ);var frame=e.begin(new PcodeProgram(language,Arrays.asList(code),lib.getSymbols(language)){});int steps=0;while(!frame.isFinished()&&steps++<100000)e.step(frame,lib);equal(true,frame.isFinished(),"bounded execution");}
    @Override protected void run()throws Exception{
        C6000PacketContext.prime(currentProgram,monitor);arithmetic=BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage());var rows=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonArray();int count=0,refused=0;Set<Long> made=new HashSet<>();
        for(var item:rows){var row=item.getAsJsonObject();long entry=row.get("entry").getAsLong();var at=toAddr(entry);
            if(made.add(entry)){var scope=new AddressSet(at,at.add(0x3f));new DisassembleCommand(at,scope,false).applyTo(currentProgram,monitor);currentProgram.getFunctionManager().createFunction(row.get("name").getAsString(),at,scope,SourceType.USER_DEFINED);}
            var f=currentProgram.getFunctionManager().getFunctionAt(at);
            if(row.has("refused")){boolean rejected=false;try{new C6000PipelineCompiler(currentProgram,f).compile();}catch(IllegalArgumentException error){if(!error.getMessage().contains(row.get("refused").getAsString()))throw error;rejected=true;}equal(true,rejected,row.get("name")+" refused");refused++;continue;}
            var result=new C6000PipelineCompiler(currentProgram,f).compile();var state=initial(row);execute(result.code(),state);
            for(var expected:row.getAsJsonObject("expected").entrySet())equal(expected.getValue().getAsLong(),value(state,expected.getKey()),row.get("name")+" "+expected.getKey());
            count++;
        }
        equal(36,count,"SAT cases");equal(2,refused,"SAT refusals");println("C6000_PIPELINE_SAT_OK cases="+count+" refused="+refused);
    }
}
