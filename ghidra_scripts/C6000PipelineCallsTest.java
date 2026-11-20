// SPDX-License-Identifier: Apache-2.0
// @category C6000
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.pcode.*;
import ghidra.pcode.exec.*;
import c6000.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
public class C6000PipelineCallsTest extends GhidraScript {
 BytesPcodeArithmetic arithmetic;
 long n(JsonObject row,String key){return row.get(key).getAsLong();}
 long reg(BytesPcodeExecutorState state,String name){return arithmetic.toLong(state.getVar(currentProgram.getRegister(name),PcodeExecutorStatePiece.Reason.INSPECT),PcodeArithmetic.Purpose.INSPECT);}
 long value(BytesPcodeExecutorState state,Varnode node){return arithmetic.toLong(state.getVar(node,PcodeExecutorStatePiece.Reason.INSPECT),PcodeArithmetic.Purpose.INSPECT);}
 void equal(long expected,long actual,String why){if(expected!=actual)throw new AssertionError(why+" expected="+Long.toHexString(expected)+" actual="+Long.toHexString(actual));}
 String hash(long first,long end)throws Exception{long start=first&~31L;byte[] bytes=new byte[(int)(((end+31)&~31L)-start)];currentProgram.getMemory().getBytes(toAddr(start),bytes);return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));}
 C6000PipelineCompiler.TraceWindow window(long owner,long end)throws Exception{return new C6000PipelineCompiler.TraceWindow(owner,owner,end,hash(owner,end));}
 protected void run()throws Exception {
  C6000PacketContext.prime(currentProgram,monitor);arithmetic=BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage());var rows=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonArray();var records=new JsonArray();int accepted=0,refused=0;
  for(var e:rows){var row=e.getAsJsonObject();String name=row.get("name").getAsString(),mode=row.get("mode").getAsString();long c=n(row,"caller"),end=n(row,"caller_end");boolean closed=mode.equals("multi")||mode.equals("closed");
   var body=new AddressSet(toAddr(c),toAddr(end-1));if(!closed)for(var x:row.getAsJsonArray("sites")){var site=x.getAsJsonObject();body.add(toAddr(n(site,"callee")),toAddr(n(site,"callee_end")-1));}
   var function=currentProgram.getFunctionManager().createFunction(name,toAddr(c),body,SourceType.USER_DEFINED);
   if(closed)for(var x:row.getAsJsonArray("sites")){var site=x.getAsJsonObject();long f=n(site,"callee");if(currentProgram.getFunctionManager().getFunctionAt(toAddr(f))==null)currentProgram.getFunctionManager().createFunction(name+"_"+Long.toHexString(f),toAddr(f),new AddressSet(toAddr(f),toAddr(n(site,"callee_end")-1)),SourceType.USER_DEFINED);}
   String oldBody=function.getBody().toString(),oldHash=hash(c,c+0x400);C6000PipelineCompiler.Result schedule;List<C6000PipelineCompiler.ClosedCallBoundary> boundaries=List.of();List<C6000PipelineCompiler.ClosedCallProof> proofs=List.of();
   try{
    if(closed){var plans=new ArrayList<C6000PipelineCompiler.ClosedCallPlan>();for(var x:row.getAsJsonArray("sites")){var site=x.getAsJsonObject();plans.add(new C6000PipelineCompiler.ClosedCallPlan(currentProgram.getLanguageID().getIdAsString(),window(c,end),window(n(site,"callee"),n(site,"callee_end")),c,null,n(site,"call"),n(site,"link"),n(site,"continuation"),n(site,"callee_return"),n(row,"caller_return"),new C6000PipelineCompiler.TraceEntry(true,Set.of()),"Synthetic sequential leaf calls, separate owners and explicit drained entry"));}
     var result=C6000PipelineCompiler.compileClosedCallsTrace(currentProgram,function,plans);schedule=result.schedule();boundaries=result.boundaries();proofs=result.proofs();
    }else schedule=new C6000PipelineCompiler(currentProgram,function).compile();
    if(row.has("refused"))throw new AssertionError("Accepted "+name);accepted++;
   }catch(IllegalArgumentException error){if(!row.has("refused")||!error.getMessage().contains(row.get("refused").getAsString()))throw new AssertionError(name+" unexpected refusal "+error);row.addProperty("error",error.toString());records.add(row);refused++;println("EXPECTED_REFUSAL "+name+" "+error.getMessage());continue;}
   if(!oldBody.equals(function.getBody().toString())||!oldHash.equals(hash(c,c+0x400)))throw new AssertionError("Source/owner changed");
   var state=new BytesPcodeExecutorState(currentProgram.getLanguage(),PcodeStateCallbacks.NONE);for(var register:currentProgram.getLanguage().getRegisters())if(!register.isProcessorContext()&&register.getMinimumByteSize()==4)state.setVar(register,arithmetic.fromConst(0,4));
   for(var x:Map.of("B3",0x9000L,"B15",0x8100L,"A4",0x8200L,"A6",0x12345678L,"B7",0x55L).entrySet())state.setVar(currentProgram.getRegister(x.getKey()),arithmetic.fromConst(x.getValue(),4));state.setVar(toAddr(0x8000),0x400,false,new byte[0x400]);
   if(row.has("input"))for(var x:row.getAsJsonObject("input").entrySet())state.setVar(currentProgram.getRegister(x.getKey()),arithmetic.fromConst(x.getValue().getAsLong(),4));
   if(row.has("memory"))for(var x:row.getAsJsonObject("memory").entrySet())state.setVar(toAddr(Long.parseLong(x.getKey())),4,false,arithmetic.fromConst(x.getValue().getAsLong(),4));
   var lang=(ghidra.app.plugin.processors.sleigh.SleighLanguage)currentProgram.getLanguage();var library=PcodeUseropLibrary.<byte[]>nil();var executor=new PcodeExecutor<byte[]>(lang,arithmetic,state,PcodeExecutorStatePiece.Reason.EXECUTE_READ);var frame=executor.begin(new PcodeProgram(lang,Arrays.asList(schedule.code()),library.getSymbols(lang)){});int operations=0,cycles=0,enters=0,returns=0;var kinds=new ArrayList<String>();
   while(!frame.isFinished()&&operations++<100000){if(schedule.cycleStarts().containsKey(frame.index()))cycles++;for(var point:boundaries)if(point.pcodeIndex()==frame.index()){
     kinds.add(point.kind());equal(point.expectedTarget()==null?0x9000:point.expectedTarget(),value(state,point.capturedTarget()),name+" live link "+point.kind());
     if(point.kind().equals("CALL_ENTER")){enters++;if(mode.equals("multi")&&enters==2)equal(n(row,"memory_word"),arithmetic.toLong(state.getVar(toAddr(0x8200),4,false,PcodeExecutorStatePiece.Reason.INSPECT),PcodeArithmetic.Purpose.INSPECT),name+" first store matured before second callee");var proof=proofs.stream().filter(p->p.callPc()==point.branchPc()).findFirst().orElseThrow();equal(proof.expectedTarget(),value(state,proof.capturedTarget()),name+" E1 destination");}
     if(point.kind().equals("CALL_RETURN")){returns++;if(mode.equals("multi")){equal(1,point.stores().size(),name+" pending return store");equal(2,point.stores().get(0).remainingAdvances(),name+" store remains E1 at return");equal(0x8200,value(state,point.stores().get(0).address()),name+" store E1 address");equal(n(row,"memory_word"),value(state,point.stores().get(0).value()),name+" store E1 value");}}
    }executor.step(frame,library);}
   if(!frame.isFinished())throw new AssertionError(name+" exceeded bound");for(var x:row.getAsJsonObject("expected").entrySet())equal(x.getValue().getAsLong(),reg(state,x.getKey()),name+" "+x.getKey());
   if(row.has("memory_word"))equal(n(row,"memory_word"),arithmetic.toLong(state.getVar(toAddr(0x8200),4,false,PcodeExecutorStatePiece.Reason.INSPECT),PcodeArithmetic.Purpose.INSPECT),name+" store across return");
   if(closed){equal(row.getAsJsonArray("sites").size(),enters,name+" enter count");equal(enters,returns,name+" return count");if(!kinds.get(kinds.size()-1).equals("CALLER_RETURN"))throw new AssertionError("Missing final return");}
   row.addProperty("cycles",cycles);row.addProperty("operations",operations);row.addProperty("executed",true);records.add(row);println("PIPELINE_CALL_CASE "+name+" cycles="+cycles);
  }Files.writeString(Path.of(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().create().toJson(records));println("C6000_PIPELINE_CALLS_OK accepted="+accepted+" refused="+refused);
 }
}
