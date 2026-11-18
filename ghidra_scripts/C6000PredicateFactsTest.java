// SPDX-License-Identifier: Apache-2.0
// @category C6000
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.pcode.exec.*;
import java.util.*;
import java.nio.file.*;
import java.lang.reflect.*;
public class C6000PredicateFactsTest extends GhidraScript {
 static class Fact {long pc;String register;String other;int truth;}
 static class Case {String name;long at;boolean accepted;String refused;long[] a5_values;Map<String,Long> expected;Fact fresh_token;}
 Object component(Object target,String name)throws Exception{var method=target.getClass().getDeclaredMethod(name);method.setAccessible(true);return method.invoke(target);}
 int predicateIndex(String name){return switch(name){case "A0"->0;case "A1"->1;case "A2"->2;case "B0"->3;case "B1"->4;case "B2"->5;default->throw new IllegalArgumentException("not a predicate GPR: "+name);};}
 void verifyFreshToken(c6000.C6000PipelineCompiler compiler,Fact fact)throws Exception{
  Field field=c6000.C6000PipelineCompiler.class.getDeclaredField("states");field.setAccessible(true);Map<?,?> states=(Map<?,?>)field.get(compiler);int found=0;
  for(Object state:states.keySet())if(((Number)component(state,"pc")).longValue()==fact.pc){
   var values=(List<?>)component(component(state,"facts"),"values");Object value=values.get(predicateIndex(fact.register)),other=values.get(predicateIndex(fact.other));
   int truth=((Number)component(value,"truth")).intValue(),token=((Number)component(value,"token")).intValue(),otherToken=((Number)component(other,"token")).intValue();
   if(truth!=fact.truth||token==otherToken)throw new AssertionError("nonzero predicated write did not break value alias at "+Long.toHexString(fact.pc)+": "+fact.register+"="+truth+"/"+token+" "+fact.other+" token="+otherToken);
   found++;
  }
  if(found==0)throw new AssertionError("no compiler state at predicate fact checkpoint "+Long.toHexString(fact.pc));
 }
 protected void run()throws Exception{
  c6000.C6000PacketContext.prime(currentProgram,monitor);var cases=new com.google.gson.Gson().fromJson(Files.readString(Paths.get(getScriptArgs()[0])),Case[].class);int accepted=0,refused=0,executed=0;
  var arithmetic=BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage());var reason=PcodeExecutorStatePiece.Reason.INSPECT;
  for(var item:cases){var function=currentProgram.getFunctionManager().createFunction(item.name,toAddr(item.at),new AddressSet(toAddr(item.at),toAddr(item.at+511)),SourceType.USER_DEFINED);c6000.C6000PipelineCompiler.Result result;
   try{var compiler=new c6000.C6000PipelineCompiler(currentProgram,function);result=compiler.compile();if(!item.accepted)throw new AssertionError("Unsoundly accepted "+item.name);if(item.fresh_token!=null)verifyFreshToken(compiler,item.fresh_token);accepted++;}
   catch(IllegalArgumentException error){String reasonText=item.refused==null?"return leaves architectural pipeline effects pending":item.refused;if(item.accepted||!error.getMessage().contains(reasonText))throw new AssertionError(item.name+" unexpected refusal "+error);println("EXPECTED_REFUSAL "+item.name);refused++;continue;}
   println("SUPPORTED "+item.name+" states="+result.states());
   long[] a5Values=item.a5_values==null?new long[]{0}:item.a5_values;
   for(long initial:new long[]{0,1,0xffffffffL})for(long a5:a5Values){
    var state=new BytesPcodeExecutorState(currentProgram.getLanguage(),PcodeStateCallbacks.NONE);
    for(var register:currentProgram.getLanguage().getRegisters())if(!register.isProcessorContext()&&register.getMinimumByteSize()==4)state.setVar(register,arithmetic.fromConst(0,4));
    for(var entry:Map.of("B0",initial,"A4",0x8000L,"B4",0x8000L,"B3",0x9000L).entrySet())state.setVar(currentProgram.getRegister(entry.getKey()),arithmetic.fromConst(entry.getValue(),4));state.setVar(currentProgram.getRegister("A5"),arithmetic.fromConst(a5,4));
    state.setVar(toAddr(0x8000),128,false,new byte[128]);state.setVar(toAddr(0x8000),4,false,arithmetic.fromConst(0x00010001,4));
    var executor=new PcodeExecutor<byte[]>((ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage(), ghidra.pcode.exec.BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage()), state, PcodeExecutorStatePiece.Reason.EXECUTE_READ);var library=PcodeUseropLibrary.<byte[]>nil();var frame=executor.begin(new ghidra.pcode.exec.PcodeProgram((ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage(), Arrays.asList(result.code()),library.getSymbols((ghidra.app.plugin.processors.sleigh.SleighLanguage)currentProgram.getLanguage())) {});int steps=0;
    while(!frame.isFinished()&&steps++<100000)executor.step(frame,library);if(!frame.isFinished())throw new AssertionError(item.name+" exceeded step bound");
    long pc=arithmetic.toLong(state.getVar(currentProgram.getRegister("PC"),reason),PcodeArithmetic.Purpose.INSPECT);if(pc!=0x9000)throw new AssertionError(item.name+" wrong captured return");
    if(arithmetic.toLong(state.getVar(toAddr(0x8000),4,false,reason),PcodeArithmetic.Purpose.INSPECT)!=0x00010001L)throw new AssertionError("Unexpected memory write");
    if(item.a5_values!=null&&arithmetic.toLong(state.getVar(currentProgram.getRegister("A1"),reason),PcodeArithmetic.Purpose.INSPECT)!=(a5&3))throw new AssertionError(item.name+" wrong AND predicate value");
    if(item.expected!=null)for(var expected:item.expected.entrySet())if(arithmetic.toLong(state.getVar(currentProgram.getRegister(expected.getKey()),reason),PcodeArithmetic.Purpose.INSPECT)!=(expected.getValue()&0xffffffffL))throw new AssertionError(item.name+" wrong "+expected.getKey());
    executed++;
   }
  }
  println("PREDICATE_FACTS_TEST_OK accepted="+accepted+" refused="+refused+" executions="+executed);
 }
}
