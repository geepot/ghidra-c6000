// @category C6000
// Independent phase expectations from SPRUFE8B 3.5 and 4.2; synthetic words only.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.pcode.exec.*;
import java.util.*;
public class C6000PipelineSemanticsTest extends GhidraScript {
 record Case(String name,long at,Map<String,Long> input,Map<String,Long> expected,long memory){}
 Map<String,Long> regs(Object...items){Map<String,Long> r=new LinkedHashMap<>();for(int i=0;i<items.length;i+=2)r.put((String)items[i],((Number)items[i+1]).longValue());return r;}
 protected void run()throws Exception{
  c6000.C6000PacketContext.prime(currentProgram,monitor);
  var cases=List.of(new Case("parallel_sticky_saturation",0x2700,regs("A3",0x80000000L,"B5",0x80000000L,"CSR",0x14000100L),regs("A4",0x7fffffff,"B4",0x7fffffff,"CSR",0x14000300L,"SSR",3),0x11223344),
   new Case("incoming_cross_stall",0x1f04,regs("A4",5),regs("B6",5),0x11223344),
   new Case("parallel_old",0x1000,regs("A3",0x44),regs("A4",0x44,"A3",1),0x11223344),
   new Case("mpy_delay",0x1100,regs("A3",0x40000000,"A4",0x40400000,"A5",0x55),regs("A5",0x40c00000,"A6",0x55,"A7",0x40c00000),0x11223344),
   new Case("load_store_old",0x1200,regs("B6",0x22,"A4",0x8000,"B4",0x8000),regs("A5",0x11223344),0x22),
   new Case("store_capture",0x1300,regs("A3",0x44,"A4",0x8000),regs("A3",1),0x44),
   new Case("two_pending_branches",0x1400,regs("A4",0x8000),regs("A3",1,"A4",2,"A5",3,"A6",4),0x11223344),
   new Case("predicate_captured_true",0x1500,regs("B0",1),regs("A4",0x22,"B0",0),0x11223344),
   new Case("predicate_captured_false",0x1500,regs("B0",0),regs("A4",0x11,"B0",0),0x11223344),
   new Case("six_pending_branches",0x1700,regs("A4",0x8000),regs("A5",0x11,"A6",0x12,"A7",0x13,"A8",0x14,"A9",0x15,"A10",0x16),0x11223344),
   new Case("false_pending_write",0x1800,regs("B0",0,"A3",0x40000000,"A4",0x40400000,"A5",0x55),regs("A5",7),0x11223344),
   new Case("late_overwrites_early",0x1900,regs("A3",0x40000000,"A4",0x40400000),regs("A6",9,"A7",0x40c00000),0x11223344),
   new Case("return_target_capture",0x1a00,regs(),regs("B3",0x1234),0x11223344),
   new Case("load_base_e1",0x1b00,regs("A4",0x8000,"A5",0x55),regs("A6",0x8004,"A7",0x22334455),0x11223344),
   new Case("updating_load_alias_phases",0x1e40,regs("A4",0x8000),regs("A4",0x22334455,"A6",0x8004,"A7",0x22334455),0x11223344),
   new Case("doubleword_load",0x1c00,regs("A8",0x8000,"A4",0x44),regs("A4",currentProgram.getMemory().isBigEndian()?0x22334455:0x11223344,"A5",currentProgram.getMemory().isBigEndian()?0x11223344:0x22334455,"A6",0x8010,"A7",0x44),0x11223344),
   new Case("cross_path_stall",0x1d00,regs("A4",0x8000),regs("A6",5,"A5",0x11223344),0x11223344),
   new Case("late_float_flags",0x1600,regs("A3",0x7f7fffff,"A4",0x40000000,"B4",0,"FMCR",0xc0),regs("A5",0x7f800000,"FMCR",0xc0),0x11223344));
  var arith=BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage());var reason=PcodeExecutorStatePiece.Reason.INSPECT;var funcs=new HashMap<Long,ghidra.program.model.listing.Function>();int checked=0;var records=new ArrayList<Object>();
  for(var item:cases){var f=funcs.get(item.at());if(f==null){f=currentProgram.getFunctionManager().createFunction(item.name(),toAddr(item.at()),new AddressSet(toAddr(item.at()),toAddr(item.at()+0x9f)),SourceType.USER_DEFINED);funcs.put(item.at(),f);}var result=new c6000.C6000PipelineCompiler(currentProgram,f,item.name().equals("incoming_cross_stall")?Set.of("A4"):Set.of()).compile();println("SCHEDULE "+item.name()+" states="+result.states()+" ops="+result.code().length);
   var state=new BytesPcodeExecutorState(currentProgram.getLanguage(),PcodeStateCallbacks.NONE);for(var reg:currentProgram.getLanguage().getRegisters())if(!reg.isProcessorContext()&&reg.getMinimumByteSize()==4)state.setVar(reg,arith.fromConst(0,4));state.setVar(currentProgram.getRegister("B3"),arith.fromConst(0x9000,4));for(var e:item.input().entrySet())state.setVar(currentProgram.getRegister(e.getKey()),arith.fromConst(e.getValue(),4));state.setVar(toAddr(0x8000),128,false,new byte[128]);state.setVar(toAddr(0x8000),4,false,arith.fromConst(0x11223344,4));state.setVar(toAddr(0x8004),4,false,arith.fromConst(0x22334455,4));
   var ex=new PcodeExecutor<byte[]>((ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage(), ghidra.pcode.exec.BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage()), state, PcodeExecutorStatePiece.Reason.EXECUTE_READ);var lib=PcodeUseropLibrary.<byte[]>nil();var frame=ex.begin(new ghidra.pcode.exec.PcodeProgram((ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage(), Arrays.asList(result.code()),lib.getSymbols((ghidra.app.plugin.processors.sleigh.SleighLanguage)currentProgram.getLanguage())) {});int steps=0,cycles=0,stalls=0;while(!frame.isFinished()&&steps++<100000){int index=frame.index();if(result.cycleStarts().containsKey(index))cycles++;ex.step(frame,lib);if(result.stallTargets().containsKey(index)&&frame.index()==result.stallTargets().get(index))stalls++;}if(!frame.isFinished())throw new AssertionError("Step bound "+item.name());
   for(var e:item.expected().entrySet()){long actual=arith.toLong(state.getVar(currentProgram.getRegister(e.getKey()),reason),PcodeArithmetic.Purpose.INSPECT);if(actual!=(e.getValue()&0xffffffffL))throw new AssertionError(item.name()+" "+e.getKey()+"="+Long.toHexString(actual)+" expected="+Long.toHexString(e.getValue()));}
   long memory=arith.toLong(state.getVar(toAddr(0x8000),4,false,reason),PcodeArithmetic.Purpose.INSPECT);if(memory!=item.memory())throw new AssertionError(item.name()+" memory="+Long.toHexString(memory));for(int k:new int[]{6,7})if(arith.toLong(state.getVar(toAddr(0x8000+4*k),4,false,reason),PcodeArithmetic.Purpose.INSPECT)!=0)throw new AssertionError("Guard executed "+item.name());
   if(arith.toLong(state.getVar(currentProgram.getRegister("PC"),reason),PcodeArithmetic.Purpose.INSPECT)!=0x9000)throw new AssertionError("Wrong return target");records.add(java.util.Map.of("name",item.name(),"entry",item.at(),"input",item.input(),"expected",item.expected(),"memory",item.memory(),"cycles",cycles+stalls,"stalls",stalls,"oracle_entry",item.name().equals("incoming_cross_stall")?0x1f00:item.at(),"oracle_prefix_cycles",item.name().equals("incoming_cross_stall")?1:0));checked++;
  }
  java.nio.file.Path output=java.nio.file.Paths.get(getScriptArgs()[0]).getParent();java.nio.file.Files.writeString(output.resolve("cases.json"),new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(records));byte[] image=new byte[0x3000];currentProgram.getMemory().getBytes(toAddr(0x1000),image);java.nio.file.Files.write(output.resolve("image.bin"),image);
  var f=funcs.get(0x1000L);f.setReturnType(ghidra.program.model.data.UnsignedIntegerDataType.dataType,SourceType.USER_DEFINED);new ghidra.app.cmd.disassemble.DisassembleCommand(toAddr(0x1000),new AddressSet(toAddr(0x1000),toAddr(0x1003)),false).applyTo(currentProgram,monitor);
  c6000.C6000PipelineSchedules.enable(currentProgram,f,"Synthetic function begins with an empty pipeline",Set.of(),monitor);
  var bodyBefore=new AddressSet(f.getBody());c6000.C6000PipelineSchedules.enable(currentProgram,f,"Synthetic function begins with an empty pipeline",Set.of(),monitor);if(!f.getBody().equals(bodyBefore))throw new AssertionError("Enable not idempotent");
  currentProgram.getFunctionManager().createFunction("foreign_owner",toAddr(0x2200),new AddressSet(toAddr(0x2200),toAddr(0x221f)),SourceType.USER_DEFINED);
  createData(toAddr(0x2304),ghidra.program.model.data.DWordDataType.dataType);
  var rejections=Map.of(0x1e00L,"unimplemented phase contract",0x2000L,"potential simultaneous memory/register writes",0x2100L,"another function",0x2300L,"defined data",0x2400L,"return leaves architectural pipeline effects pending");
  for(var rejection:rejections.entrySet()){
   long address=rejection.getKey();var bad=currentProgram.getFunctionManager().createFunction("refuse_"+address,toAddr(address),new AddressSet(toAddr(address),toAddr(address+0x1f)),SourceType.USER_DEFINED);
   if(!new ghidra.app.cmd.disassemble.DisassembleCommand(toAddr(address),new AddressSet(toAddr(address),toAddr(address+3)),false).applyTo(currentProgram,monitor))throw new AssertionError("Cannot define refusal entry");
   boolean refused=false;try{c6000.C6000PipelineSchedules.enable(currentProgram,bad,"Synthetic empty entry",Set.of(),monitor);}catch(IllegalArgumentException error){if(!error.getMessage().contains(rejection.getValue()))throw new AssertionError("Unexpected refusal "+error);refused=true;}
   if(!refused)throw new AssertionError("Unsupported schedule accepted");var flag=currentProgram.getProgramContext().getValue(currentProgram.getRegister("c_schedule_entry"),toAddr(address),false);if(java.math.BigInteger.ONE.equals(flag))throw new AssertionError("Refusal mutated entry context");
  }
var d=new DecompInterface();d.setOptions(new DecompileOptions());d.openProgram(currentProgram);d.enableDebug(new java.io.File(getScriptArgs()[0]));try{var result=d.decompileFunction(f,30,monitor);if(!result.decompileCompleted())throw new AssertionError(result.getErrorMessage());println(result.getDecompiledFunction().getC());if(result.getDecompiledFunction().getC().contains("return 1;"))throw new AssertionError("Sequential packet semantics leaked into decompiler");}finally{d.dispose();}println("C6000_PIPELINE_SEMANTICS_OK cases="+checked+" rejections="+rejections.size());
 }
}
