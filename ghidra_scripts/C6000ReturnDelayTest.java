// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Return window, target sampling and native decompiler checks. Usage: cases.tsv [baseline].
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
import java.nio.file.*;
import c6000.C6000PacketContext;
public class C6000ReturnDelayTest extends GhidraScript {
 protected void run()throws Exception{
  String[] args=getScriptArgs();boolean baseline=args.length>1;
  C6000PacketContext.prime(currentProgram,monitor);
  currentProgram.getMemory().createInitializedBlock("results",toAddr(0x8000),4096,(byte)0,monitor,false);
  int checked=0;
  for(String row:Files.readAllLines(Paths.get(args[0]))){var f=row.split("\\t");var at=toAddr(Long.parseUnsignedLong(f[0],16));int bytes=Integer.parseInt(f[2]);int length=Integer.parseInt(f[5]);long mask=Long.parseUnsignedLong(f[3],16);
   currentProgram.getProgramContext().setValue(currentProgram.getRegister("c_branch_terminal"),at,at,BigInteger.ONE);
   // The production recovery must discover the hand-counted window, not a test context write.
   int prefix=f.length>6?Integer.parseInt(f[6]):0;
   var functionAt=at.subtract(prefix);
   new DisassembleCommand(functionAt,null,true).applyTo(currentProgram,monitor);
   var branch=currentProgram.getListing().getInstructionAt(at);branch.setFlowOverride(FlowOverride.RETURN);
   ghidra.program.model.address.AddressSetView body=new AddressSet(functionAt,at.add(branch.getLength()-1));
   var function=currentProgram.getFunctionManager().createFunction(f[1],functionAt,body,ghidra.program.model.symbol.SourceType.USER_DEFINED);
   // Exercise preservation of labels, all comment classes and explicit refs.
   var savedAt=at.add(length);var listing=currentProgram.getListing();
   for(int ct=0;ct<5;ct++)listing.setComment(savedAt,ct,"keep "+f[1]+" "+ct);
   var label=currentProgram.getSymbolTable().createLabel(savedAt,"tail_"+f[1],ghidra.program.model.symbol.SourceType.USER_DEFINED);long symbolId=label.getID();
   currentProgram.getReferenceManager().addMemoryReference(savedAt,toAddr(0x803c),ghidra.program.model.symbol.RefType.DATA,ghidra.program.model.symbol.SourceType.USER_DEFINED,-1);
   println("CASE "+f[1]+" initial="+branch+" length="+branch.getLength()+" delay="+currentProgram.getProgramContext().getValue(currentProgram.getRegister("c_flow_delay"),at,false));
   if(!baseline){
    println("REPAIRS "+c6000.C6000DelaySlots.recover(currentProgram,monitor,new ghidra.app.util.importer.MessageLog()));
    branch=currentProgram.getListing().getInstructionAt(at);body=function.getBody();
    if(currentProgram.getSymbolTable().getSymbol(symbolId)==null)throw new AssertionError("Lost label "+f[1]);
    for(int ct=0;ct<5;ct++)if(!("keep "+f[1]+" "+ct).equals(listing.getComment(ct,savedAt)))throw new AssertionError("Lost comment "+f[1]);
    if(currentProgram.getReferenceManager().getReference(savedAt,toAddr(0x803c),-1)==null)throw new AssertionError("Lost reference "+f[1]);
    if(!c6000.C6000DelaySlots.recover(currentProgram,monitor,new ghidra.app.util.importer.MessageLog()).isEmpty())throw new AssertionError("Non-idempotent "+f[1]);
    var actual=currentProgram.getProgramContext().getValue(currentProgram.getRegister("c_flow_delay"),at,false);
    if(actual==null||actual.intValue()!=bytes){for(var dbg:currentProgram.getListing().getInstructions(new AddressSet(at,at.add(24)),true))println("DEBUG "+dbg.getAddress()+" "+dbg+" length="+dbg.getLength()+" delay="+dbg.isInDelaySlot());throw new AssertionError(f[1]+": discovered byte window "+actual+" expected "+bytes);}
   }
   // Ghidra's generic depth parses the slots with the branch context; count bytes instead.
   if(branch.getPrototype().getDelaySlotByteCount()==0&&!baseline)throw new AssertionError(f[1]+": missing native delay slots");
   if(!baseline&&!body.contains(at.add(length+bytes-1)))throw new AssertionError(f[1]+": body omits delay work at "+at+" length="+length+" bytes="+bytes+" "+body);
   if(body.contains(at.add(length+bytes)))throw new AssertionError(f[1]+": consumes guard/next function "+body);
   // Execute the exact listing p-code. Ghidra's generic pseudo-disassembler
   // cannot retain address-specific compact context across native delay slots.
   var arithmetic=ghidra.pcode.exec.BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage());
   var state=new ghidra.pcode.exec.BytesPcodeExecutorState(currentProgram.getLanguage(),ghidra.pcode.exec.PcodeStateCallbacks.NONE);
   var reason=ghidra.pcode.exec.PcodeExecutorStatePiece.Reason.INSPECT;
   for(String reg:new String[]{"AMR","CSR"})state.setVar(currentProgram.getRegister(reg),arithmetic.fromConst(0,4));
   for(String reg:new String[]{"A3","A4","B3","TSR"})state.setVar(currentProgram.getRegister(reg),arithmetic.fromConst(reg.equals("A3")?0x11223344:reg.equals("A4")?0x8000:reg.equals("B3")?0x9000:2,4));
   for(String reg:new String[]{"IRP","NRP"})state.setVar(currentProgram.getRegister(reg),arithmetic.fromConst(0x9000,4));
   state.setVar(toAddr(0x8000),32,false,new byte[32]);
   var executor=new ghidra.pcode.exec.PcodeExecutor<byte[]>((ghidra.app.plugin.processors.sleigh.SleighLanguage) currentProgram.getLanguage(), ghidra.pcode.exec.BytesPcodeArithmetic.forLanguage(currentProgram.getLanguage()), state, ghidra.pcode.exec.PcodeExecutorStatePiece.Reason.EXECUTE_READ);
   executor.execute(ghidra.pcode.exec.PcodeProgram.fromInstruction(branch,true),ghidra.pcode.exec.PcodeUseropLibrary.nil());
   for(int k=0;k<8;k++){int want=(mask&(1L<<k))!=0?0x11223344:0;long actual=arithmetic.toLong(state.getVar(toAddr(0x8000+4*k),4,false,reason),ghidra.pcode.exec.PcodeArithmetic.Purpose.INSPECT);if(actual!=Integer.toUnsignedLong(want))throw new AssertionError(f[1]+": listing pcode store["+k+"]="+Long.toHexString(actual));}
   long pc=arithmetic.toLong(state.getVar(currentProgram.getRegister("PC"),reason),ghidra.pcode.exec.PcodeArithmetic.Purpose.INSPECT);if(pc!=0x9000)throw new AssertionError(f[1]+": listing pcode target="+Long.toHexString(pc));
   if(Integer.parseInt(f[4])==1&&(arithmetic.toLong(state.getVar(currentProgram.getRegister("CSR"),reason),ghidra.pcode.exec.PcodeArithmetic.Purpose.INSPECT)&1)==0)throw new AssertionError(f[1]+": listing pcode omits RINT");
   if(length==4){var emu=new EmulatorHelper(currentProgram);
   try{
    emu.writeRegister("IRP",0x9000);emu.writeRegister("NRP",0x9000);emu.writeRegister("AMR",0);emu.writeRegister("A3",0x11223344);emu.writeRegister("A4",0x8000);emu.writeRegister("B3",0x9000);emu.writeRegister("CSR",0);emu.writeRegister("TSR",2);
    emu.getEmulator().setExecuteAddress(at.getOffset());if(!emu.step(monitor))throw new AssertionError(f[1]+": "+emu.getLastError());
    for(int k=0;k<8;k++){int want=(mask&(1L<<k))!=0?0x11223344:0;byte[] data=emu.readMemory(toAddr(0x8000+4*k),4);int actual=java.nio.ByteBuffer.wrap(data).order(currentProgram.getMemory().isBigEndian()?java.nio.ByteOrder.BIG_ENDIAN:java.nio.ByteOrder.LITTLE_ENDIAN).getInt();if(actual!=want)throw new AssertionError(f[1]+": store["+k+"]="+Integer.toHexString(actual)+" expected="+Integer.toHexString(want));}
    if(emu.getEmulator().getExecuteAddress().getOffset()!=0x9000)throw new AssertionError(f[1]+": return target sampled after delay write");
    if(Integer.parseInt(f[4])==1&&(emu.readRegister("CSR").longValue()&1)==0)throw new AssertionError(f[1]+": RINT omitted");
   }finally{emu.dispose();}}
   int stores=0,transfer=-1,index=0,lastStore=-1;for(var op:branch.getPcode(true)){if(op.getOpcode()==PcodeOp.STORE){stores++;lastStore=index;}if(op.getOpcode()==PcodeOp.RETURN||op.getOpcode()==PcodeOp.BRANCHIND)transfer=index;index++;}
   if(stores!=Long.bitCount(mask)||transfer<lastStore)throw new AssertionError(f[1]+": native store/return order "+stores+" stores");
   var d=new DecompInterface();d.setOptions(new DecompileOptions());d.openProgram(currentProgram);try{var result=d.decompileFunction(function,15,monitor);if(!result.decompileCompleted())throw new AssertionError(f[1]+": "+result.getErrorMessage());}finally{d.dispose();}
   checked++;
  }
  println("C6000_RETURN_DELAY_OK cases="+checked);
 }
}
