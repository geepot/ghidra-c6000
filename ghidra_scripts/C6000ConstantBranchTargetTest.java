// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Run as preScript with "prepare cases.tsv", then postScript with "check cases.tsv".
// Exercises both exact target recovery and conservative handling of uncertain
// predication, execute-packet reads, and alternate entries (SPRUFE8B Table 4-11).
import ghidra.app.script.GhidraScript;
import java.nio.file.*;
import java.util.*;
import c6000.C6000PacketContext;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

public class C6000ConstantBranchTargetTest extends GhidraScript {
 protected void run() throws Exception {
  String[] args=getScriptArgs();
  if(args.length!=2)throw new IllegalArgumentException("prepare|check cases.tsv");
  List<String> rows=Files.readAllLines(Paths.get(args[1]));
  if(args[0].equals("prepare")) {
   currentProgram.getMemory().createUninitializedBlock("high_targets",toAddr(0xc0040000L),0x10000,false);
   currentProgram.getMemory().createUninitializedBlock("low_targets",toAddr(0x11800000L),0x10000,false);
   for(String row:rows){String[] f=row.split("\t");long start=Long.parseUnsignedLong(f[0],16);
    currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(start));
    if(f[4].equals("1"))currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(start+4));
   }
   C6000PacketContext.prime(currentProgram,monitor);
   for(String row:rows){String[] f=row.split("\t");long start=Long.parseUnsignedLong(f[0],16);
    var at=toAddr(start);var body=new AddressSet(at,at.add(31));
    new DisassembleCommand(at,body,true).applyTo(currentProgram,monitor);
    currentProgram.getFunctionManager().createFunction("fixture_"+f[0],at,body,SourceType.USER_DEFINED);
   }
   return;
  }
  if(!args[0].equals("check"))throw new IllegalArgumentException("bad mode");
  int checked=0;
  for(String row:rows){String[] f=row.split("\t");long start=Long.parseUnsignedLong(f[0],16);
   long site=start+Long.parseLong(f[5]);
   var branch=currentProgram.getListing().getInstructionAt(toAddr(site));
   if(branch==null)throw new AssertionError("Missing branch at "+Long.toHexString(site));
   Set<String> targets=new TreeSet<>();for(var a:branch.getFlows())targets.add(a.toString());
   if(f[3].equals("exact")){
    if(!targets.equals(Set.of(f[1])))throw new AssertionError(branch.getAddress()+" expected "+f[1]+" got "+targets);
   }else if(f[3].equals("entered")){
    // The unpredicated MVKH always runs (it is lifted with no guard, issue #101), so the low half
    // alone is no target; the path through the other entry has no known one.
    if(!targets.contains(f[1]))throw new AssertionError(branch.getAddress()+" expected "+f[1]+" among "+targets);
   }else if(!targets.contains(f[2])){
    throw new AssertionError(branch.getAddress()+" uncertain intermediate target discarded: "+targets);
   }
   println("C6000_CONSTANT_BRANCH_CASE "+branch.getAddress()+" "+f[3]+" "+targets);checked++;
  }
  println("C6000_CONSTANT_BRANCH_TARGET_OK cases="+checked);
 }
}
