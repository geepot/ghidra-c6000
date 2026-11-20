// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Run after auto-analysis of tests/fixtures/jump-table.py, in either endian mode.
// Checks stable override IDs, lossless rehoming, retained detached labels,
// and preservation of an override whose cases differ from the decoded table.
import c6000.C6000JumpTableAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class C6000SwitchOwnershipTest extends GhidraScript {
 Symbol switchAt(Function function,Address at){
  for(Symbol s:currentProgram.getSymbolTable().getSymbols(at)){
   var p=s.getParentNamespace();
   if(s.getName().equals("switch")&&p.getParentNamespace().getParentNamespace().getID()==function.getID())return s;
  }
  throw new AssertionError("Missing switch for "+function.getEntryPoint());
 }
 Map<Long,String> labels(Namespace space){
  Map<Long,String> result=new TreeMap<>();var it=currentProgram.getSymbolTable().getSymbols(space);
  while(it.hasNext()){var s=it.next();result.put(s.getID(),s.getName()+":"+s.getAddress());}return result;
 }
 String listing(){
  StringBuilder b=new StringBuilder();var it=currentProgram.getListing().getInstructions(true);
  while(it.hasNext()){var i=it.next();b.append(i.getAddress()).append(':').append(i).append(':').append(i.getFlowOverride()).append(':').append(Arrays.toString(i.getFlows())).append('\n');}return b.toString();
 }
 protected void run() throws Exception {
  Function owner=getFunctionAt(toAddr(0x1000));Address at=toAddr(0x1018);
  if(owner==null)throw new AssertionError("Missing switch function");
  Symbol marker=switchAt(owner,at);Namespace table=marker.getParentNamespace();
  Map<Long,String> before=labels(table);String code=listing();AddressSet body=new AddressSet(owner.getBody());
  new C6000JumpTableAnalyzer().added(currentProgram,new AddressSet(owner.getEntryPoint()),monitor,new MessageLog());
  if(!before.equals(labels(table))||marker.getID()!=switchAt(owner,at).getID())throw new AssertionError("Repeated analysis rewrote an unchanged override");

  var wrongAt=toAddr(0x1080);var wrongBody=new AddressSet(wrongAt,wrongAt.add(7));
  new DisassembleCommand(wrongAt,wrongBody,false).applyTo(currentProgram,monitor);
  Function wrong=currentProgram.getFunctionManager().getFunctionAt(wrongAt);
  if(wrong==null)wrong=currentProgram.getFunctionManager().createFunction("unrelated_owner",wrongAt,wrongBody,SourceType.USER_DEFINED);
  code=listing();
  table.getSymbol().setNamespace(HighFunction.findCreateOverrideSpace(wrong));
  if(C6000JumpTableAnalyzer.repairDetachedOverrides(currentProgram,monitor,new MessageLog())!=1)throw new AssertionError("Detached table was not rehomed");
  if(!before.equals(labels(table))||switchAt(owner,at).getID()!=marker.getID())throw new AssertionError("Rehoming lost labels or IDs");
  if(!code.equals(listing())||!body.equals(owner.getBody()))throw new AssertionError("Repair changed code or body");

  AddressSet smaller=new AddressSet(body);smaller.deleteRange(at,at.add(3));owner.setBody(smaller);
  if(C6000JumpTableAnalyzer.repairDetachedOverrides(currentProgram,monitor,new MessageLog())!=1)throw new AssertionError("Ownerless table was not retained outside function");
  if(!table.getName(true).startsWith("C6000_detached_switches::")||!before.equals(labels(table)))throw new AssertionError("Detached metadata lost");
  if(C6000JumpTableAnalyzer.repairDetachedOverrides(currentProgram,monitor,new MessageLog())!=0)throw new AssertionError("Repair not idempotent");
  if(!code.equals(listing())||!smaller.equals(owner.getBody()))throw new AssertionError("Repair changed code or body");
  owner.setBody(body);table.getSymbol().setNamespace(HighFunction.findCreateOverrideSpace(owner));

  // A manual case choice differs from the code-derived table: retain it.
  var symtab=currentProgram.getSymbolTable();
  Namespace manual=symtab.createNameSpace(HighFunction.findCreateOverrideSpace(wrong),"jmp_"+at,SourceType.USER_DEFINED);
  symtab.createLabel(at,"switch",manual,SourceType.USER_DEFINED);
  int index=0;for(long value:new long[]{0x1020,0x1040,0x1080})symtab.createLabel(toAddr(value),"case_"+index++,manual,SourceType.USER_DEFINED);
  Map<Long,String> manualBefore=labels(manual);
  if(C6000JumpTableAnalyzer.repairDetachedOverrides(currentProgram,monitor,new MessageLog())!=0||!manualBefore.equals(labels(manual)))throw new AssertionError("Unverified manual table was changed");
  if(!before.equals(labels(table))||!code.equals(listing())||!body.equals(owner.getBody()))throw new AssertionError("Valid switch was changed");
  // Once the duplicate agrees with the recovered cases, retain it outside
  // the wrong function without replacing the existing correct-owner copy.
  var manualSymbols=symtab.getSymbols(manual);Symbol caseTwo=null;
  while(manualSymbols.hasNext()){var s=manualSymbols.next();if(s.getName().equals("case_2"))caseTwo=s;}
  if(caseTwo==null)throw new AssertionError("Missing manual case");caseTwo.delete();
  symtab.createLabel(toAddr(0x1060),"case_2",manual,SourceType.USER_DEFINED);
  manualBefore=labels(manual);
  if(C6000JumpTableAnalyzer.repairDetachedOverrides(currentProgram,monitor,new MessageLog())!=1||!manualBefore.equals(labels(manual)))throw new AssertionError("Verified duplicate was not retained losslessly");
  if(!manual.getName(true).startsWith("C6000_detached_switches::")||!before.equals(labels(table)))throw new AssertionError("Duplicate replaced valid-owner table");
  println("C6000_SWITCH_OWNERSHIP_OK checks=6");
 }
}
