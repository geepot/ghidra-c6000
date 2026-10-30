// SPDX-License-Identifier: Apache-2.0
// @category C6000
// SPRUFE8B 3.5, 3.6 and Tables 4-6/4-10/4-11; issues #23/#24.
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class C6000DelayedCallTimingTest extends GhidraScript {
    protected void run() throws Exception {
        var args=getScriptArgs();
        var rows=JsonParser.parseString(Files.readString(Path.of(args[1]))).getAsJsonArray();
        if(args[0].equals("prepare")) {
            c6000.C6000PacketContext.prime(currentProgram,monitor);
            for(var element:rows) {
                var row=element.getAsJsonObject();var at=toAddr(row.get("entry").getAsLong());
                if(!row.get("call").getAsBoolean() && !row.get("untyped_return").getAsBoolean()) createData(toAddr(row.get("ret").getAsLong()),DWordDataType.dataType);
                currentProgram.getSymbolTable().addExternalEntryPoint(at);
                var body=new AddressSet(at,at.add(63));
                new DisassembleCommand(at,body,true).applyTo(currentProgram,monitor);
                currentProgram.getFunctionManager().createFunction(row.get("name").getAsString(),at,body,SourceType.USER_DEFINED);
            }
            return;
        }
        if(!args[0].equals("check"))throw new IllegalArgumentException("prepare|check cases.json");
        var cls=Class.forName("c6000.C6000CallAnalyzer$Walker");
        var constructor=cls.getDeclaredConstructor(Program.class);constructor.setAccessible(true);
        var recognize=cls.getDeclaredMethod("recognize",Instruction.class);recognize.setAccessible(true);
        var walker=constructor.newInstance(currentProgram);long before=currentProgram.getModificationNumber();
        var failures=new ArrayList<String>();int accepted=0;
        for(var element:rows) {
            var row=element.getAsJsonObject();String name=row.get("name").getAsString();
            var instruction=getInstructionAt(toAddr(row.get("site").getAsLong()));
            if(instruction==null)throw new AssertionError("Missing branch: "+name);
            var call=recognize.invoke(walker,instruction);boolean expected=row.get("call").getAsBoolean();
            if((call!=null)!=expected)failures.add(name+" verdict expected="+expected+" got="+(call!=null));
            if(call!=null && expected && instruction.getRegister(0)!=null) {
                var method=call.getClass().getDeclaredMethod("target");method.setAccessible(true);
                var target=(ghidra.program.model.address.Address)method.invoke(call);
                if(target==null||target.getOffset()!=row.get("target").getAsLong())failures.add(name+" target="+target);
            }
            if(expected)accepted++;
        }
        if(before!=currentProgram.getModificationNumber())throw new AssertionError("Recognition changed the program");
        if(!failures.isEmpty())throw new AssertionError("Timing proof failures: "+failures);
        for(int repeat=0;repeat<2;repeat++) {
            new c6000.C6000CallAnalyzer().added(currentProgram,currentProgram.getMemory(),monitor,new ghidra.app.util.importer.MessageLog());
            for(var element:rows) {
                var row=element.getAsJsonObject();String name=row.get("name").getAsString();
                var instruction=getInstructionAt(toAddr(row.get("site").getAsLong()));
                if(row.get("call").getAsBoolean()) {
                    var calls=new HashSet<Long>();int references=0;
                    for(var ref:instruction.getReferencesFrom())if(ref.getReferenceType().isCall()){calls.add(ref.getToAddress().getOffset());references++;}
                    if(!instruction.getFlowType().isCall()||!calls.equals(Set.of(row.get("target").getAsLong()))||references!=1)
                        throw new AssertionError(name+" native call refs="+calls+" count="+references);
                    if(getFunctionAt(toAddr(row.get("target").getAsLong()))==null)throw new AssertionError("Missing callee: "+name);
                    if(getFunctionAt(toAddr(row.get("other").getAsLong()))!=null)throw new AssertionError("Spurious target function: "+name);
                } else {
                    if(instruction.getFlowOverride()==FlowOverride.CALL)throw new AssertionError("False native call: "+name);
                    var at=toAddr(row.get("ret").getAsLong());
                    if(getInstructionAt(at)!=null || currentProgram.getMemory().getInt(at)!=0x0200a358 ||
                       (!row.get("untyped_return").getAsBoolean() && getDataAt(at)==null))
                        throw new AssertionError("Return data decoded or removed: "+name);
                }
            }
        }
        println("C6000_DELAYED_CALL_TIMING_OK cases="+rows.size()+" accepted="+accepted+" refused="+(rows.size()-accepted));
    }
}
