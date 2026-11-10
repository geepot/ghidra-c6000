// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check 64-bit argument and result storage in a tests/fixtures/abi-pairs.py image.
// Run as preScript with "prepare", then as postScript with no arguments.

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import java.util.Iterator;

public class C6000AbiPairsTest extends GhidraScript {
	private static final long[] ENTRIES = { 0x1000L, 0x102cL, 0x1068L, 0x1084L, 0x1014L, 0x1048L };
	private static final String[] NAMES = { "twice64", "second", "neg64", "callit", "sink", "pass" };
	private static final String[] PROTOS = { "longlong twice64(longlong x)", "double second(int k, double y)",
		"longlong neg64(longlong x)", "longlong callit(longlong x)" };
	private static final String PAIR = "A5:4,A4:4|A5_A4:8";

	@Override
	protected void run() throws Exception {
		if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("prepare")) {
			for (int i = 0; i < ENTRIES.length; i++) {
				currentProgram.getSymbolTable().addExternalEntryPoint(toAddr(ENTRIES[i]));
				disassemble(toAddr(ENTRIES[i]));
				createFunction(toAddr(ENTRIES[i]), NAMES[i]);
			}
			return;
		}
		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		try {
			// Undeclared: pass hands its untouched A4 to sink beside B4 and A6.
			int args = -1;
			for (Iterator<PcodeOpAST> it = decompile(decompiler, 0x1048L).getPcodeOps(); it.hasNext();) {
				PcodeOpAST op = it.next();
				if (op.getOpcode() == PcodeOp.CALL && op.getInput(0).getOffset() == 0x1014L) args = op.getNumInputs() - 1;
			}
			if (args != 3) throw new AssertionError("pass calls sink with " + args + " arguments, expected 3");
			// Declared: a 64-bit argument takes its slot's pair, a 64-bit result A5:A4.
			declare(1, 1);
			Function second = function(0x102cL);
			storage(second.getReturn().getVariableStorage(), PAIR, "second result");
			storage(param(second, 0, 2), "A4:4", "second k");
			storage(param(second, 1, 2), "B5_B4:8", "second y");
			// Undeclared: a result stays 4 bytes in A4, whether computed as two words or as a pair.
			storage(decompile(decompiler, 0x1000L).getFunctionPrototype().getReturnStorage(), "A4:4", "recovered twice64 result");
			storage(decompile(decompiler, 0x1068L).getFunctionPrototype().getReturnStorage(), "A4:4", "recovered neg64 result");
			declare(0, 3);
			Function twice = function(0x1000L);
			storage(twice.getReturn().getVariableStorage(), PAIR, "twice64 result");
			storage(param(twice, 0, 1), "A5_A4:8", "twice64 x");
			HighFunction high = decompile(decompiler, 0x1000L);
			if (high.getFunctionPrototype().getReturnStorage().size() != 8 || ret(high) == null || ret(high).getSize() != 8) {
				throw new AssertionError("twice64 does not return 8 bytes: " + high.getFunctionPrototype().getReturnStorage());
			}
			// The caller passes x through to both callees in A5:A4.
			high = decompile(decompiler, 0x1084L);
			int calls = 0;
			for (Iterator<PcodeOpAST> it = high.getPcodeOps(); it.hasNext();) {
				PcodeOpAST op = it.next();
				if (op.getOpcode() != PcodeOp.CALL) continue;
				long target = op.getInput(0).getOffset();
				if (target != 0x1000L && target != 0x1068L) continue;
				if (op.getNumInputs() != 2 || op.getInput(1).getSize() != 8) {
					throw new AssertionError("callit call to " + Long.toHexString(target) + ": " + op);
				}
				calls++;
			}
			if (calls != 2) throw new AssertionError("callit: " + calls + " calls to neg64/twice64");
			// A 16-byte struct result is returned through a buffer whose address is passed in
			// A3, and x stays in A4; an 8-byte struct result returns in A5:A4 (cl6x 8.3.15 EABI).
			structResult(0x1014L, 16, "A3");
			structResult(0x1048L, 8, null);
			storage(function(0x1048L).getReturn().getVariableStorage(), PAIR, "8-byte struct result");
		}
		finally {
			decompiler.dispose();
		}
		println("C6000_ABI_PAIRS_OK checks=15");
	}

	private void declare(int from, int to) throws Exception {
		CParser parser = new CParser(currentProgram.getDataTypeManager());
		for (int i = from; i <= to; i++) {
			FunctionDefinitionDataType sig = (FunctionDefinitionDataType) parser.parse(PROTOS[i] + ";");
			if (!new ApplyFunctionSignatureCmd(toAddr(ENTRIES[i]), sig, SourceType.USER_DEFINED).applyTo(currentProgram)) {
				throw new AssertionError("cannot apply " + PROTOS[i]);
			}
		}
	}

	/** Declare {@code struct sN f(int x)} at entry; x must be in A4 and the hidden pointer, if any, in register hidden. */
	private void structResult(long entry, int size, String hidden) {
		StructureDataType struct = new StructureDataType("s" + size, 0);
		for (int i = 0; i < size / 4; i++) struct.add(IntegerDataType.dataType, 4, "f" + i, null);
		FunctionDefinitionDataType sig = new FunctionDefinitionDataType("ret" + size);
		sig.setReturnType(struct);
		sig.setArguments(new ParameterDefinition[] { new ParameterDefinitionImpl("x", IntegerDataType.dataType, null) });
		if (!new ApplyFunctionSignatureCmd(toAddr(entry), sig, SourceType.USER_DEFINED).applyTo(currentProgram)) {
			throw new AssertionError("cannot apply struct s" + size + " result");
		}
		Function f = function(entry);
		String hiddenAt = null, x = null;
		for (Parameter p : f.getParameters()) {
			if (p.isAutoParameter()) hiddenAt = p.getRegister() == null ? p.getVariableStorage().toString() : p.getRegister().getName();
			else if (p.getName().equals("x")) x = p.getVariableStorage().toString();
		}
		if (!"A4:4".equals(x) || !java.util.Objects.equals(hidden, hiddenAt)) {
			throw new AssertionError("struct s" + size + " result: x in " + x + ", hidden pointer in " + hiddenAt +
				", expected A4:4 and " + hidden + "; " + f.getSignature());
		}
	}

	private Function function(long entry) {
		Function f = getFunctionAt(toAddr(entry));
		if (f == null) throw new AssertionError("no function at " + Long.toHexString(entry));
		return f;
	}

	private VariableStorage param(Function f, int index, int count) {
		Parameter[] p = f.getParameters();
		if (p.length != count) throw new AssertionError(f.getName() + " has " + p.length + " parameters: " + f.getSignature());
		return p[index].getVariableStorage();
	}

	private HighFunction decompile(DecompInterface decompiler, long entry) {
		DecompileResults r = decompiler.decompileFunction(function(entry), 30, monitor);
		if (!r.decompileCompleted()) throw new AssertionError(Long.toHexString(entry) + ": " + r.getErrorMessage());
		return r.getHighFunction();
	}

	private static Varnode ret(HighFunction high) {
		for (Iterator<PcodeOpAST> it = high.getPcodeOps(); it.hasNext();) {
			PcodeOpAST op = it.next();
			if (op.getOpcode() == PcodeOp.RETURN && op.getNumInputs() > 1) return op.getInput(1);
		}
		return null;
	}

	private static void storage(VariableStorage s, String want, String what) {
		if (s == null || !java.util.Arrays.asList(want.split("\\|")).contains(s.toString())) throw new AssertionError(what + " storage " + s + ", expected " + want);
	}
}
