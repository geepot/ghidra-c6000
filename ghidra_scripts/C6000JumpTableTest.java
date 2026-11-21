// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check switch-table recovery in an auto-analysed tests/fixtures/jump-table.py image.

import java.util.Set;
import java.util.TreeSet;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class C6000JumpTableTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		for (long entry : new long[] { 0x1200L, 0x1400L, 0x1600L, 0x1800L, 0x1a00L, 0x1c00L, 0x1e00L, 0x2000L, 0x2200L, 0x2400L, 0x2600L }) {
			disassemble(toAddr(entry));
			createFunction(toAddr(entry), null);
		}
		analyzeChanges(currentProgram);
		// Each guarded dispatch gets exactly its three cases: the default branch, the decoy compare
		// and the dispatch's own predicate. The unguarded one gets none.
		check(0x1000L, 0x1018L, 0x1020L, 0x1040L, 0x1060L);
		check(0x1200L, 0x121cL, 0x1240L, 0x1260L, 0x1280L);
		check(0x1400L, 0x1414L, 0x1440L, 0x1460L, 0x1480L);
		check(0x1600L, 0x1614L);
		// A biased index (compare idx - 3, address (idx << 2) - 12 + table), an address built by
		// SHL, a biased copy of another register (no table), and a fold one entry past the compare.
		check(0x1800L, 0x1828L, 0x1840L, 0x1860L, 0x1880L);
		check(0x1a00L, 0x1a20L, 0x1a40L, 0x1a60L, 0x1a80L);
		check(0x1c00L, 0x1c28L);
		check(0x1e00L, 0x1e28L, 0x1e60L, 0x1e80L, 0x1ec0L);
		// The biased copy taken in the packet that shifts the index in place, folded by ADDK;
		// the bias held in a register.
		check(0x2000L, 0x2028L, 0x2040L, 0x2060L, 0x2080L);
		check(0x2200L, 0x222cL, 0x2240L, 0x2260L, 0x2280L);
		// Set up in the delay slots of a jump into the dispatch tail; known-bad 2600 lowers the flag.
		check(0x2400L, 0x248cL, 0x24a0L, 0x24c0L, 0x24e0L);
		check(0x2600L, 0x268cL);
		println("C6000_JUMP_TABLE_OK");
	}

	private void check(long entry, long at, long... cases) throws Exception {
		Instruction dispatch = getInstructionAt(toAddr(at));
		Set<Address> targets = new TreeSet<>();
		for (Reference ref : dispatch.getReferencesFrom()) {
			if (ref.getReferenceType().isFlow() && !ref.getReferenceType().isFallthrough()) targets.add(ref.getToAddress());
		}
		Set<Address> expected = new TreeSet<>();
		for (long c : cases) expected.add(toAddr(c));
		if (!targets.equals(expected)) {
			throw new AssertionError("dispatch at " + toAddr(at) + " targets " + targets + ", expected " + expected);
		}
		if (cases.length == 0) return;
		Function function = getFunctionAt(toAddr(entry));
		for (Address c : expected) {
			if (!function.getBody().contains(c)) throw new AssertionError(c + " not in the switch's function");
		}
		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
		String c = result.getDecompiledFunction() == null ? "" : result.getDecompiledFunction().getC();
		decompiler.dispose();
		if (!c.contains("switch") || c.contains("Could not recover jumptable")) {
			throw new AssertionError("decompiler did not use the switch at " + toAddr(at) + ":\n" + c);
		}
	}
}
