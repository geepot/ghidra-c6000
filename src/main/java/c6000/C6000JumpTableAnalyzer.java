/* ###
 * Copyright 2026 ghidra-c6000 contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package c6000;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Comparator;
import java.util.TreeSet;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Recover the TI compiler's switch dispatch through a table of code pointers:
 *
 * <pre>
 *   CMPLTU  N, idx, p           ; guard: p = idx out of range
 *   [!p] MVK/MVKH table, t      ; table base
 *   ADD     t, scaled_idx, t
 *   [!p] LDW *+t(0), r
 *   B/BNOP  r                   ; dispatch; [p] B default is in the delay slots
 * </pre>
 *
 * Ghidra's decompiler finds the table but, with the guard and the predicated
 * loads spread over the delay slots, cannot bound it ("Too many branches").
 * This reads the N+1 entries the guard allows, stopping at the first that
 * is not a code address, adds them as computed-jump references, decodes them and writes a
 * jump-table override so the decompiler emits the switch.
 */
public class C6000JumpTableAnalyzer extends AbstractAnalyzer {
	private static final int MAX_ENTRIES = 256;

	public C6000JumpTableAnalyzer() {
		super("C6000 Jump Tables",
			"Recovers switch tables dispatched by LDW from an MVK/MVKH table and a register branch",
			AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		// The override lives in the function holding the dispatch, so run per
		// new function (including ones a script creates later); the late branch
		// pass calls recover() on new code to decode the cases in the meantime.
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C6000PacketContext.isC6000(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		AddressSet bodies = new AddressSet();
		for (Address entry : set.getAddresses(true)) {
			Function function = program.getFunctionManager().getFunctionAt(entry);
			if (function != null) bodies.add(function.getBody());
		}
		int recovered = recover(program, bodies, monitor, log);
		if (recovered > 0) Msg.info(this, getName() + "> recovered " + recovered + " jump table(s)");
		return true;
	}

	/** Recover the dispatches in {@code region}; returns how many were found. */
	static int recover(Program program, AddressSetView region, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		repairDetachedOverrides(program, monitor, log);
		AddressSetView set = region;
		Listing listing = program.getListing();
		List<Address> branches = new ArrayList<>();
		InstructionIterator instructions = listing.getInstructions(set, true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction insn = instructions.next();
			String op = C6000CallAnalyzer.baseName(insn);
			if ((op.equals("B.S2") || op.equals("BNOP.S2")) && insn.getRegister(0) != null &&
				!C6000PacketStagingAnalyzer.inert(insn) && !"B3".equals(insn.getDefaultOperandRepresentation(0)) &&
				insn.getFlowOverride() == FlowOverride.NONE && C6000PacketStagingAnalyzer.flow(insn).isComputed()) {
				branches.add(insn.getAddress());
			}
		}

		C6000CallAnalyzer.Walker walker = new C6000CallAnalyzer.Walker(program);
		Disassembler disassembler = Disassembler.getDisassembler(program, monitor, null);
		// Fix bodies up in entry order. FunctionDB.hashCode() is the identity hash, so a HashSet
		// visited functions in a different order on each run, and one function's fixed-up body can
		// claim code another's then does not: the same program analyzed twice got different bodies.
		Set<Function> bodies = new TreeSet<>(Comparator.comparing(Function::getEntryPoint));
		int recovered = 0;
		for (Address at : branches) {
			monitor.checkCancelled();
			Instruction branch = listing.getInstructionAt(at);
			if (branch == null) continue;
			List<Address> targets = targets(program, walker, branch);
			if (targets.size() < 2) continue;
			boolean changed = false;
			for (Address target : targets) {
				if (!hasFlowTo(branch, target)) {
					program.getReferenceManager().addMemoryReference(at, target,
						RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0);
					changed = true;
				}
				if (listing.getInstructionAt(target) == null) {
					C6000DelaySlots.announce(program, disassembler.disassemble(target, null, true));
					changed = true;
				}
			}
			Function function = listing.getFunctionContaining(at);
			// Rewriting an existing override or refixing an unchanged body would
			// retrigger function analysis on the same function forever.
			boolean wrote = false;
			if (function != null && !hasOverride(program, function, at)) {
				try {
					new JumpTable(at, new ArrayList<>(targets), true, 0).writeOverride(function);
					wrote = true;
				}
				catch (InvalidInputException e) {
					log.appendMsg("C6000 Jump Tables",
						"no switch override at " + at + ": " + e.getMessage());
				}
			}
			// Only new references or code can change the body.
			if (function != null && changed) bodies.add(function);
			if (changed || wrote) recovered++;
		}
		for (Function function : bodies) {
			monitor.checkCancelled();
			CreateFunctionCmd.fixupFunctionBody(program, function, monitor);
		}
		repairDetachedOverrides(program, monitor, log);
		return recovered;
	}

	/**
	 * A later body repair can leave a generated switch override on its former
	 * owner. Ghidra passes it to the native decompiler even though its branch
	 * is not in that function, which can crash the process. Move only canonical
	 * overrides whose ordered cases still match the recovered TI table. Keep
	 * every label and ID: rehome to the current function, or retain under a
	 * detached namespace when no function owns the branch yet.
	 */
	public static int repairDetachedOverrides(Program program, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		var symbols = program.getSymbolTable();
		// By name, in the order a walk of every symbol finds them: by address, then ID.
		List<Symbol> switches = new ArrayList<>();
		for (Symbol symbol : symbols.getSymbols("switch")) switches.add(symbol);
		switches.sort(java.util.Comparator.comparing(Symbol::getAddress).thenComparingLong(Symbol::getID));
		C6000CallAnalyzer.Walker walker = new C6000CallAnalyzer.Walker(program);
		int repaired = 0;
		for (Symbol symbol : switches) {
			monitor.checkCancelled();
			Function oldOwner = overrideOwner(symbol);
			Address at = symbol.getAddress();
			if (oldOwner == null || oldOwner.getBody().contains(at)) continue;
			Instruction branch = program.getListing().getInstructionAt(at);
			if (branch == null || branch.getRegister(0) == null ||
				"B3".equals(branch.getDefaultOperandRepresentation(0)) ||
				branch.getFlowOverride() != FlowOverride.NONE ||
				!C6000PacketStagingAnalyzer.flow(branch).isComputed()) continue;
			String op = C6000CallAnalyzer.baseName(branch);
			if (!(op.equals("B.S2") || op.equals("BNOP.S2"))) continue;
			List<Address> expected = targets(program, walker, branch);
			Namespace table = symbol.getParentNamespace();
			if (expected.size() < 2 || !matchesRecoveredTable(program, table, at, expected)) continue;
			Function owner = program.getFunctionManager().getFunctionContaining(at);
			try {
				Namespace destination = owner == null ? null : HighFunction.findCreateOverrideSpace(owner);
				// The right owner may already have its own copy. Preserve that
				// copy and retain the detached duplicate outside both functions.
				if (destination == null || symbols.getNamespace(table.getName(), destination) != null) {
					Namespace root = symbols.getNamespace("C6000_detached_switches", program.getGlobalNamespace());
					if (root == null) root = symbols.createNameSpace(program.getGlobalNamespace(),
						"C6000_detached_switches", SourceType.ANALYSIS);
					String name = "from_" + oldOwner.getEntryPoint() + "_" + table.getSymbol().getID();
					destination = symbols.getNamespace(name, root);
					if (destination == null) destination = symbols.createNameSpace(root, name, SourceType.ANALYSIS);
				}
				if (destination == null || symbols.getNamespace(table.getName(), destination) != null) {
					log.appendMsg("C6000 Jump Tables", "retained conflicting detached override at " + at);
					continue;
				}
				table.getSymbol().setNamespace(destination);
				log.appendMsg("C6000 Jump Tables", "retained switch " + at + " outside former owner " + oldOwner.getEntryPoint() + " under " + destination.getName(true));
				repaired++;
			}
			catch (ghidra.util.exception.DuplicateNameException |
					ghidra.program.model.listing.CircularDependencyException | InvalidInputException e) {
				log.appendException(e);
			}
		}
		return repaired;
	}

	private static boolean matchesRecoveredTable(Program program, Namespace table,
			Address at, List<Address> expected) {
		Set<Integer> cases = new HashSet<>();
		boolean hasSwitch = false;
		var symbols = program.getSymbolTable().getSymbols(table);
		while (symbols.hasNext()) {
			Symbol symbol = symbols.next();
			if (symbol.getSymbolType() != ghidra.program.model.symbol.SymbolType.LABEL) return false;
			if (symbol.getName().equals("switch")) {
				if (hasSwitch || !symbol.getAddress().equals(at)) return false;
				hasSwitch = true;
			}
			else {
				if (!symbol.getName().matches("case_[0-9]+")) return false;
				int index;
				try { index = Integer.parseInt(symbol.getName().substring(5)); }
				catch (NumberFormatException e) { return false; }
				if (index >= expected.size() || !cases.add(index) ||
					!symbol.getAddress().equals(expected.get(index))) return false;
			}
		}
		return hasSwitch && cases.size() == expected.size();
	}

	private static Function overrideOwner(Symbol symbol) {
		Namespace table = symbol.getParentNamespace();
		if (table == null || !table.getName().equals("jmp_" + symbol.getAddress())) return null;
		Namespace overrides = table.getParentNamespace();
		if (overrides == null || !overrides.getName().equals("override")) return null;
		Namespace owner = overrides.getParentNamespace();
		return owner instanceof Function ? (Function) owner : null;
	}

	/** An unsigned compare of a value against {@code limit}, setting {@code flag} when it is past it. */
	private record Guard(int at, Register flag, Linear compared, long limit) {}

	/**
	 * A register's value as {@code scale * src + offset}, where {@code src} is that register's
	 * value at path position {@code at}. Compilers bias a switch index whose cases don't start at
	 * zero (compare {@code idx - k}) and fold the bias into the table address ({@code (idx << 2) -
	 * 4k + table}); both are linear in the same {@code idx}.
	 */
	private record Linear(Register src, int at, long scale, long offset) {
		Linear plus(long c) { return new Linear(src, at, scale, offset + c); }
		Linear shifted(int k) { return new Linear(src, at, scale << k, offset << k); }
	}

	/** Where a table address or entry came from: the table, and its byte offset as a linear value. */
	private record Indexed(long table, Linear bytes, int at) {}

	/**
	 * The table entries a register branch dispatches to, or an empty list. The table's bound comes only
	 * from an unsigned compare of the index the table is read with, still unchanged when it is used,
	 * whose result keeps the dispatch from issuing past the bound (SPRUFE8B 3.12 CMPLTU/CMPGTU).
	 */
	static List<Address> targets(Program program, C6000CallAnalyzer.Walker walker,
			Instruction branch) {
		List<Instruction> straight = walker.lookBack(branch);
		List<Address> found = targets(program, walker, branch, straight, -1);
		if (!found.isEmpty()) return found;
		// A switch may set its index and table up and then jump into a dispatch tail. Each jump into
		// the straight-line code gives another path: what precedes the jump, the jump and its delay
		// slots, then the code from its target (SPRUFE8B 4.2.6).
		Listing listing = program.getListing();
		for (int k = straight.size() - 1; k >= 0; k--) {
			Instruction landing = straight.get(k);
			if (landing.getFlowType().isJump() || landing.getFlowType().isTerminal()) break;
			for (Reference ref : program.getReferenceManager().getReferencesTo(landing.getMinAddress())) {
				if (!ref.getReferenceType().isJump()) continue;
				// A latched jump enters where it lands: the path follows the branch itself.
				Instruction jump = walker.entering(listing.getInstructionAt(ref.getFromAddress()), landing.getMinAddress());
				List<Instruction> slots = jump == null ? null : walker.window(jump);
				if (slots == null) continue;
				// What runs before that jump may itself come in through one (Walker.entryPath).
				List<Instruction> path = new ArrayList<>(walker.entryPath(jump, walker.lookBack(jump), true));
				walker.enteredBy = -1;
				int via = path.size();
				path.add(jump);
				path.addAll(slots);
				path.addAll(straight.subList(k, straight.size()));
				found = targets(program, walker, branch, path, via);
				if (!found.isEmpty()) return found;
			}
		}
		return found;
	}

	/**
	 * The table entries {@code branch} dispatches to along {@code lookBack}, the code that issues before
	 * it. With {@code via} at or above zero, the path follows the jump at that index to its target.
	 */
	private static List<Address> targets(Program program, C6000CallAnalyzer.Walker walker,
			Instruction branch, List<Instruction> lookBack, int via) {
		Map<Register, long[]> regs = new HashMap<>();
		Map<Register, Indexed> tableBase = new HashMap<>();	// holds table + a byte offset
		Map<Register, Indexed> loaded = new HashMap<>();	// holds an entry of table
		Map<Register, Linear> linear = new HashMap<>();	// a value derived linearly from another
		// Members of an execute packet read the values from before it, so its linear results
		// land when it ends (SPRUFE8B 3.5); two members may write one register only on
		// complementary predicates (3.8.8), so its value depends on the path and is dropped.
		Map<Register, Linear> packet = new HashMap<>();
		java.util.Set<Register> twice = new java.util.HashSet<>();
		List<Guard> guards = new ArrayList<>();
		List<Instruction> path = new ArrayList<>(lookBack);
		if (via < 0) {
			// The straight line, unless a label in it is reached only by one jump (Walker.entryPath).
			path = new ArrayList<>(walker.entryPath(branch, lookBack));
			via = walker.enteredBy;
			// The path follows that jump like any other: its own predicate is checked below.
			walker.enteredBy = -1;
		}
		List<Instruction> entered = path;
		path = new ArrayList<>(entered);
		path.add(branch);
		int start = walker.reachable(path, via, path.size() - 1);
		if (via >= 0 && start > via) return new ArrayList<>();
		path = new ArrayList<>(entered.subList(start, entered.size()));
		if (via >= 0) via -= start;
		String taken = via < 0 ? null : C6000CallAnalyzer.predicate(path.get(via));
		Register takenFlag = taken == null ? null : program.getRegister(taken.replace("!", ""));
		for (int at = 0; at < path.size(); at++) {
			// The hardware's instruction: one that stages a write or carries a landing is wrapped in
			// the listing, and the wrapper does not have its operands.
			Instruction insn = C6000PacketStagingAnalyzer.hardware(path.get(at));
			// Past the jump the path follows, what is predicated the other way does not run while the
			// flag is unchanged (SPRUFE8B 3.6).
			String own = takenFlag == null || at <= via ? null : C6000CallAnalyzer.predicate(insn);
			if (own != null && own.replace("!", "").equals(takenFlag.getName()) && !own.equals(taken) &&
				walker.unchanged(path, via, at, takenFlag)) {
				endPacket(program, insn, packet, twice, linear);
				continue;
			}
			String op = C6000CallAnalyzer.baseName(insn);
			String name = op.contains(".") ? op.substring(0, op.indexOf('.')) : op;
			int n = insn.getNumOperands();
			Register dst = n > 0 ? insn.getRegister(n - 1) : null;
			Indexed base = null, entryOf = null;
			Linear derived = null;
			if ((name.equals("ADD") || name.equals("ADDAW")) && n == 3) {
				// ADD adds a byte offset to the table, ADDAW a word index (SPRUFE8B 3.12 ADD, ADDAW).
				boolean words = name.equals("ADDAW");
				Register r0 = insn.getRegister(0), r1 = insn.getRegister(1);
				Scalar constant = insn.getScalar(0) != null ? insn.getScalar(0) : insn.getScalar(1);
				if (constant != null && !words && (r0 != null || r1 != null)) {
					Register r = r0 != null ? r0 : r1;
					Indexed held = tableBase.get(r);
					if (held != null && held.bytes() != null)
						base = new Indexed(held.table(), held.bytes().plus(constant.getSignedValue()), at);
					else derived = linearOf(linear, r, at).plus(constant.getSignedValue());
				}
				else if (r0 != null && r1 != null) {
					// Only a plain table constant plus one index: two offsets don't make an entry.
					Long table = tableBase.containsKey(r0) ? null : table(program, regs, tableBase, r0);
					if (table != null) base = indexed(table, linearOf(linear, r1, at), words, at);
					// ADDAW shifts src1, so only its src2 (the base) can be the table.
					else if (!words && !tableBase.containsKey(r1) && (table = table(program, regs, tableBase, r1)) != null)
						base = indexed(table, linearOf(linear, r0, at), false, at);
					else if (!words && constant(regs, r1) != null) derived = linearOf(linear, r0, at).plus(constant(regs, r1));
					else if (!words && constant(regs, r0) != null) derived = linearOf(linear, r1, at).plus(constant(regs, r0));
				}
			}
			else if ((name.equals("SUBAW") || name.equals("SUBAH") || name.equals("SUBAB")) && n == 3 &&
					insn.getRegister(0) != null && insn.getScalar(1) != null) {
				// SUBAx src2,ucst5,dst: src2 less the constant scaled by the access size (SPRUFE8B 3.12 SUBAB/SUBAH/SUBAW).
				int shift = name.equals("SUBAW") ? 2 : name.equals("SUBAH") ? 1 : 0;
				derived = linearOf(linear, insn.getRegister(0), at).plus(-(insn.getScalar(1).getUnsignedValue() << shift));
			}
			else if (name.equals("SUB") && n == 3 && insn.getRegister(0) != null) {
				// SUB idx,K or SUB idx,r with r a known constant (MVK K,r). Written first minus second on
				// every unit: .L/.S src1 - src2, .D (written src2, src1) src2 - src1 (SPRUFE8B 3.12 SUB).
				Long k = insn.getScalar(1) != null ? (Long) insn.getScalar(1).getSignedValue() : constant(regs, insn.getRegister(1));
				if (k != null) derived = linearOf(linear, insn.getRegister(0), at).plus(-k);
			}
			else if (name.equals("SHL") && n == 3 && insn.getRegister(0) != null && insn.getScalar(1) != null &&
				insn.getScalar(1).getUnsignedValue() < 32) {
				derived = linearOf(linear, insn.getRegister(0), at).shifted((int) insn.getScalar(1).getUnsignedValue());
			}
			else if (name.equals("MV") && n == 2 && insn.getRegister(0) != null) {
				derived = linearOf(linear, insn.getRegister(0), at);
			}
			else if (name.equals("ADDK") && n == 2 && insn.getScalar(0) != null && insn.getRegister(1) != null) {
				// ADDK adds a 16-bit constant in place (SPRUFE8B 3.12 ADDK).
				derived = linearOf(linear, insn.getRegister(1), at).plus((short) insn.getScalar(0).getUnsignedValue());
			}
			else if (name.equals("LDW") && n >= 2) {
				// *+table[idx] scales a word index; *table holds table + a byte offset itself. Only the
				// positive-offset form without modification reads at base + offset (SPRUFE8B 3.9.3):
				// *-R subtracts it, and *++R/*--R/*R++/*R-- change R or read at R itself. The 32-bit
				// forms hold the address in one operand; the compact ones list the base and the offset
				// apart and print a zero offset without the plus (*A4[0x0]), so read the mode as printed.
				String text = insn.toString();
				String mode = text.substring(text.indexOf(' ') + 1, text.lastIndexOf(',')).replace(" ", "");
				boolean plain = mode.matches("\\*\\+?[AB][0-9]+(\\[.*\\])?");
				List<Object> address = new ArrayList<>();
				for (int i = 0; i < n - 1; i++) address.addAll(java.util.Arrays.asList(insn.getOpObjects(i)));
				Linear bytes = null;
				Long table = null;
				boolean offset = !plain;
				for (Object o : address) {
					if (o instanceof Scalar s && s.getValue() != 0) offset = true;
					if (!(o instanceof Register r)) continue;
					Long found = table(program, regs, tableBase, r);
					if (found != null && table == null) {
						table = found;
						Indexed held = tableBase.get(r);
						if (held != null) bytes = held.bytes();
					}
					else bytes = linearOf(linear, r, at).shifted(2);
				}
				if (table != null && !offset) entryOf = new Indexed(table, bytes, at);
			}
			else if ((name.equals("CMPLTU") || name.equals("CMPGTU")) && n == 3) {
				// CMPLTU K,idx (K < idx) or CMPGTU idx,K (idx > K) flags an index past K.
				int limitAt = name.equals("CMPLTU") ? 0 : 1;
				Long limit = operandValue(insn, limitAt, regs);
				Register compared = insn.getRegister(1 - limitAt);
				if (limit != null && compared != null && dst != null)
					guards.add(new Guard(at, dst, linearOf(linear, compared, at), limit));
			}
			// A native delay carrier's results include its followers', which come later in this
			// walk as instructions of their own (as Walker.issueWrites counts them).
			if (!insn.getPrototype().hasDelaySlots()) for (Object written : C6000PacketStagingAnalyzer.hardware(insn).getResultObjects()) {
				if (written instanceof Register r) {
					tableBase.remove(r);
					loaded.remove(r);
					if (packet.containsKey(r)) twice.add(r);
					packet.put(r, null);
				}
			}
			walker.track(insn, regs);
			// The path takes the jump, so its predicate held when it issued: under [!R] the flag is
			// zero from here while unchanged, under [R] only nonzero (SPRUFE8B 3.6). Whatever an earlier
			// predicated write left in regs for it no longer stands.
			if (at == via && takenFlag != null) {
				regs.keySet().removeIf(known -> known.getAddress().getAddressSpace().equals(takenFlag.getAddress().getAddressSpace()) &&
					known.getOffset() < takenFlag.getOffset() + takenFlag.getMinimumByteSize() &&
					takenFlag.getOffset() < known.getOffset() + known.getMinimumByteSize());
				if (taken.startsWith("!")) regs.put(takenFlag, new long[] { 0, C6000CallAnalyzer.FULL });
			}
			if (dst != null && base != null) tableBase.put(dst, base);
			if (dst != null && entryOf != null) loaded.put(dst, entryOf);
			if (dst != null && derived != null) packet.put(dst, derived);
			endPacket(program, insn, packet, twice, linear);
		}
		path.add(branch);
		Indexed read = loaded.get(branch.getRegister(0));
		Long bound = null;
		long first = 0;
		// The entry the load reads, as a word index; null unless the byte offset is whole words.
		Linear word = read == null || read.bytes() == null || read.bytes().scale() % 4 != 0 ||
			read.bytes().offset() % 4 != 0 ? null :
			new Linear(read.bytes().src(), read.bytes().at(), read.bytes().scale() / 4, read.bytes().offset() / 4);
		if (word != null && word.scale() == 1) {
			for (Guard guard : guards) {
				// The compare and the load derive from the same index value, in either order: the
				// compared value x = idx + c, the entry read idx + d, so entries d - c .. d - c + K.
				Linear compared = guard.compared();
				if (compared.src().equals(word.src()) && compared.scale() == 1 &&
					walker.unchanged(path, Math.min(compared.at(), word.at()), Math.max(compared.at(), word.at()), word.src()) &&
					(walker.guards(path, guard.at(), guard.flag(), path.size() - 1) ||
						// The path takes the jump: its own predicate is a guard too.
						via > guard.at() && walker.guards(path, guard.at(), guard.flag(), via))) {
					bound = guard.limit();
					first = word.offset() - compared.offset();
				}
			}
		}
		Long table = read == null ? null : read.table();
		List<Address> targets = new ArrayList<>();
		// No guard, no table: reading until a non-code word runs into the next table.
		if (table == null || bound == null) return targets;
		Memory memory = program.getMemory();
		MemoryBlock code = memory.getBlock(branch.getAddress());
		long count = Math.min(bound + 1, MAX_ENTRIES);
		Address entry;
		try { entry = branch.getAddress().getNewAddress(table + 4 * first); }
		catch (ghidra.program.model.address.AddressOutOfBoundsException e) { return targets; }
		for (int i = 0; i < count; i++) {
			try {
				Address target = branch.getAddress().getNewAddress(
					memory.getInt(entry.add(4L * i)) & 0xffffffffL);
				// The guard bounds the table; a word that is not an even address
				// in the dispatching block ends it early.
				if (!code.contains(target) || (target.getOffset() & 1) != 0) break;
				targets.add(target);
			}
			catch (MemoryAccessException | ghidra.program.model.address.AddressOutOfBoundsException e) {
				break;
			}
		}
		return targets;
	}

	/** The linear value a register holds at path position {@code at}: derived, or its own value there. */
	private static Linear linearOf(Map<Register, Linear> linear, Register r, int at) {
		Linear held = linear.get(r);
		return held != null ? held : new Linear(r, at, 1, 0);
	}

	/** A table plus an index, the index a byte offset or (ADDAW) a word index. */
	private static Indexed indexed(long table, Linear index, boolean words, int at) {
		return new Indexed(table, words ? index.shifted(2) : index, at);
	}

	/** A register's known 32-bit constant, signed; null when unknown. */
	private static Long constant(Map<Register, long[]> regs, Register r) {
		long[] value = r == null ? null : regs.get(r);
		return value != null && value[1] == C6000CallAnalyzer.FULL ? (long) (int) value[0] : null;
	}

	/** At the end of {@code insn}'s execute packet, its linear results land (SPRUFE8B 3.5, 3.8.8). */
	private static void endPacket(Program program, Instruction insn, Map<Register, Linear> packet,
			java.util.Set<Register> twice, Map<Register, Linear> linear) {
		boolean ends = true;
		try { ends = !C6000ExecutionPackets.parallelWithNext(program, insn); }
		catch (MemoryAccessException e) { /* the packet ends here */ }
		if (!ends) return;
		for (var e : packet.entrySet()) {
			if (e.getValue() == null || twice.contains(e.getKey())) linear.remove(e.getKey());
			else linear.put(e.getKey(), e.getValue());
		}
		packet.clear();
		twice.clear();
	}

	private static Long operandValue(Instruction insn, int index, Map<Register, long[]> regs) {
		Scalar scalar = insn.getScalar(index);
		if (scalar != null) return scalar.getUnsignedValue();
		long[] value = regs.get(insn.getRegister(index));
		return value != null && value[1] == C6000CallAnalyzer.FULL ? value[0] & 0xffffffffL : null;
	}

	/** Table address held by a register: an in-image constant, or table + index. */
	private static Long table(Program program, Map<Register, long[]> regs,
			Map<Register, Indexed> tableBase, Register r) {
		if (r == null) return null;
		Indexed base = tableBase.get(r);
		if (base != null) return base.table();
		long[] value = regs.get(r);
		if (value == null || value[1] != C6000CallAnalyzer.FULL) return null;
		long address = value[0] & 0xffffffffL;
		try {
			if ((address & 3) == 0 &&
				program.getMemory().contains(program.getAddressFactory()
					.getDefaultAddressSpace().getAddress(address))) {
				return address;
			}
		}
		catch (ghidra.program.model.address.AddressOutOfBoundsException e) {
			return null;
		}
		return null;
	}

	/** True when {@code function} already carries a switch override for the branch at {@code at}. */
	private static boolean hasOverride(Program program, Function function, Address at) {
		for (Symbol symbol : program.getSymbolTable().getSymbols(at)) {
			Function owner = overrideOwner(symbol);
			if (symbol.getName().equals("switch") && owner != null &&
				owner.getID() == function.getID()) return true;
		}
		return false;
	}

	private static boolean hasFlowTo(Instruction branch, Address target) {
		for (Reference ref : branch.getReferencesFrom()) {
			if (ref.getReferenceType().isFlow() && ref.getToAddress().equals(target)) return true;
		}
		return false;
	}
}
