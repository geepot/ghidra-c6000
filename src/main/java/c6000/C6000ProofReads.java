// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

/**
 * What each delay-window proof of a program read last time (C6000Recording), so a pass re-proves only
 * branches, jumps and windows whose reads a change has touched since. Read sets are kept as sorted
 * {@code long[]} range pairs in one address space: some 30,000 proofs on a real image, and an
 * AddressSet each would cost an order of magnitude more memory.
 */
final class C6000ProofReads {
	private static final Map<Program, C6000ProofReads> PROGRAMS = Collections.synchronizedMap(new WeakHashMap<>());

	/** Branch, jump and windowed-instruction proofs. */
	final Map<Address, long[]> lays = new HashMap<>(), jumps = new HashMap<>(), falls = new HashMap<>();

	/** The return each jump's last proof cut (absent: none), and the jumps that cut each return. */
	final Map<Address, Address> cutOf = new HashMap<>();
	final Map<Address, Set<Address>> cutters = new HashMap<>();

	static C6000ProofReads of(Program program) {
		return PROGRAMS.computeIfAbsent(C6000Recording.raw(program), p -> new C6000ProofReads());
	}

	/** Forget everything, as after a change that names no address. */
	void clear() {
		lays.clear();
		jumps.clear();
		falls.clear();
		cutOf.clear();
		cutters.clear();
	}

	static long[] pack(AddressSetView reads) {
		long[] ranges = new long[2 * reads.getNumAddressRanges()];
		int i = 0;
		for (AddressRange range : reads) {
			ranges[i++] = range.getMinAddress().getOffset();
			ranges[i++] = range.getMaxAddress().getOffset();
		}
		return ranges;
	}

	/** True when a proof is missing, or what it read meets {@code changed} (in {@code at}'s space). */
	static boolean stale(long[] ranges, AddressSetView changed, Address at) {
		if (ranges == null) return true;
		for (int i = 0; i < ranges.length; i += 2)
			if (changed.intersects(at.getNewAddress(ranges[i]), at.getNewAddress(ranges[i + 1]))) return true;
		return false;
	}

	/** Record that jump {@code jump} now cuts {@code transfer} (null: none); the returns whose cut changed. */
	List<Address> cut(Address jump, Address transfer) {
		Address old = transfer == null ? cutOf.remove(jump) : cutOf.put(jump, transfer);
		if (Objects.equals(old, transfer)) return List.of();
		if (old != null) {
			var set = cutters.get(old);
			if (set != null && set.remove(jump) && set.isEmpty()) cutters.remove(old);
		}
		if (transfer != null) cutters.computeIfAbsent(transfer, t -> new HashSet<>()).add(jump);
		List<Address> changed = new ArrayList<>(2);
		if (old != null) changed.add(old);
		if (transfer != null) changed.add(transfer);
		return changed;
	}
}
