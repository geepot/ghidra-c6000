// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.function.Supplier;

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

/**
 * A cache of answers computed from the program, cleared when the program changes, that keeps working
 * under delay-window read sets.
 * <p>
 * Each delay-window proof reads through its own {@link C6000Recording}, which records what the proof
 * depended on. A plain cache would skip those reads on a hit, so a later change to them would not
 * re-prove the branch. Here each answer computed inside a recording keeps the reads it made, and a hit
 * inside a recording replays them into it, so the recording sees what it would have seen. Keys are the
 * objects behind the views ({@link C6000Recording#raw}), so one proof's answers serve the next. An
 * answer computed outside any recording has no reads kept: inside a recording it is computed again.
 */
final class C6000ReadCache<K, V> {
	private record Entry<V>(V value, AddressSetView reads) {}

	private Map<K, Entry<V>> answers;
	private final boolean identity;
	private final int capacity;
	private java.lang.ref.WeakReference<Program> of = new java.lang.ref.WeakReference<>(null);
	private long stamp = -1;

	/** {@code identity}: keys compare by identity (instructions), else by equals (addresses). */
	C6000ReadCache(boolean identity, int capacity) {
		this.identity = identity;
		this.answers = fresh();
		this.capacity = capacity;
	}

	private Map<K, Entry<V>> fresh() {
		return identity ? new IdentityHashMap<>() : new HashMap<>();
	}

	/**
	 * The answer for {@code key} in {@code program}; {@code through} is the object the caller reads
	 * through (a recording view or not), and {@code compute} computes the answer through it.
	 */
	synchronized V get(Program program, K key, Object through, Supplier<V> compute) {
		Program owner = C6000Recording.raw(program);
		long now = owner.getModificationNumber();
		if (of.get() != owner || stamp != now || answers.size() > capacity) {
			answers.clear();
			of = new java.lang.ref.WeakReference<>(owner);
			stamp = now;
		}
		K plain = C6000Recording.raw(key);
		C6000Recording recording = C6000Recording.of(through);
		Entry<V> known = answers.get(plain);
		if (known != null && recording == null) return known.value();
		if (known != null && known.reads() != null) {
			recording.replay(known.reads());
			return recording.view(known.value());
		}
		if (recording == null) {
			V value = compute.get();
			answers.put(plain, new Entry<>(C6000Recording.raw(value), null));
			return value;
		}
		AddressSet reads = recording.capture();
		V value;
		try {
			value = compute.get();
		}
		finally {
			recording.release(reads);
		}
		answers.put(plain, new Entry<>(C6000Recording.raw(value), reads));
		return value;
	}
}
