// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.util.*;

import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.ProgramChangeRecord;

/**
 * The addresses a program changed since the last {@link #take}: code, references (both ends),
 * functions, context, bookmarks, symbols. Delay-window recovery used to re-prove every branch of the
 * program on each pass; this tells it which parts of the program a pass can have affected.
 * A change that names no address (an undo, a language change) is counted as {@link #unplaced}.
 */
final class C6000ChangeTracker implements DomainObjectListener {
	private static final Map<Program, C6000ChangeTracker> TRACKERS =
		Collections.synchronizedMap(new WeakHashMap<>());

	private AddressSet changed = new AddressSet();

	/**
	 * Each function's body as last seen. A body change names the function by its entry; a proof that asked
	 * which function contains an address far from the entry depended on the body itself, old and new.
	 */
	private final Map<Address, AddressSet> bodies = new HashMap<>();
	private java.lang.ref.WeakReference<Program> program = new java.lang.ref.WeakReference<>(null);
	private int unplaced;
	private boolean fresh = true;

	/** The tracker of {@code program}, listening from its first use on. */
	static C6000ChangeTracker of(Program program) {
		synchronized (TRACKERS) {
			C6000ChangeTracker tracker = TRACKERS.get(program);
			if (tracker == null) {
				tracker = new C6000ChangeTracker();
				tracker.program = new java.lang.ref.WeakReference<>(program);
				for (Function f : program.getFunctionManager().getFunctions(true))
					tracker.bodies.put(f.getEntryPoint(), new AddressSet(f.getBody()));
				program.addListener(tracker);
				TRACKERS.put(program, tracker);
			}
			return tracker;
		}
	}

	/** What changed since the last take, and how many changes named no address. */
	record Changes(AddressSetView addresses, int unplaced, boolean fresh) {}

	/** Deliver pending events, then return and reset what changed since the last take. */
	Changes take(Program program) {
		program.flushEvents();
		synchronized (this) {
			Changes changes = new Changes(changed, unplaced, fresh);
			changed = new AddressSet();
			unplaced = 0;
			fresh = false;
			return changes;
		}
	}

	@Override
	public synchronized void domainObjectChanged(DomainObjectChangedEvent event) {
		for (int i = 0; i < event.numRecords(); i++) {
			DomainObjectChangeRecord record = event.getChangeRecord(i);
			if (!(record instanceof ProgramChangeRecord change)) {
				unplaced++;
				continue;
			}
			boolean placed = add(change.getStart(), change.getEnd());
			for (Object value : new Object[] { change.getObject(), change.getOldValue(), change.getNewValue() }) {
				if (value instanceof Reference r) placed |= add(r.getFromAddress(), null) | add(r.getToAddress(), null);
				else if (value instanceof Function f) placed |= function(f);
				else if (value instanceof CodeUnit unit) placed |= add(unit.getMinAddress(), unit.getMaxAddress());
				else if (value instanceof ghidra.program.model.symbol.Symbol symbol) placed |= add(symbol.getAddress(), null);
				else if (value instanceof Address a) placed |= add(a, null);
				else if (value instanceof AddressSetView set) for (AddressRange range : set) placed |= add(range.getMinAddress(), range.getMaxAddress());
			}
			// A function event names the entry; the body it had and has now changed with it.
			if (change.getStart() != null && bodies.containsKey(change.getStart()) &&
				!(change.getObject() instanceof Function)) {
				var f = getFunctionAt(change);
				if (f != null) placed |= function(f);
			}
			if (!placed) unplaced++;
		}
	}

	/** The function whose entry {@code change} names; the program is held weakly, like the tracker map holds it. */
	private Function getFunctionAt(ProgramChangeRecord change) {
		Program p = program.get();
		return p == null || p.isClosed() ? null : p.getFunctionManager().getFunctionAt(change.getStart());
	}

	/** A function changed: its old body (as last seen), its current body and its entry. */
	private boolean function(Function f) {
		Address entry = f.getEntryPoint();
		boolean placed = add(entry, null);
		AddressSet old = bodies.get(entry);
		if (old != null) for (AddressRange range : old) placed |= add(range.getMinAddress(), range.getMaxAddress());
		AddressSet now;
		try {
			now = f.isDeleted() ? null : new AddressSet(f.getBody());
		}
		catch (RuntimeException e) {
			now = null;
		}
		if (now == null) bodies.remove(entry);
		else {
			bodies.put(entry, now);
			for (AddressRange range : now) placed |= add(range.getMinAddress(), range.getMaxAddress());
		}
		return placed;
	}

	private boolean add(Address start, Address end) {
		if (start == null || !start.isMemoryAddress()) return false;
		if (end == null || !end.isMemoryAddress() || !end.getAddressSpace().equals(start.getAddressSpace()) ||
			end.compareTo(start) < 0) end = start;
		changed.add(start, end);
		return true;
	}
}
