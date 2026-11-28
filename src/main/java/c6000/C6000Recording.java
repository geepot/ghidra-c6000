// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SymbolTable;

/**
 * A view of a program that records every address a computation reads through it: what a delay-window
 * proof depended on, so recovery re-proves a branch only when a change touches what its last proof read.
 * <p>
 * The view is a set of dynamic proxies over the program and what it hands out: the listing, memory, the
 * reference, function and symbol managers, the program context and bookmarks, and the instructions,
 * code units, functions and iterators they return. A call records the addresses it is given, the code
 * unit or function it is made on, a function body it returns, a memory range it reads, and the gap a
 * neighbour lookup skips (a new instruction there would change the answer). Reads are kept at
 * fetch-packet granularity (32 bytes). Writes are forwarded to the program unchanged.
 * <p>
 * Each underlying object gets one proxy per recording, so identity comparisons and identity-keyed caches
 * work within a recording. Ghidra entry points that look a program up or reach into its database
 * (AutoAnalysisManager, Disassembler, DecompInterface) must be given {@link #raw} objects.
 */
final class C6000Recording {
	private static final Set<Class<?>> VIEWS = Set.of(Program.class, Listing.class, Memory.class, ReferenceManager.class,
		FunctionManager.class, SymbolTable.class, ProgramContext.class, BookmarkManager.class, Instruction.class,
		CodeUnit.class, Data.class, Function.class, InstructionIterator.class, CodeUnitIterator.class,
		FunctionIterator.class, Iterator.class);

	private final AddressSet reads = new AddressSet();
	// Open captures (C6000ReadCache): the reads of each answer being computed, innermost first.
	private final ArrayDeque<AddressSet> captures = new ArrayDeque<>();
	// The last packet range noted: a proof reads the same packets over and over, and adding a range
	// already there still walks the address set's tree. Forgotten when a capture opens or closes, so
	// every open capture holds it.
	private ghidra.program.model.address.AddressSpace lastSpace;
	private long lastLo = 1, lastHi = 0;
	private final IdentityHashMap<Object, Object> views = new IdentityHashMap<>();
	private final Program program;

	C6000Recording(Program program) {
		this.program = (Program) view(raw(program));
	}

	/** The recording view of the program. */
	Program program() {
		return program;
	}

	/** Every address read through the view so far, widened to whole fetch packets. */
	AddressSetView reads() {
		return reads;
	}

	/** The recording {@code object} is a view of; null if it is not one. */
	static C6000Recording of(Object object) {
		if (object != null && Proxy.isProxyClass(object.getClass()) &&
			Proxy.getInvocationHandler(object) instanceof Handler handler) return handler.recording();
		return null;
	}

	/** Start collecting the reads of one computation, for a cache to keep with its answer; see {@link #release}. */
	AddressSet capture() {
		AddressSet set = new AddressSet();
		captures.push(set);
		lastSpace = null;
		return set;
	}

	/** End the capture {@link #capture} began. */
	void release(AddressSet set) {
		captures.remove(set);
		lastSpace = null;
	}

	/** Record {@code set} as read: what a cached answer read when it was computed. */
	void replay(AddressSetView set) {
		reads.add(set);
		for (AddressSet open : captures) open.add(set);
	}

	/** The recording view of {@code object}, if it came from this or another recording's program. */
	@SuppressWarnings("unchecked")
	<T> T view(T object) {
		Object target = raw(object);
		if (target == null || !viewed(target)) return object;
		return (T) views.computeIfAbsent(target, t -> Proxy.newProxyInstance(C6000Recording.class.getClassLoader(),
			interfaces(t.getClass()), new Handler(t)));
	}

	/** The object behind a recording view; {@code object} itself if it is not one. */
	@SuppressWarnings("unchecked")
	static <T> T raw(T object) {
		if (object != null && Proxy.isProxyClass(object.getClass()) &&
			Proxy.getInvocationHandler(object) instanceof Handler handler) return (T) handler.target;
		return object;
	}

	private static boolean viewed(Object target) {
		return VIEWED.get(target.getClass());
	}

	// Whether objects of a class get a view: asked for every result of an interface type (every Address,
	// too), so answered once per class rather than by testing each of VIEWS.
	private static final ClassValue<Boolean> VIEWED = new ClassValue<>() {
		@Override
		protected Boolean computeValue(Class<?> type) {
			for (Class<?> view : VIEWS) if (view.isAssignableFrom(type)) return true;
			return false;
		}
	};

	private static final Map<Class<?>, Class<?>[]> INTERFACES = new java.util.concurrent.ConcurrentHashMap<>();

	private static Class<?>[] interfaces(Class<?> type) {
		return INTERFACES.computeIfAbsent(type, t -> {
			Set<Class<?>> all = new LinkedHashSet<>();
			for (Class<?> c = t; c != null; c = c.getSuperclass()) collect(c, all);
			all.removeIf(i -> !Modifier.isPublic(i.getModifiers()));
			return all.toArray(Class<?>[]::new);
		});
	}

	private static void collect(Class<?> type, Set<Class<?>> all) {
		for (Class<?> i : type.getInterfaces()) if (all.add(i)) collect(i, all);
	}

	private void note(Address from, Address to) {
		if (from == null || !from.isMemoryAddress()) return;
		if (to == null || !to.getAddressSpace().equals(from.getAddressSpace()) || to.compareTo(from) < 0) to = from;
		var space = from.getAddressSpace();
		long lo = from.getOffset() & ~31L, hi = to.getOffset() | 31L;
		lo = Math.max(lo, space.getMinAddress().getOffset());
		hi = Math.min(hi, space.getMaxAddress().getOffset());
		if (space == lastSpace && lo >= lastLo && hi <= lastHi) return;
		lastSpace = space; lastLo = lo; lastHi = hi;
		Address min = from.getNewAddress(lo), max = from.getNewAddress(hi);
		reads.add(min, max);
		for (AddressSet open : captures) open.add(min, max);
	}

	private void note(AddressSetView set) {
		if (set == null) return;
		for (AddressRange range : set) note(range.getMinAddress(), range.getMaxAddress());
	}

	private void note(CodeUnit unit) {
		if (unit != null) note(unit.getMinAddress(), unit.getMaxAddress());
	}

	private final class Handler implements InvocationHandler {
		final Object target;
		Address forward;   // an iterator's last yielded end, for the gaps between its items

		Handler(Object target) {
			this.target = target;
		}

		C6000Recording recording() {
			return C6000Recording.this;
		}

		@Override
		public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
			String name = method.getName();
			if (method.getDeclaringClass() == Object.class) {
				if (name.equals("equals")) return target.equals(raw(args[0]));
				if (name.equals("hashCode")) return target.hashCode();
				if (name.equals("toString")) return target.toString();
			}
			Object[] plain = args == null ? null : args.clone();
			if (plain != null) for (int i = 0; i < plain.length; i++) {
				plain[i] = raw(plain[i]);
				if (plain[i] instanceof Address a) note(a, a);
				else if (plain[i] instanceof AddressSetView set && !(target instanceof Function)) note(set);
			}
			if (target instanceof CodeUnit unit) note(unit);
			else if (target instanceof Function function) note(function.getEntryPoint(), function.getEntryPoint());
			Object result;
			try {
				result = method.invoke(target, plain);
			}
			catch (InvocationTargetException e) {
				throw e.getCause();
			}
			after(name, plain, result);
			return result == null || !method.getReturnType().isInterface() ? result : view(result);
		}

		/** What a result depends on beyond the arguments: a gap skipped, a body returned, memory read. */
		private void after(String name, Object[] args, Object result) {
			Address at = args != null && args.length > 0 && args[0] instanceof Address a ? a : null;
			if (target instanceof Listing) {
				if ((name.equals("getInstructionBefore") || name.equals("getCodeUnitBefore")) && at != null)
					note(result instanceof CodeUnit u ? u.getMinAddress() : at.getAddressSpace().getMinAddress(), at);
				else if ((name.equals("getInstructionAfter") || name.equals("getCodeUnitAfter")) && at != null)
					note(at, result instanceof CodeUnit u ? u.getMaxAddress() : at.getAddressSpace().getMaxAddress());
				else if (result instanceof CodeUnit u) note(u);
				else if (result instanceof Iterator<?> && at != null) {
					// getInstructions(start, forward): the iterator records the gaps it walks over
					Object it = view(result);
					((Handler) Proxy.getInvocationHandler(it)).forward = at;
				}
			}
			else if (target instanceof CodeUnit unit) {
				if (name.equals("getNext"))
					note(unit.getMaxAddress(), result instanceof CodeUnit u ? u.getMaxAddress() : unit.getAddress().getAddressSpace().getMaxAddress());
				else if (name.equals("getPrevious"))
					note(result instanceof CodeUnit u ? u.getMinAddress() : unit.getAddress().getAddressSpace().getMinAddress(), unit.getMinAddress());
			}
			else if (target instanceof Function && result instanceof AddressSetView body) note(body);
			else if (target instanceof Memory && at != null) {
				int length = 8;
				if (args.length > 1 && args[1] instanceof byte[] bytes) length = Math.max(length, bytes.length);
				note(at, at.addWrap(length - 1));
			}
			else if (target instanceof FunctionManager && result instanceof Function f) note(f.getBody());
			else if (target instanceof Iterator<?> && name.equals("hasNext") && Boolean.FALSE.equals(result) && forward != null)
				note(forward, forward.getAddressSpace().getMaxAddress());   // nothing more up to the end
			else if (target instanceof Iterator<?> && name.equals("next") && result instanceof CodeUnit u && forward != null) {
				note(forward, u.getMaxAddress());
				forward = u.getMaxAddress();
			}
			if (result instanceof CodeUnit u) note(u);
		}
	}
}
