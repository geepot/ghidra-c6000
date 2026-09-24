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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Annotates the code fetched into a C6000 software-pipelined loop buffer.
 *
 * <p>SPKERNEL is an end-of-loading marker, not an architectural branch. The
 * repeat schedule depends on ILC, predicates, stage boundaries and SPMASK;
 * annotating the matching boundaries preserves that relationship without
 * inventing a control-flow edge in Ghidra's decompiler.
 */
public final class C6000SoftwareLoops {

	private static final String CATEGORY = "C6000 Software Loop";
	// The buffer holds at most 14 execute packets (SPRUFE8B section 7.4.1).
	// 1024 bytes generously covers 14 packets including compact headers.
	private static final long MAX_SPAN = 1024;
	private static final String[] UNITS = {
		"L1", "L2", "S1", "S2", "D1", "D2", "M1", "M2"
	};

	private C6000SoftwareLoops() {
	}

	public static final class Result {
		public int paired;
		public int masked;
		public int unmatched;
	}

	/** Annotate disassembled loop instructions in {@code set}; safe to rerun. */
	public static Result annotate(Program program, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		Result result = new Result();
		Listing listing = program.getListing();
		InstructionIterator instructions = listing.getInstructions(set, true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction insn = instructions.next();
			String name = insn.getMnemonicString();
			if (isLoopStart(name)) {
				Instruction kernel = findKernel(listing, insn);
				if (kernel != null) {
					annotatePair(program, insn, kernel);
					result.paired++;
				}
				else {
					result.unmatched++;
				}
			}
			else if (isKernel(name)) {
				// The kernel may be in a newly disassembled address set while
				// its SPLOOP was already disassembled in an earlier pass.
				Instruction start = findStart(listing, insn);
				if (start != null && !set.contains(start.getMinAddress())) {
					annotatePair(program, start, insn);
					result.paired++;
				}
				else if (start == null) {
					result.unmatched++;
				}
			}
			if (name.contains("SPMASK")) {
				int mask = operand(insn);
				String note = "Buffer mask " + unitNames(mask) +
					(name.contains("SPMASKR") ? "; nested loop reload point" : "");
				program.getBookmarkManager().setBookmark(insn.getMinAddress(),
					BookmarkType.INFO, CATEGORY, note);
				result.masked++;
			}
		}
		return result;
	}

	private static void annotatePair(Program program, Instruction start, Instruction kernel) {
		int ii = operand(start);
		int rawDelay = operand(kernel);
		String startName = start.getMnemonicString();
		String kernelName = kernel.getMnemonicString();
		String kind = startName.contains("SPLOOPW") ? "predicate-terminated" :
			"ILC-counted";
		String delay = kernelName.contains("SPKERNELR") ?
			"reload at first epilog cycle" : stageCycle(ii, rawDelay);
		int undecoded = missingBytes(program.getListing(), start, kernel);
		String common = "ii=" + ii + ", " + kind + "; " + delay +
			(undecoded == 0 ? "" : "; " + undecoded + " undecoded body byte(s)");
		if (undecoded == 0) {
			String body = describeBody(program, start, kernel);
			if (body != null) {
				common += "; " + body;
			}
		}
		program.getBookmarkManager().setBookmark(start.getMinAddress(),
			BookmarkType.INFO, CATEGORY,
			"SPLOOP buffer ends at " + kernel.getMinAddress() + "; " + common);
		program.getBookmarkManager().setBookmark(kernel.getMinAddress(),
			BookmarkType.INFO, CATEGORY,
			"SPKERNEL for " + start.getMinAddress() + "; " + common);
	}

	private static String stageCycle(int ii, int encoded) {
		if (ii < 1 || ii > 14) {
			return "post-epilog fetch delay field=0x" +
				Integer.toHexString(encoded) + " (ii outside Table 3-28)";
		}
		int cycleBits = ii == 1 ? 0 : ii == 2 ? 1 :
			ii <= 4 ? 2 : ii <= 8 ? 3 : 4;
		int cycle = encoded & ((1 << cycleBits) - 1);
		// SPRUFE8B Table 3-29: bit 5 carries stage[0], bit 4 carries
		// stage[1], and so on. Cycle bits keep their ordinary bit order.
		int stage = 0;
		for (int bit = 0; bit < 6 - cycleBits; bit++) {
			stage |= ((encoded >>> (5 - bit)) & 1) << bit;
		}
		return "post-epilog fetch delay=(" + stage + " stages, " + cycle + " cycles)";
	}

	private static String describeBody(Program program, Instruction start,
			Instruction kernel) {
		try {
			C6000LoopBuffer buffer = C6000LoopBuffer.fromProgram(program, start, kernel);
			return "source body=" + buffer.bodyStart() + ".." + kernel.getMinAddress() +
				", " + buffer.sourcePackets() + " source execute packet(s), dynlen=" +
				buffer.dynamicLength() + " cycle(s)";
		}
		catch (MemoryAccessException | IllegalArgumentException e) {
			return null;
		}
	}

	private static int operand(Instruction insn) {
		Scalar scalar = insn.getScalar(0);
		return scalar == null ? 0 : (int) scalar.getUnsignedValue();
	}

	private static String unitNames(int mask) {
		StringBuilder out = new StringBuilder();
		for (int bit = 0; bit < UNITS.length; bit++) {
			if ((mask & (1 << bit)) != 0) {
				if (out.length() > 0) {
					out.append(',');
				}
				out.append(UNITS[bit]);
			}
		}
		return out.length() == 0 ? "none" : out.toString();
	}

	private static Instruction findKernel(Listing listing, Instruction start) {
		Instruction previous = start;
		for (Instruction cursor = listing.getInstructionAfter(start.getMinAddress());
				cursor != null && within(start, cursor) && adjacent(previous, cursor);
				cursor = listing.getInstructionAfter(cursor.getMinAddress())) {
			String name = cursor.getMnemonicString();
			if (isKernel(name)) {
				return cursor;
			}
			if (isLoopStart(name)) {
				return null;
			}
			previous = cursor;
		}
		return null;
	}

	private static Instruction findStart(Listing listing, Instruction kernel) {
		Instruction next = kernel;
		for (Instruction cursor = listing.getInstructionBefore(kernel.getMinAddress());
				cursor != null && within(cursor, kernel) && adjacent(cursor, next);
				cursor = listing.getInstructionBefore(cursor.getMinAddress())) {
			String name = cursor.getMnemonicString();
			if (isLoopStart(name)) {
				return cursor;
			}
			if (isKernel(name)) {
				return null;
			}
			next = cursor;
		}
		return null;
	}

	private static boolean isLoopStart(String name) {
		return name.contains("SPLOOP") && !name.contains("SPKERNEL");
	}

	private static boolean isKernel(String name) {
		return name.contains("SPKERNEL");
	}

	private static boolean within(Instruction first, Instruction second) {
		return first.getMinAddress().getAddressSpace().equals(
			second.getMinAddress().getAddressSpace()) &&
			second.getMinAddress().getOffset() - first.getMinAddress().getOffset() <= MAX_SPAN;
	}

	private static boolean adjacent(Instruction first, Instruction second) {
		long gap = second.getMinAddress().getOffset() - first.getMaxAddress().getOffset() - 1;
		// A legal but still undecoded 16/32-bit slot can lie inside a buffer.
		// The firmware has these gaps; keep them visible in the bookmark.
		return gap >= 0 && gap <= 4;
	}

	private static int missingBytes(Listing listing, Instruction start, Instruction kernel) {
		int missing = 0;
		Instruction previous = start;
		for (Instruction cursor = listing.getInstructionAfter(start.getMinAddress());
				cursor != null && cursor.getMinAddress().compareTo(kernel.getMinAddress()) <= 0;
				cursor = listing.getInstructionAfter(cursor.getMinAddress())) {
			missing += (int) (cursor.getMinAddress().getOffset() -
				previous.getMaxAddress().getOffset() - 1);
			previous = cursor;
		}
		return missing;
	}
}
