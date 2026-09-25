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

import java.math.BigInteger;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

/**
 * Populates the C6000 SLEIGH context register with the per-slot decode
 * parameters carried by compact fetch-packet header words.
 *
 * <p>A C6000 fetch packet is 32 bytes (eight 32-bit words). A packet is a
 * <em>compact</em> packet exactly when bits 31..28 of its eighth word are
 * {@code 1110} (TI SPRUFE8B section 3.10.2). In that case the eighth word is a
 * <em>header</em> rather than an instruction, and the header's layout field
 * says which of the other seven words hold one 32-bit instruction and which
 * hold two 16-bit compact instructions. The header's expansion field supplies
 * the register set, LD/ST data sizes, saturation and branch-mode parameters
 * that the 16-bit opcodes cannot express.
 *
 * <p>SLEIGH cannot read the header itself: the header sits <em>after</em> the
 * instructions it describes, and a SLEIGH constructor's instruction length is
 * fixed by the tokens it matches, so a decoder that peeked at word 7 would
 * have to declare every compact instruction 32 bytes long. The context
 * register is therefore primed out of band by this class, which the packaged
 * {@link C6000PacketAnalyzer} runs before disassembly.
 *
 * <p>With no context primed, every word decodes as a normal 32-bit
 * instruction - a graceful, if wrong, fallback rather than a hard failure.
 */
public final class C6000PacketContext {

	/** C6000 fetch packets are eight 32-bit words. */
	public static final int FETCH_PACKET_SIZE = 32;

	/** Layout field bit i set means word i holds two 16-bit instructions. */
	private static final int LAYOUT_SHIFT = 21;
	private static final int LAYOUT_MASK = 0x7f;

	private static final int PROT_SHIFT = 20;
	private static final int RS_SHIFT = 19;
	private static final int DSZ_SHIFT = 16;
	private static final int BR_SHIFT = 15;
	private static final int SAT_SHIFT = 14;

	private C6000PacketContext() {
		// static utility
	}

	/**
	 * True if this language is one of the C6000 languages this extension
	 * provides. Language ids look like {@code C6000:LE:32:default}.
	 */
	public static boolean isC6000(Program program) {
		if (program == null || program.getLanguage() == null) {
			return false;
		}
		return "C6000".equals(program.getLanguage().getProcessor().toString());
	}

	/**
	 * Prime the context register for every compact fetch packet that overlaps
	 * an initialized memory block of {@code program}.
	 *
	 * @param program  the program to annotate
	 * @param monitor  a cancellable monitor (may be {@link TaskMonitor#DUMMY})
	 * @return the number of compact fetch packets found
	 */
	public static int prime(Program program, TaskMonitor monitor) throws Exception {
		if (!isC6000(program)) {
			return 0;
		}
		Memory memory = program.getMemory();

		int packets = 0;
		for (MemoryBlock block : memory.getBlocks()) {
			if (!block.isInitialized()) {
				continue;
			}
			Address start = block.getStart();
			long base = start.getOffset() & ~(long) (FETCH_PACKET_SIZE - 1);
			Address cursor = start.getNewAddress(base);
			Address end = block.getEnd();
			while (cursor.compareTo(end) <= 0) {
				if (monitor != null && monitor.isCancelled()) {
					return packets;
				}
				Address hdrAddr = cursor.add(FETCH_PACKET_SIZE - 4);
				if (hdrAddr.compareTo(end) > 0 || !memory.contains(hdrAddr)) {
					cursor = cursor.add(FETCH_PACKET_SIZE);
					continue;
				}
				int header = memory.getInt(hdrAddr);
				if ((header >>> 28) != 0xE) {
					// A noflow context field with no explicit value does not
					// reliably match a SLEIGH c_is16=0 constructor. Prime
					// ordinary words as well as compact ones.
					for (int i = 0; i < 8; i++) {
						Address word = cursor.add(i * 4);
						if (word.compareTo(start) >= 0 && word.compareTo(end) <= 0) {
							setField(program, "c_is16", word, 0);
							setField(program, "c_isheader", word, 0);
							setField(program, "c_pfollow", word, 0);
							primeBranchMode(program, word);
						}
					}
					cursor = cursor.add(FETCH_PACKET_SIZE);
					continue;
				}
				packets++;
				int layout = (header >>> LAYOUT_SHIFT) & LAYOUT_MASK;
				int rs = (header >>> RS_SHIFT) & 1;
				int dsz = (header >>> DSZ_SHIFT) & 7;
				int prot = (header >>> PROT_SHIFT) & 1;
				int br = (header >>> BR_SHIFT) & 1;
				int sat = (header >>> SAT_SHIFT) & 1;
				for (int i = 0; i < 7; i++) {
					Address word = cursor.add(i * 4);
					boolean compact = ((layout >>> i) & 1) == 1;
					setSlot(program, word, compact, rs, dsz, prot, br, sat);
					setField(program, "c_pfollow", word,
						parallelFollowers(header, layout, 2 * i));
					if (compact) {
						setSlot(program, word.add(2), true, rs, dsz, prot, br, sat);
						setField(program, "c_pfollow", word.add(2),
							parallelFollowers(header, layout, 2 * i + 1));
					}
					else {
						// make sure a stale 16-bit marking cannot survive
						setSlot(program, word.add(2), false, 0, 0, 0, 0, 0);
						setField(program, "c_pfollow", word.add(2), 0);
					}
				}
				// The header is a 32-bit CPKT instruction, not a compact slot.
				setField(program, "c_is16", hdrAddr, 0);
				setField(program, "c_isheader", hdrAddr, 1);
				setField(program, "c_pfollow", hdrAddr, 0);
				primeBranchMode(program, hdrAddr);
				cursor = cursor.add(FETCH_PACKET_SIZE);
			}
		}
		return packets;
	}

	/**
	 * Write one context slot.  The fields are written individually rather than
	 * as one packed value on the base context register: Ghidra treats a write
	 * through a context <em>field</em> register as a disassembly-context change,
	 * which is what the SLEIGH matcher consults.
	 */
	private static void setSlot(Program program, Address at,
			boolean is16, int rs, int dsz, int prot, int br, int sat) throws Exception {
		setField(program, "c_is16", at, is16 ? 1 : 0);
		setField(program, "c_isheader", at, 0);
		primeBranchMode(program, at);
		setField(program, "c_rs", at, rs);
		setField(program, "c_dsz", at, dsz);
		setField(program, "c_prot", at, prot);
		setField(program, "c_br", at, br);
		setField(program, "c_sat", at, sat);
	}

	private static void primeBranchMode(Program program, Address at) throws Exception {
		Register field = program.getRegister("c_branch_terminal");
		if (program.getProgramContext().getValue(field, at, false) == null) {
			setField(program, "c_branch_terminal", at, 0);
		}
	}

	/** Number of following instructions in the same execute packet. */
	private static int parallelFollowers(int header, int layout, int halfword) {
		int count = 0;
		while (halfword < 14 && ((header >>> halfword) & 1) != 0) {
			int next = halfword + (((layout >>> (halfword / 2)) & 1) != 0 ? 1 : 2);
			if (next >= 14) break; // word 7 is the header, not an instruction
			count++;
			halfword = next;
		}
		return count;
	}

	private static void setField(Program program, String name, Address at, int value)
			throws Exception {
		Register field = program.getRegister(name);
		if (field == null) {
			throw new IllegalStateException("C6000 language has no context field " + name);
		}
		BigInteger wanted = BigInteger.valueOf(value);
		// A corpus script or analyzer may prime an already disassembled image.
		// Ghidra rejects context writes inside instructions, even if the value
		// is unchanged, so make repeated priming safe.
		if (wanted.equals(program.getProgramContext().getValue(field, at, false))) {
			return;
		}
		program.getProgramContext().setValue(field, at, at,
			wanted);
	}
}
