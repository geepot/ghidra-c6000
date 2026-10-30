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
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
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
		return prime(program, null, monitor);
	}

	/** Prime whole fetch packets overlapping a native analyzer's changed byte set. */
	public static int prime(Program program, AddressSetView changed, TaskMonitor monitor) throws Exception {
		if (!isC6000(program)) {
			return 0;
		}
		Memory memory = program.getMemory();
		AddressSetView initialized = memory.getAllInitializedAddressSet();
		AddressSet requested = fetchPackets(changed == null ? initialized : changed);
		// Normalize after intersection: adjacent blocks and disjoint fragments may
		// belong to one physical packet. Block boundaries have no ISA meaning.
		AddressSet scope = fetchPackets(requested.intersect(initialized));

		int packets = 0;
		for (var range : scope.getAddressRanges()) {
			long base = range.getMinAddress().getOffset();
			long last = range.getMaxAddress().getOffset() & ~31L;
			for (long offset = base; offset <= last; offset += FETCH_PACKET_SIZE) {
				if (monitor != null) monitor.checkCancelled();
				Address cursor = range.getMinAddress().getNewAddress(offset);
				Address hdrAddr = cursor.add(FETCH_PACKET_SIZE - 4);
				// A truncated imported fetch packet has no readable compact header.
				// Prime its ordinary words, matching physicalDecodeFields' default.
				boolean completeHeader = initialized.contains(hdrAddr, hdrAddr.add(3));
				int header = completeHeader ? memory.getInt(hdrAddr) : 0;
				if ((header >>> 28) != 0xE) {
					// A noflow context field with no explicit value does not
					// reliably match a SLEIGH c_is16=0 constructor. Prime
					// ordinary words as well as compact ones.
					for (int i = 0; i < 16; i++) {
						Address word = cursor.add(i * 2);
						// Ordinary words need an explicit decode value at their
						// start. Halfwords only need cleanup if they were compact;
						// avoid new context writes inside existing 32-bit instructions.
						boolean staleHalfword = BigInteger.ONE.equals(program.getProgramContext().getValue(
							program.getRegister("c_is16"), word, false));
						if (initialized.contains(word) && ((i & 1) == 0 || staleHalfword)) {
							setField(program, "c_is16", word, 0);
							setField(program, "c_isheader", word, 0);
							setField(program, "c_pfollow", word, 0);
							setField(program, "c_hdrpkt", word, 0);
							primeBranchMode(program, word);
						}
					}
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
					if (initialized.contains(word)) {
						setSlot(program, word, compact, rs, dsz, prot, br, sat);
						setField(program, "c_pfollow", word, parallelFollowers(header, layout, 2 * i));
					}
					if (initialized.contains(word.add(2))) {
						// Clear stale halfword context when a layout changes to full-width.
						setSlot(program, word.add(2), compact, compact ? rs : 0,
							compact ? dsz : 0, compact ? prot : 0, compact ? br : 0, compact ? sat : 0);
						setField(program, "c_pfollow", word.add(2), compact ? parallelFollowers(header, layout, 2 * i + 1) : 0);
					}
				}
				// The header is a 32-bit CPKT instruction, not a compact slot.
				setField(program, "c_is16", hdrAddr, 0);
				setField(program, "c_isheader", hdrAddr, 1);
				setField(program, "c_pfollow", hdrAddr, 0);
				setField(program, "c_hdrpkt", hdrAddr, 1);
				primeBranchMode(program, hdrAddr);
			}
		}
		return packets;
	}

	private static AddressSet fetchPackets(AddressSetView addresses) {
		AddressSet packets = new AddressSet();
		for (var range : addresses.getAddressRanges()) {
			Address first = range.getMinAddress(), last = range.getMaxAddress();
			packets.add(first.getNewAddress(first.getOffset() & ~31L),
				last.getNewAddress((last.getOffset() & ~31L) + 31));
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
		setField(program, "c_hdrpkt", at, 1);
		primeBranchMode(program, at);
		setField(program, "c_rs", at, rs);
		setField(program, "c_dsz", at, dsz);
		setField(program, "c_prot", at, prot);
		setField(program, "c_br", at, br);
		setField(program, "c_sat", at, sat);
	}

	private static void primeBranchMode(Program program, Address at) throws Exception {
		// Native SLEIGH delayslot() counts bytes, not follower instructions.
		// Do not shorten a longer window already proved by the late pass.
		Register delay = program.getRegister("c_flow_delay");
		int bytes = 0;
		try { bytes = C6000ExecutionPackets.parallelBytes(program, at); }
		catch (ghidra.program.model.mem.MemoryAccessException ignored) { }
		BigInteger current = program.getProgramContext().getValue(delay, at, false);
		// Existing programs need the late pass to clear and re-decode a proven
		// window before changing context; never invalidate annotations here.
		if ((current == null || current.intValue() < bytes) &&
		        program.getListing().getInstructionContaining(at) == null) {
		    setField(program, "c_flow_delay", at, bytes);
		}
		Register field = program.getRegister("c_branch_terminal");
		if (program.getProgramContext().getValue(field, at, false) == null) {
			setField(program, "c_branch_terminal", at, 0);
		}
	}

    /** Read-only physical header fields for isolated decoders; never writes ProgramContext. */
    static Map<String,Integer> physicalDecodeFields(Program program,Address at)throws Exception {
        long base=at.getOffset()&~31L;int offset=(int)(at.getOffset()-base);
        Address headerAt=at.getNewAddress(base+28);int header=program.getMemory().getAllInitializedAddressSet().contains(headerAt, headerAt.add(3))?program.getMemory().getInt(headerAt):0;
        if((header>>>28)!=0xe)return Map.of("c_is16",0,"c_isheader",0,"c_hdrpkt",0,"c_rs",0,"c_dsz",0,"c_prot",0,"c_br",0,"c_sat",0,"c_pfollow",0);
        int layout=(header>>>LAYOUT_SHIFT)&LAYOUT_MASK;
        return Map.of("c_is16",offset<28&&((layout>>>(offset/4))&1)!=0?1:0,"c_isheader",offset==28?1:0,"c_hdrpkt",1,
            "c_rs",(header>>>RS_SHIFT)&1,"c_dsz",(header>>>DSZ_SHIFT)&7,"c_prot",(header>>>PROT_SHIFT)&1,
            "c_br",(header>>>BR_SHIFT)&1,"c_sat",(header>>>SAT_SHIFT)&1,"c_pfollow",offset==28?0:parallelFollowers(header,layout,offset/2));
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
