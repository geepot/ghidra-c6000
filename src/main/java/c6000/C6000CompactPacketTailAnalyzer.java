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

import java.util.Map;
import java.util.TreeMap;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Decode the rest of a compact fetch packet after a discovered branch.
 *
 * <p>A branch terminates its execute packet, but later slots in the same
 * fetch packet can be alternate entry points. Ghidra's ordinary flow walk
 * otherwise leaves those slots undefined, including parallel instructions
 * after branches reached through another path.
 */
public class C6000CompactPacketTailAnalyzer extends AbstractAnalyzer {
	public C6000CompactPacketTailAnalyzer() {
		super("C6000 Compact Packet Tails",
			"Decode compact instruction slots following discovered branches",
			AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.CODE_ANALYSIS.after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C6000PacketContext.isC6000(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		Listing listing = program.getListing();
		Map<Long, Integer> tails = new TreeMap<>();
		InstructionIterator instructions = listing.getInstructions(set, true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();
			if (instruction.getLength() != 2) continue;
			String name = instruction.getMnemonicString();
			if (!name.contains("BNOP") && !name.contains("CALLP")) continue;
			long address = instruction.getAddress().getOffset();
			long base = address & ~31L;
			int end = (int) (address + 2 - base);
			tails.merge(base, end, Math::min);
		}

		Disassembler disassembler = Disassembler.getDisassembler(program, monitor, null);
		int decoded = 0;
		for (Map.Entry<Long, Integer> entry : tails.entrySet()) {
			monitor.checkCancelled();
			long base = entry.getKey();
			Address packet = program.getAddressFactory().getDefaultAddressSpace().getAddress(base);
			int header;
			try {
				header = program.getMemory().getInt(packet.add(28));
			}
			catch (MemoryAccessException e) {
				continue;
			}
			if ((header >>> 28) != 0xe) continue;
			int layout = (header >>> 21) & 0x7f;
			for (int offset = entry.getValue(); offset < 28;) {
				monitor.checkCancelled();
				int length = ((layout >>> (offset / 4)) & 1) != 0 ? 2 : 4;
				if (length == 4 && (offset & 3) != 0) break;
				Address slot = packet.add(offset);
				if (listing.getInstructionContaining(slot) == null &&
					listing.getDefinedDataContaining(slot) == null) {
					disassembler.disassemble(slot,
						new AddressSet(slot, slot.add(length - 1)), false);
					if (listing.getInstructionAt(slot) != null) decoded++;
				}
				offset += length;
			}
		}
		if (decoded > 0) log.appendMsg(getName(), "decoded " + decoded + " packet tail slot(s)");
		return true;
	}
}
