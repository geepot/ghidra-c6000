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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Recover calls encoded as B plus a delayed ADDKPC that writes B3.
 *
 * <p>C6000 permits the return address to be installed in a later instruction
 * of the branch's delay window. Ghidra sees the B as a jump unless this
 * instruction pair is recognized. A CALL flow override preserves the branch
 * target and lets ordinary function analysis create the callee.
 */
public class C6000CallAnalyzer extends AbstractAnalyzer {
	private static final int DELAY_PACKETS = 5;
	private static final int MAX_SCAN_BYTES = 160;

	public C6000CallAnalyzer() {
		super("C6000 Delayed Calls",
			"Classifies B instructions with a delayed ADDKPC to B3 as calls",
			AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		// The generic constant analyzer creates computed B-register target
		// references just before REFERENCE_ANALYSIS. Reclassify them afterward.
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C6000PacketContext.isC6000(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		Listing listing = program.getListing();
		InstructionIterator instructions = listing.getInstructions(set, true);
		int recovered = 0;
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction branch = instructions.next();
			String mnemonic = branch.getMnemonicString();
			if ((!mnemonic.endsWith("B.S1") && !mnemonic.endsWith("B.S2")) ||
				branch.getFlowOverride() == FlowOverride.CALL) {
				continue;
			}
			int completedPackets = 0;
			Instruction previous = branch;
			while (completedPackets <= DELAY_PACKETS) {
				boolean parallel;
				try {
					parallel = parallelWithNext(program, previous);
				}
				catch (MemoryAccessException e) {
					break;
				}
				if (!parallel) completedPackets++;
				if (completedPackets > DELAY_PACKETS) break;
				Instruction delayed = nextExecutable(listing, previous);
				if (delayed == null || delayed.getMinAddress().subtract(
						branch.getMinAddress()) > MAX_SCAN_BYTES) break;
				String name = delayed.getMnemonicString();
				if (name.endsWith("ADDKPC.S2") && delayed.getNumOperands() >= 2 &&
					"B3".equals(delayed.getDefaultOperandRepresentation(1))) {
					branch.setFlowOverride(FlowOverride.CALL);
					recovered++;
					break;
				}
				if (delayed.getFlowType().isJump() || delayed.getFlowType().isCall()) break;
				previous = delayed;
			}
		}
		if (recovered > 0) log.appendMsg(getName(), "recovered " + recovered + " delayed call(s)");
		return true;
	}

	private static Instruction nextExecutable(Listing listing, Instruction current) {
		Instruction next = listing.getInstructionAfter(current.getMinAddress());
		while (next != null && next.getMnemonicString().equals("CPKT")) {
			if (!adjacent(current, next)) return null;
			current = next;
			next = listing.getInstructionAfter(current.getMinAddress());
		}
		return next != null && adjacent(current, next) ? next : null;
	}

	private static boolean adjacent(Instruction a, Instruction b) {
		return b.getMinAddress().getOffset() == a.getMaxAddress().getOffset() + 1;
	}

	private static boolean parallelWithNext(Program program, Instruction instruction)
			throws MemoryAccessException {
		Address address = instruction.getMinAddress();
		if (instruction.getLength() == 4) {
			return (program.getMemory().getInt(address) & 1) != 0;
		}
		long base = address.getOffset() & ~31L;
		int header = program.getMemory().getInt(address.getNewAddress(base + 28));
		if ((header >>> 28) != 0xe) {
			throw new MemoryAccessException("missing compact header at " + address);
		}
		return ((header >>> ((address.getOffset() - base) / 2)) & 1) != 0;
	}
}
