// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Decode the image from tests/fixtures/compact-header-collision.py at 0x1000.

import c6000.C6000PacketContext;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class C6000CompactHeaderTest extends GhidraScript {
	private Instruction decode(long offset) throws Exception {
		Address address = toAddr(offset);
		new DisassembleCommand(address, null, false).applyTo(currentProgram, monitor);
		return currentProgram.getListing().getInstructionAt(address);
	}

	private void expect(long address, int length, String mnemonic) throws Exception {
		Instruction instruction = decode(address);
		if (instruction == null || instruction.getLength() != length ||
			!instruction.getMnemonicString().equals(mnemonic)) {
			throw new AssertionError("at " + toAddr(address) + ": expected " + mnemonic +
				"/" + length + ", got " + instruction);
		}
	}

	private void block(String name, long start, int size) throws Exception {
		currentProgram.getMemory().createInitializedBlock(name, toAddr(start), size, (byte) 0, monitor, false);
	}

	private void fragmentedPacket(long base, int firstOffset, int firstSize, int lastOffset, int lastSize, int layout) throws Exception {
		block("fragment_a_" + base, base + firstOffset, firstSize);
		block("fragment_b_" + base, base + lastOffset, lastSize);
		var memory = currentProgram.getMemory();
		memory.setInt(toAddr(base + firstOffset), memory.getInt(toAddr(0x1020)));
		memory.setInt(toAddr(base + 28), 0xe0000000 | layout << 21);
		var changed = new ghidra.program.model.address.AddressSet(toAddr(base + firstOffset), toAddr(base + 31));
		if (C6000PacketContext.prime(currentProgram, changed, monitor) != 1)
			throw new AssertionError("Split packet counted more than once or its header was missed at " + toAddr(base));
		expect(base + firstOffset, 2, "SUB.S2");
		expect(base + firstOffset + 2, 2, "MPYH.M1");
		expect(base + 28, 4, "CPKT");
	}

	@Override
	protected void run() throws Exception {
		// A changed header byte must prime its whole packet, without touching
		// the unrelated first packet (native BYTE_ANALYZER range contract).
		var analyzer = new c6000.C6000PacketAnalyzer();
		analyzer.added(currentProgram, new ghidra.program.model.address.AddressSet(toAddr(0x103f)),
			monitor, new ghidra.app.util.importer.MessageLog());
		if (!java.math.BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(
			currentProgram.getRegister("c_is16"), toAddr(0x1020), false)) ||
			currentProgram.getProgramContext().getValue(currentProgram.getRegister("c_is16"), toAddr(0x1000), false) != null)
			throw new AssertionError("Packet analyzer did not honor the changed-byte scope");
		var cancelled = new ghidra.util.task.TaskMonitorAdapter(true);cancelled.cancel();
		try {
			analyzer.added(currentProgram, new ghidra.program.model.address.AddressSet(toAddr(0x103f)),
				cancelled, new ghidra.app.util.importer.MessageLog());
			throw new AssertionError("Packet analyzer swallowed cancellation");
		} catch (ghidra.util.exception.CancelledException expected) { }
		// Raw imports need not end on a full fetch-packet boundary. Incomplete
		// header bytes must not abort ordinary instruction/context discovery.
		currentProgram.getMemory().createInitializedBlock("partial_fetch", toAddr(0x2000), 31, (byte) 0, monitor, false);
		C6000PacketContext.prime(currentProgram, new ghidra.program.model.address.AddressSet(toAddr(0x2000)), monitor);
		expect(0x2000, 4, "NOP");
		int packets = C6000PacketContext.prime(currentProgram, monitor);
		if (packets != 1) {
			throw new AssertionError("expected one compact packet, got " + packets);
		}
		Instruction stray = decode(0x1000);
		if (stray != null && !stray.getMnemonicString().equals("BAD-Instruction")) {
			throw new AssertionError("reserved non-header word decoded as " + stray);
		}
		expect(0x1020, 2, "SUB.S2");
		expect(0x1022, 2, "MPYH.M1");
		expect(0x103c, 4, "CPKT");
		// SPRUFE8B 3.10.2: physical fetch packets can cross imported block
		// boundaries; even the four header bytes may reside in adjacent blocks.
		fragmentedPacket(0x2100, 0, 28, 28, 4, 1);
		fragmentedPacket(0x2200, 0, 30, 30, 2, 1);
		fragmentedPacket(0x2300, 4, 24, 28, 4, 2);
		fragmentedPacket(0x2400, 0, 4, 28, 4, 1);
		for (long hole : new long[] {0x2300, 0x2404, 0x241a}) {
			if (currentProgram.getProgramContext().getValue(currentProgram.getRegister("c_is16"), toAddr(hole), false) != null)
				throw new AssertionError("Packet priming wrote context into an unloaded hole at " + toAddr(hole));
		}
		// The final ordinary instruction has a mathematical one-past-end
		// sentinel; it must not create an address outside the 32-bit space.
		block("top_of_memory", 0xffffffe0L, 32);
		C6000PacketContext.prime(currentProgram, new ghidra.program.model.address.AddressSet(toAddr(0xfffffffcL)), monitor);
		if (c6000.C6000ExecutionPackets.parallelBytes(currentProgram, toAddr(0xfffffffcL)) != 0)
			throw new AssertionError("Final NOP has unexpected followers");
		expect(0xfffffffcL, 4, "NOP");
		// Removing a compact header must also clear the second halfword's
		// noflow context, otherwise a later full-width decode can inherit it.
		block("changed_layout", 0x2500, 32);
		currentProgram.getMemory().setInt(toAddr(0x251c), 0xe0200000);
		var changedLayout = new ghidra.program.model.address.AddressSet(toAddr(0x251c));
		C6000PacketContext.prime(currentProgram, changedLayout, monitor);
		currentProgram.getMemory().setInt(toAddr(0x251c), 0);
		C6000PacketContext.prime(currentProgram, changedLayout, monitor);
		if (!java.math.BigInteger.ZERO.equals(currentProgram.getProgramContext().getValue(
			currentProgram.getRegister("c_is16"), toAddr(0x2502), false)))
			throw new AssertionError("Removed header left stale compact halfword context");

		println("C6000_COMPACT_HEADER_OK");
	}
}
