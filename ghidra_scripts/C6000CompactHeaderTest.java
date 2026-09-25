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

	@Override
	protected void run() throws Exception {
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
		println("C6000_COMPACT_HEADER_OK");
	}
}
