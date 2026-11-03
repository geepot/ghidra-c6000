// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Prime compact-dstk.py's packets with an initialized overlay over OTHER present,
// as the ELF loader adds for sections such as .TI.section.flags.
// Usage: C6000PacketScopeTest.java <cases.tsv>

import java.io.BufferedReader;
import java.io.FileReader;

import c6000.C6000PacketAnalyzer;
import c6000.C6000PacketContext;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class C6000PacketScopeTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 1) {
			throw new IllegalArgumentException("expected cases.tsv path");
		}
		Address other = currentProgram.getAddressFactory().getAddressSpace("OTHER").getAddress(0);
		currentProgram.getMemory().createInitializedBlock(".TI.section.flags", other, 4,
			(byte) 0, monitor, true);
		// Auto-analysis passes every added byte, overlays included, to the analyzer.
		MessageLog log = new MessageLog();
		if (!new C6000PacketAnalyzer().added(currentProgram,
				currentProgram.getMemory().getAllInitializedAddressSet(), monitor, log)) {
			throw new AssertionError("packet analyzer failed with an OTHER overlay present: " + log);
		}
		int packets;
		try {
			packets = C6000PacketContext.prime(currentProgram, monitor);
		}
		catch (IllegalArgumentException e) {
			throw new AssertionError("prime failed with an OTHER overlay present: " + e.getMessage());
		}
		int checked = 0;
		try (BufferedReader rows = new BufferedReader(new FileReader(args[0]))) {
			String row;
			while ((row = rows.readLine()) != null) {
				String[] fields = row.split("\\t");
				Address address = toAddr(0x1000L + 32L * Integer.parseInt(fields[0]));
				new DisassembleCommand(address, null, false).applyTo(currentProgram, monitor);
				Instruction insn = currentProgram.getListing().getInstructionAt(address);
				String mnemonic = (Integer.parseInt(fields[2]) != 0 ? "LDW" : "STW") + ".D2";
				if (insn == null || insn.getLength() != 2 || !insn.getMnemonicString().equals(mnemonic)) {
					throw new AssertionError(fields[1] + ": expected compact " + mnemonic + " at " +
						address + ", got " + insn);
				}
				checked++;
			}
		}
		println("C6000_PACKET_SCOPE_OK cases=" + checked + " packets=" + packets);
	}
}
