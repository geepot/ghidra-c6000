// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check SP add/sub decode, results, and FADCR flags. Usage: <cases.tsv>.

import java.io.BufferedReader;
import java.io.FileReader;

import c6000.C6000PacketContext;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class C6000FloatAddTest extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("expected cases.tsv path");
        }
        C6000PacketContext.prime(currentProgram, monitor);
        int checked = 0;
        try (BufferedReader rows = new BufferedReader(new FileReader(args[0]))) {
            String row;
            while ((row = rows.readLine()) != null) {
                String[] f = row.split("\\t");
                long offset = 0x1000L + 32L * Integer.parseInt(f[0]);
                Address address = toAddr(offset);
                Instruction insn = currentProgram.getListing().getInstructionAt(address);
                if (insn == null) {
                    new DisassembleCommand(address, null, false).applyTo(currentProgram, monitor);
                    insn = currentProgram.getListing().getInstructionAt(address);
                }
                if (insn == null || insn.getLength() != 4 ||
                    !insn.getMnemonicString().equals(f[1]) ||
                    !insn.getDefaultOperandRepresentation(0).equals(f[2]) ||
                    !insn.getDefaultOperandRepresentation(1).equals(f[3]) ||
                    !insn.getDefaultOperandRepresentation(2).equals(f[4])) {
                    throw new AssertionError(f[0] + ": decoded as " + insn);
                }
                for (PcodeOp op : insn.getPcode()) {
                    if (op.getOpcode() == PcodeOp.CALLOTHER) {
                        throw new AssertionError(f[0] + ": placeholder " + op);
                    }
                }
                EmulatorHelper emulator = new EmulatorHelper(currentProgram);
                try {
                    emulator.writeRegister(f[5], Long.parseUnsignedLong(f[7], 16));
                    emulator.writeRegister(f[6], Long.parseUnsignedLong(f[8], 16));
                    emulator.writeRegister("FADCR", Long.parseUnsignedLong(f[10], 16));
                    emulator.getEmulator().setExecuteAddress(offset);
                    if (!emulator.step(monitor)) {
                        throw new AssertionError(f[0] + ": " + emulator.getLastError());
                    }
                    long actual = emulator.readRegister(f[4].replace(':', '_')).longValue();
                    long expected = Long.parseUnsignedLong(f[9], 16);
                    long flags = emulator.readRegister("FADCR").longValue();
                    long expectedFlags = Long.parseUnsignedLong(f[11], 16);
                    if (actual != expected || flags != expectedFlags) {
                        throw new AssertionError(f[0] + ": result=0x" +
                            Long.toHexString(actual) + " FADCR=0x" +
                            Long.toHexString(flags) + " expected result=0x" +
                            f[9] + " FADCR=0x" + f[11]);
                    }
                } finally {
                    emulator.dispose();
                }
                checked++;
            }
        }
        println("C6000_FLOAT_ADD_OK cases=" + checked);
    }
}
