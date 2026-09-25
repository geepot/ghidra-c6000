// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Verify MVKH's high-half write, MVK's low constant, and predication.

import java.io.BufferedReader;
import java.io.FileReader;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class C6000MvkhTest extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("expected cases.tsv path");
        int checked = 0;
        try (BufferedReader rows = new BufferedReader(new FileReader(args[0]))) {
            String row;
            while ((row = rows.readLine()) != null) {
                String[] fields = row.split("\\t");
                long offset = 0x1000L + 32L * Integer.parseInt(fields[0]);
                Address address = toAddr(offset);
                Instruction instruction = currentProgram.getListing().getInstructionAt(address);
                if (instruction == null) {
                    new DisassembleCommand(address, null, false).applyTo(currentProgram, monitor);
                    instruction = currentProgram.getListing().getInstructionAt(address);
                }
                if (instruction == null || instruction.getLength() != 4 ||
                    !instruction.getMnemonicString().equals(fields[1])) {
                    throw new AssertionError(fields[0] + ": decoded as " + instruction);
                }
                for (PcodeOp op : instruction.getPcode()) {
                    if (op.getOpcode() == PcodeOp.CALLOTHER) {
                        throw new AssertionError(fields[0] + ": placeholder " + op);
                    }
                }
                EmulatorHelper emulator = new EmulatorHelper(currentProgram);
                try {
                    emulator.writeRegister(fields[2], Long.parseUnsignedLong(fields[3], 16));
                    if (!fields[2].equals("B0")) {
                        emulator.writeRegister("B0", Long.parseUnsignedLong(fields[4], 16));
                    }
                    emulator.getEmulator().setExecuteAddress(offset);
                    if (!emulator.step(monitor)) {
                        throw new AssertionError(fields[0] + ": " + emulator.getLastError());
                    }
                    long actual = emulator.readRegister(fields[2]).longValue() & 0xffffffffL;
                    long expected = Long.parseUnsignedLong(fields[5], 16);
                    if (actual != expected) {
                        throw new AssertionError(fields[0] + ": result=0x" +
                            Long.toHexString(actual) + " expected=0x" + fields[5]);
                    }
                } finally {
                    emulator.dispose();
                }
                checked++;
            }
        }
        println("C6000_MVKH_OK cases=" + checked);
    }
}
