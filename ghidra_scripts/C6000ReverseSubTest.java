// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check both local and cross-path reverse-operand SUB.S encodings.

import java.io.BufferedReader;
import java.io.FileReader;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class C6000ReverseSubTest extends GhidraScript {
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
                EmulatorHelper emulator = new EmulatorHelper(currentProgram);
                try {
                    emulator.writeRegister(fields[2], 3);
                    emulator.writeRegister(fields[3], 0x10);
                    emulator.writeRegister(fields[4], 0x55);
                    emulator.writeRegister("B0", Integer.parseInt(fields[5]));
                    emulator.getEmulator().setExecuteAddress(offset);
                    if (!emulator.step(monitor)) {
                        throw new AssertionError(fields[0] + ": " + emulator.getLastError());
                    }
                    long actual = emulator.readRegister(fields[4]).longValue() & 0xffffffffL;
                    long expected = Long.parseUnsignedLong(fields[6], 16);
                    if (actual != expected) {
                        throw new AssertionError(fields[0] + ": result=0x" +
                            Long.toHexString(actual) + " expected=0x" + fields[6]);
                    }
                } finally {
                    emulator.dispose();
                }
                checked++;
            }
        }
        println("C6000_REVERSE_SUB_OK cases=" + checked);
    }
}
