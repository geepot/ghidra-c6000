// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Verify scalar and 40-bit comparison forms and unsigned long ADDU.

import java.io.BufferedReader;
import java.io.FileReader;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class C6000CompareFormsTest extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("expected cases.tsv path");
        int valid = 0;
        int invalid = 0;
        try (BufferedReader rows = new BufferedReader(new FileReader(args[0]))) {
            String row;
            while ((row = rows.readLine()) != null) {
                String[] f = row.split("\\t");
                long offset = 0x1000L + 32L * Integer.parseInt(f[0]);
                Address address = toAddr(offset);
                Instruction instruction = currentProgram.getListing().getInstructionAt(address);
                if (instruction == null) {
                    new DisassembleCommand(address, null, false).applyTo(currentProgram, monitor);
                    instruction = currentProgram.getListing().getInstructionAt(address);
                }
                if (f[1].equals("-")) {
                    if (instruction != null) {
                        throw new AssertionError(f[0] + ": accepted invalid form as " + instruction);
                    }
                    invalid++;
                    continue;
                }
                if (instruction == null || instruction.getLength() != 4 ||
                    !instruction.getMnemonicString().equals(f[1])) {
                    throw new AssertionError(f[0] + ": decoded as " + instruction);
                }
                EmulatorHelper emulator = new EmulatorHelper(currentProgram);
                try {
                    emulator.writeRegister("A4", 0xffffffffL);
                    emulator.writeRegister("B4", 0x80000000L);
                    emulator.writeRegister("A6", 0xfffffffdL);
                    emulator.writeRegister("B6", 0x80000001L);
                    emulator.writeRegister("A7", 0xffffffffL);
                    emulator.writeRegister("B7", 0x12345600L);
                    String bank = f[2].equals("1") ? "A" : "B";
                    emulator.writeRegister(bank + "8", 0x55);
                    emulator.writeRegister(bank + "9", 0x66);
                    emulator.getEmulator().setExecuteAddress(offset);
                    if (!emulator.step(monitor)) {
                        throw new AssertionError(f[0] + ": " + emulator.getLastError());
                    }
                    long actual = (emulator.readRegister(bank + "9").longValue() << 32) |
                        (emulator.readRegister(bank + "8").longValue() & 0xffffffffL);
                    long expected = Long.parseUnsignedLong(f[3], 16);
                    if (actual != expected) {
                        throw new AssertionError(f[0] + ": result=0x" +
                            Long.toHexString(actual) + " expected=0x" + f[3]);
                    }
                } finally {
                    emulator.dispose();
                }
                valid++;
            }
        }
        println("C6000_COMPARE_FORMS_OK valid=" + valid + " invalid=" + invalid);
    }
}
