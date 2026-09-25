// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Validate 40-bit shift operand forms and pair-width arithmetic.

import java.io.BufferedReader;
import java.io.FileReader;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class C6000LongShiftTest extends GhidraScript {
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
                String own = f[2].equals("1") ? "A" : "B";
                String other = own.equals("A") ? "B" : "A";
                String source = f[3].equals("1") ? other : own;
                EmulatorHelper emulator = new EmulatorHelper(currentProgram);
                try {
                    emulator.writeRegister(own + "2", 0x12345678L);
                    emulator.writeRegister(own + "3", 0);
                    emulator.writeRegister(other + "2", 0x12345678L);
                    emulator.writeRegister(other + "3", 0);
                    emulator.writeRegister(source + "2", Long.parseUnsignedLong(f[4], 16));
                    emulator.writeRegister(source + "3", Long.parseUnsignedLong(f[5], 16));
                    emulator.writeRegister(own + "4", Integer.parseInt(f[6]));
                    emulator.writeRegister(own + "6", 0x55);
                    emulator.writeRegister(own + "7", 0x66);
                    emulator.getEmulator().setExecuteAddress(offset);
                    if (!emulator.step(monitor)) {
                        throw new AssertionError(f[0] + ": " + emulator.getLastError());
                    }
                    long actual = (emulator.readRegister(own + "7").longValue() << 32) |
                        (emulator.readRegister(own + "6").longValue() & 0xffffffffL);
                    long expected = Long.parseUnsignedLong(f[7], 16);
                    if (actual != expected) {
                        throw new AssertionError(f[0] + ": result=0x" +
                            Long.toHexString(actual) + " expected=0x" + f[7]);
                    }
                } finally {
                    emulator.dispose();
                }
                valid++;
            }
        }
        println("C6000_LONG_SHIFT_OK valid=" + valid + " invalid=" + invalid);
    }
}
