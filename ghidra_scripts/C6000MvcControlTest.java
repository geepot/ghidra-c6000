// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Verify MVC crhi aliases and direction-specific control-register names.

import java.io.BufferedReader;
import java.io.FileReader;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class C6000MvcControlTest extends GhidraScript {
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
                if (f[4].equals("invalid")) {
                    if (instruction != null) {
                        throw new AssertionError(f[0] + ": accepted invalid form as " + instruction);
                    }
                    invalid++;
                    continue;
                }
                if (instruction == null || instruction.getLength() != 4 ||
                    !instruction.getMnemonicString().equals("MVC.S2") ||
                    !instruction.toString().contains(f[2])) {
                    throw new AssertionError(f[0] + ": decoded as " + instruction);
                }
                if (f[4].equals("decode")) {
                    valid++;
                    continue;
                }
                EmulatorHelper emulator = new EmulatorHelper(currentProgram);
                try {
                    emulator.writeRegister("B4", 0x12345678L);
                    emulator.writeRegister("A4", 0x87654321L);
                    emulator.writeRegister(f[2], 0x55aabbccL);
                    emulator.writeRegister("B8", 0x66);
                    emulator.getEmulator().setExecuteAddress(offset);
                    if (!emulator.step(monitor)) {
                        throw new AssertionError(f[0] + ": " + emulator.getLastError());
                    }
                    boolean write = f[1].equals("write");
                    String resultRegister = write ? f[2] : "B8";
                    long expected = write ? (f[3].equals("1") ? 0x87654321L : 0x12345678L)
                        : 0x55aabbccL;
                    long actual = emulator.readRegister(resultRegister).longValue() & 0xffffffffL;
                    if (actual != expected) {
                        throw new AssertionError(f[0] + ": result=0x" +
                            Long.toHexString(actual) + " expected=0x" +
                            Long.toHexString(expected));
                    }
                } finally {
                    emulator.dispose();
                }
                valid++;
            }
        }
        println("C6000_MVC_CONTROL_OK valid=" + valid + " invalid=" + invalid);
    }
}
