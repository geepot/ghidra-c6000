// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Execute packed arithmetic fixtures from packed-arith.py. Usage: <cases.tsv>.

import java.io.BufferedReader;
import java.io.FileReader;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class C6000PackedArithmeticTest extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("expected cases.tsv path");
        }
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
                String mnemonic = f[1] + "." + f[2];
                if (insn == null || insn.getLength() != 4 ||
                    !insn.getMnemonicString().equals(mnemonic)) {
                    throw new AssertionError(mnemonic + ": decoded as " + insn);
                }
                for (PcodeOp op : insn.getPcode()) {
                    if (op.getOpcode() == PcodeOp.CALLOTHER) {
                        throw new AssertionError(mnemonic + ": placeholder " + op);
                    }
                }
                EmulatorHelper emulator = new EmulatorHelper(currentProgram);
                try {
                    boolean secondSide = f[2].endsWith("2");
                    emulator.writeRegister(secondSide ? "B1" : "A1",
                        Long.parseUnsignedLong(f[3], 16));
                    emulator.writeRegister("A2", Long.parseUnsignedLong(f[4], 16));
                    emulator.getEmulator().setExecuteAddress(offset);
                    if (!emulator.step(monitor)) {
                        throw new AssertionError(mnemonic + ": " + emulator.getLastError());
                    }
                    long actual = emulator.readRegister(secondSide ? "B3" : "A3")
                        .longValue() & 0xffffffffL;
                    long expected = Long.parseUnsignedLong(f[5], 16);
                    if (actual != expected) {
                        throw new AssertionError(mnemonic + ": got 0x" +
                            Long.toHexString(actual) + " expected 0x" + f[5]);
                    }
                } finally {
                    emulator.dispose();
                }
                checked++;
            }
        }
        println("C6000_PACKED_ARITHMETIC_OK cases=" + checked);
    }
}
