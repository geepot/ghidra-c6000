// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Execute the MPY2 cases from mpy2.py. Usage: <cases.tsv>.

import java.io.BufferedReader;
import java.io.FileReader;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class C6000Mpy2Test extends GhidraScript {
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
                String pair = f[4].replace('_', ':');
                if (insn == null || insn.getLength() != 4 ||
                    !insn.getMnemonicString().equals(f[1]) ||
                    !insn.toString().contains(pair)) {
                    throw new AssertionError(f[0] + ": decoded as " + insn);
                }
                for (PcodeOp op : insn.getPcode()) {
                    if (op.getOpcode() == PcodeOp.CALLOTHER) {
                        throw new AssertionError(f[0] + ": placeholder " + op);
                    }
                }
                EmulatorHelper emulator = new EmulatorHelper(currentProgram);
                try {
                    emulator.writeRegister(f[2], Long.parseUnsignedLong(f[5], 16));
                    emulator.writeRegister(f[3], Long.parseUnsignedLong(f[6], 16));
                    emulator.getEmulator().setExecuteAddress(offset);
                    if (!emulator.step(monitor)) {
                        throw new AssertionError(f[0] + ": " + emulator.getLastError());
                    }
                    long actual = emulator.readRegister(f[4]).longValue();
                    long expected = Long.parseUnsignedLong(f[7], 16);
                    if (actual != expected) {
                        throw new AssertionError(f[0] + ": got 0x" +
                            Long.toHexString(actual) + " expected 0x" + f[7]);
                    }
                } finally {
                    emulator.dispose();
                }
                checked++;
            }
        }
        println("C6000_MPY2_OK cases=" + checked);
    }
}
