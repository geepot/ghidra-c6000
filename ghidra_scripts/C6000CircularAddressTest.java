// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Execute AMR circular address cases. Usage: <cases.tsv>.

import java.io.BufferedReader;
import java.io.FileReader;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class C6000CircularAddressTest extends GhidraScript {
    private static long hex(String value) {
        return Long.parseUnsignedLong(value, 16);
    }

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
                String[] f = row.split("\t");
                Address address = toAddr(0x1000L + 32L * Integer.parseInt(f[0]));
                Instruction insn = currentProgram.getListing().getInstructionAt(address);
                if (insn == null) {
                    new DisassembleCommand(address, null, false).applyTo(currentProgram, monitor);
                    insn = currentProgram.getListing().getInstructionAt(address);
                }
                if (insn == null || insn.getLength() != 4 ||
                    !insn.getMnemonicString().equals(f[1])) {
                    throw new AssertionError(f[0] + ": decoded as " + insn);
                }
                for (PcodeOp op : insn.getPcode()) {
                    if (op.getOpcode() == PcodeOp.CALLOTHER) {
                        throw new AssertionError(f[0] + ": placeholder " + op);
                    }
                }
                EmulatorHelper emulator = new EmulatorHelper(currentProgram);
                try {
                    emulator.writeRegister("AMR", hex(f[5]));
                    emulator.writeRegister(f[2], hex(f[6]));
                    if (!f[3].equals("-")) {
                        emulator.writeRegister(f[3], hex(f[4]));
                    }
                    if (!f[7].equals(f[2]) && !f[7].equals(f[3])) {
                        emulator.writeRegister(f[7], hex(f[8]));
                    }
                    emulator.getEmulator().setExecuteAddress(address.getOffset());
                    if (!emulator.step(monitor)) {
                        throw new AssertionError(f[0] + ": " + emulator.getLastError());
                    }
                    long target = emulator.readRegister(f[7]).longValue() & 0xffffffffL;
                    long base = emulator.readRegister(f[2]).longValue() & 0xffffffffL;
                    if (target != hex(f[9]) || base != hex(f[10])) {
                        throw new AssertionError(f[0] + ": target=0x" +
                            Long.toHexString(target) + " base=0x" + Long.toHexString(base) +
                            " expected target=0x" + f[9] + " base=0x" + f[10]);
                    }
                    if (hex(f[11]) != 0) {
                        int width = f[1].startsWith("STB") ? 1 : 2;
                        byte[] bytes = emulator.readMemory(toAddr(hex(f[11])), width);
                        int actual = bytes[0] & 0xff;
                        if (width == 2) {
                            int other = bytes[1] & 0xff;
                            actual = currentProgram.getLanguage().isBigEndian()
                                ? (actual << 8) | other : (other << 8) | actual;
                        }
                        if (actual != hex(f[12])) {
                            throw new AssertionError(f[0] + ": stored 0x" +
                                Integer.toHexString(actual) + " expected 0x" + f[12]);
                        }
                    }
                } finally {
                    emulator.dispose();
                }
                checked++;
            }
        }
        println("C6000_CIRCULAR_ADDRESS_OK cases=" + checked);
    }
}
