// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Execute nonaligned word/doubleword transfers across a circular buffer edge.

import java.io.BufferedReader;
import java.io.FileReader;
import java.math.BigInteger;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class C6000NonalignedCircularTest extends GhidraScript {
    private static long hex(String value) {
        return Long.parseUnsignedLong(value, 16);
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("expected cases.tsv path");
        int checked = 0;
        try (BufferedReader rows = new BufferedReader(new FileReader(args[0]))) {
            String row;
            while ((row = rows.readLine()) != null) {
                String[] f = row.split("\t");
                Address pc = toAddr(0x1000L + 32L * Integer.parseInt(f[0]));
                Instruction insn = currentProgram.getListing().getInstructionAt(pc);
                if (insn == null) {
                    new DisassembleCommand(pc, null, false).applyTo(currentProgram, monitor);
                    insn = currentProgram.getListing().getInstructionAt(pc);
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
                    emulator.writeRegister("AMR", hex(f[6]));
                    emulator.writeRegister(f[2], hex(f[3]));
                    if (f[1].startsWith("ST")) {
                        emulator.writeRegister(f[4], new BigInteger(f[5], 16));
                    }
                    emulator.getEmulator().setExecuteAddress(pc.getOffset());
                    if (!emulator.step(monitor)) {
                        throw new AssertionError(f[0] + ": " + emulator.getLastError());
                    }
                    int width = Integer.parseInt(f[8]);
                    BigInteger limit = BigInteger.ONE.shiftLeft(width * 8)
                        .subtract(BigInteger.ONE);
                    BigInteger actual = emulator.readRegister(f[4]).and(limit);
                    BigInteger expected = new BigInteger(f[9], 16);
                    if (!actual.equals(expected)) {
                        throw new AssertionError(f[0] + ": result=0x" +
                            actual.toString(16) + " expected=0x" + f[9]);
                    }
                    long base = emulator.readRegister(f[2]).longValue() & 0xffffffffL;
                    if (base != hex(f[3])) {
                        throw new AssertionError(f[0] + ": base=0x" +
                            Long.toHexString(base) + " expected=0x" + f[3]);
                    }
                    if (f[1].startsWith("ST")) {
                        long start = hex(f[3]);
                        long mask = hex(f[7]);
                        for (int i = 0; i < width; i++) {
                            long address = (start & ~mask) | ((start + i) & mask);
                            int actualByte = emulator.readMemoryByte(toAddr(address)) & 0xff;
                            int expectedByte = Integer.parseInt(
                                f[10].substring(2 * i, 2 * i + 2), 16);
                            if (actualByte != expectedByte) {
                                throw new AssertionError(f[0] + ": byte " + i +
                                    " at 0x" + Long.toHexString(address) + " =0x" +
                                    Integer.toHexString(actualByte) + " expected=0x" +
                                    Integer.toHexString(expectedByte));
                            }
                        }
                    }
                } finally {
                    emulator.dispose();
                }
                checked++;
            }
        }
        println("C6000_NONALIGNED_CIRCULAR_OK cases=" + checked);
    }
}
