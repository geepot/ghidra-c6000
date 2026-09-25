// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Verify scalar and 40-bit ABS/NEG/MV operand forms and execution.

import java.io.BufferedReader;
import java.io.FileReader;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class C6000PairUnaryTest extends GhidraScript {
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
                    !instruction.getMnemonicString().equals(f[1]) ||
                    !instruction.toString().contains(f[2].replace('_', ':') + "," +
                        f[3].replace('_', ':'))) {
                    throw new AssertionError(f[0] + ": decoded as " + instruction);
                }
                for (PcodeOp op : instruction.getPcode()) {
                    if (op.getOpcode() == PcodeOp.CALLOTHER) {
                        throw new AssertionError(f[0] + ": placeholder " + op);
                    }
                }
                EmulatorHelper emulator = new EmulatorHelper(currentProgram);
                try {
                    emulator.writeRegister(f[2], Long.parseUnsignedLong(f[4], 16));
                    emulator.writeRegister("CSR", 0);
                    emulator.writeRegister("SSR", 0);
                    emulator.getEmulator().setExecuteAddress(offset);
                    if (!emulator.step(monitor)) {
                        throw new AssertionError(f[0] + ": " + emulator.getLastError());
                    }
                    long actual = emulator.readRegister(f[3]).longValue();
                    long expected = Long.parseUnsignedLong(f[5], 16);
                    long csr = emulator.readRegister("CSR").longValue() & 0x200;
                    long ssr = emulator.readRegister("SSR").longValue() & 3;
                    long expectedCsr = f[6].equals("1") ? 0x200 : 0;
                    long expectedSsr = f[6].equals("1") ? Integer.parseInt(f[7]) : 0;
                    if (actual != expected || csr != expectedCsr || ssr != expectedSsr) {
                        throw new AssertionError(f[0] + ": result=0x" +
                            Long.toHexString(actual) + " CSR=0x" + Long.toHexString(csr) +
                            " SSR=0x" + Long.toHexString(ssr) + " expected=0x" + f[5]);
                    }
                } finally {
                    emulator.dispose();
                }
                valid++;
            }
        }
        println("C6000_PAIR_UNARY_OK valid=" + valid + " invalid=" + invalid);
    }
}
