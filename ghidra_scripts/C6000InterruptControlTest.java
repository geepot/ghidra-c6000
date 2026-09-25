// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check DINT/RINT transitions and nested disable behavior. Usage: <cases.tsv>.

import java.io.BufferedReader;
import java.io.FileReader;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class C6000InterruptControlTest extends GhidraScript {
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
                    emulator.writeRegister("TSR", Long.parseUnsignedLong(f[2], 16));
                    emulator.writeRegister("CSR", Long.parseUnsignedLong(f[3], 16));
                    emulator.getEmulator().setExecuteAddress(offset);
                    if (!emulator.step(monitor)) {
                        throw new AssertionError(f[0] + ": " + emulator.getLastError());
                    }
                    long tsr = emulator.readRegister("TSR").longValue();
                    long csr = emulator.readRegister("CSR").longValue();
                    long expectedTsr = Long.parseUnsignedLong(f[4], 16);
                    long expectedCsr = Long.parseUnsignedLong(f[5], 16);
                    if (tsr != expectedTsr || csr != expectedCsr) {
                        throw new AssertionError(f[0] + ": TSR=0x" + Long.toHexString(tsr) +
                            " CSR=0x" + Long.toHexString(csr) + " expected TSR=0x" +
                            f[4] + " CSR=0x" + f[5]);
                    }
                } finally {
                    emulator.dispose();
                }
                checked++;
            }
        }
        EmulatorHelper nested = new EmulatorHelper(currentProgram);
        try {
            nested.writeRegister("TSR", 1);
            nested.writeRegister("CSR", 1);
            long[] expectedTsr = {2, 0, 0, 0};
            for (int index = 0; index < 4; index++) {
                nested.getEmulator().setExecuteAddress(0x1000L + 32L * index);
                if (!nested.step(monitor)) {
                    throw new AssertionError("nested " + index + ": " + nested.getLastError());
                }
                long tsr = nested.readRegister("TSR").longValue();
                long csr = nested.readRegister("CSR").longValue();
                if (tsr != expectedTsr[index] || csr != 0) {
                    throw new AssertionError("nested " + index + ": TSR=0x" +
                        Long.toHexString(tsr) + " CSR=0x" + Long.toHexString(csr));
                }
            }
        } finally {
            nested.dispose();
        }
        Address idleAddress = toAddr(0x1000L + 32L * checked);
        Instruction idle = currentProgram.getListing().getInstructionAt(idleAddress);
        if (idle == null) {
            new DisassembleCommand(idleAddress, null, false).applyTo(currentProgram, monitor);
            idle = currentProgram.getListing().getInstructionAt(idleAddress);
        }
        if (idle == null || !idle.getMnemonicString().equals("IDLE")) {
            throw new AssertionError("IDLE decoded as " + idle);
        }
        int idleEvents = 0;
        for (PcodeOp op : idle.getPcode()) {
            if (op.getOpcode() == PcodeOp.CALLOTHER) {
                int id = (int) op.getInput(0).getOffset();
                String name = currentProgram.getLanguage().getUserDefinedOpName(id);
                if (!"c6000_idle".equals(name)) {
                    throw new AssertionError("unexpected IDLE userop " + name);
                }
                idleEvents++;
            }
        }
        if (idleEvents != 1) {
            throw new AssertionError("IDLE events=" + idleEvents);
        }
        println("C6000_INTERRUPT_CONTROL_OK cases=" + checked + " nested=4 idle=1");
    }
}
