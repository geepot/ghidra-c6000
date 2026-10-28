// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Execute scalar SHL/SHR/SHRU count masking, including immediate controls.

import java.nio.file.Files;
import java.nio.file.Path;

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.listing.Instruction;

public class C6000WordShiftsTest extends GhidraScript {
    @Override
    protected void run() throws Exception {
        int checked = 0;
        for (String row : Files.readAllLines(Path.of(getScriptArgs()[0]))) {
            String[] f = row.split("\\t");
            long at = 0x1000L + 32L * Integer.parseInt(f[0]);
            new DisassembleCommand(toAddr(at), null, false).applyTo(currentProgram, monitor);
            Instruction insn = getInstructionAt(toAddr(at));
            if (insn == null || insn.getLength() != 4 || !insn.getMnemonicString().equals(f[1])) {
                throw new AssertionError(f[0] + ": decoded as " + insn);
            }
            EmulatorHelper emulator = new EmulatorHelper(currentProgram);
            try {
                emulator.writeRegister(f[2], Long.parseUnsignedLong(f[5], 16));
                if (!f[3].equals("-")) {
                    emulator.writeRegister(f[3], Long.parseUnsignedLong(f[6], 16));
                }
                emulator.getEmulator().setExecuteAddress(at);
                if (!emulator.step(monitor)) {
                    throw new AssertionError(f[0] + ": " + emulator.getLastError());
                }
                long actual = emulator.readRegister(f[4]).longValue() & 0xffffffffL;
                long expected = Long.parseUnsignedLong(f[7], 16);
                if (actual != expected) {
                    throw new AssertionError(f[0] + ": " + insn + " result=" +
                        Long.toHexString(actual) + " expected=" + Long.toHexString(expected));
                }
            }
            finally {
                emulator.dispose();
            }
            checked++;
        }
        println("C6000_WORD_SHIFTS_OK cases=" + checked);
    }
}
