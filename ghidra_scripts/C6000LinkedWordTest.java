// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Check C64x+ linked-word decode and event p-code. Usage: <cases.tsv>.

import java.io.BufferedReader;
import java.io.FileReader;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class C6000LinkedWordTest extends GhidraScript {
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
                Address address = toAddr(0x1000L + 32L * Integer.parseInt(f[0]));
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
                    !instruction.toString().contains("B21") ||
                    !instruction.toString().contains("*B5")) {
                    throw new AssertionError(f[0] + ": decoded as " + instruction);
                }
                boolean found = false;
                for (PcodeOp op : instruction.getPcode()) {
                    if (op.getOpcode() != PcodeOp.CALLOTHER) continue;
                    String userop = currentProgram.getLanguage().getUserDefinedOpName(
                        (int) op.getInput(0).getOffset());
                    if (userop.startsWith("c6000_unimpl")) {
                        throw new AssertionError(f[0] + ": placeholder " + op);
                    }
                    if (userop.equals(f[2])) found = true;
                }
                if (!found) throw new AssertionError(f[0] + ": missing event " + f[2]);
                valid++;
            }
        }
        println("C6000_LINKED_WORD_OK valid=" + valid + " invalid=" + invalid);
    }
}
