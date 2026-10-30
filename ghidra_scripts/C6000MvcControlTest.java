// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Verify MVC crhi aliases, direction-specific control-register names and userop-only TSC p-code.

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class C6000MvcControlTest extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("expected cases.tsv path");
        int valid = 0;
        int invalid = 0;
        List<String> failures = new ArrayList<>();
        try (BufferedReader rows = new BufferedReader(new FileReader(args[0]))) {
            String row;
            while ((row = rows.readLine()) != null) {
                String[] f = row.split("\\t");
                try {
                    if (checkRow(f)) valid++;
                    else invalid++;
                } catch (AssertionError failure) {
                    failures.add(failure.getMessage());
                }
            }
        }
        if (!failures.isEmpty()) throw new AssertionError(String.join("; ", failures));
        println("C6000_MVC_CONTROL_OK valid=" + valid + " invalid=" + invalid);
    }

    private boolean checkRow(String[] f) throws Exception {
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
            return false;
        }
        if (f[4].equals("event")) {
            checkEvent(instruction, f);
            return true;
        }
        if (instruction == null || instruction.getLength() != 4 ||
            !instruction.getMnemonicString().equals("MVC.S2") ||
            !instruction.toString().contains(f[2])) {
            throw new AssertionError(f[0] + ": decoded as " + instruction);
        }
        if (f[4].equals("decode")) {
            return true;
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
        return true;
    }

    // Columns 6 and 7: the userop and exact listing; run the p-code for each predicate value.
    private void checkEvent(Instruction instruction, String[] f) {
        if (instruction == null || instruction.getLength() != 4 || !instruction.toString().equals(f[6])) {
            throw new AssertionError(f[0] + ": decoded as " + instruction + " expected " + f[6]);
        }
        boolean write = f[1].equals("write");
        Register dst = write ? null : instruction.getRegister(1);
        if (!write && dst == null) throw new AssertionError(f[0] + ": no destination in " + instruction);
        Matcher guard = Pattern.compile("^\\[(!?)([AB]\\d+)\\]").matcher(f[6]);
        Register predicate = guard.find() ? currentProgram.getRegister(guard.group(2)) : null;
        for (long value : predicate == null ? new long[] {1} : new long[] {0, 1}) {
            boolean taken = predicate == null || (value != 0) != guard.group(1).equals("!");
            int events = run(instruction.getPcode(), f, predicate, value, dst);
            if (events != (taken ? 1 : 0)) {
                throw new AssertionError(f[0] + ": " + events + " " + f[5] + " with " + predicate + "=" + value);
            }
        }
    }

    // Interprets the guard p-code; any register access but the predicate read and the userop result fails.
    private int run(PcodeOp[] ops, String[] f, Register predicate, long value, Register dst) {
        Map<Long, Long> temps = new HashMap<>();
        int events = 0;
        int pc = 0;
        for (int steps = 0; pc < ops.length; steps++) {
            PcodeOp op = ops[pc];
            if (steps > ops.length) throw new AssertionError(f[0] + ": p-code loops");
            Varnode out = op.getOutput();
            if (op.getOpcode() == PcodeOp.CALLOTHER) {
                String name = currentProgram.getLanguage().getUserDefinedOpName((int) op.getInput(0).getOffset());
                boolean ok = name.equals(f[5]) && op.getNumInputs() == 1 && (dst == null ? out == null
                    : out != null && out.isRegister() && out.getAddress().equals(dst.getAddress()) && out.getSize() == 4);
                if (!ok) throw new AssertionError(f[0] + ": unexpected userop " + op);
                events++;
                pc++;
                continue;
            }
            if (out != null && !out.isUnique()) throw new AssertionError(f[0] + ": writes " + op);
            long a = op.getNumInputs() > 0 ? input(op.getInput(0), temps, predicate, value, f) : 0;
            long b = op.getNumInputs() > 1 ? input(op.getInput(1), temps, predicate, value, f) : 0;
            switch (op.getOpcode()) {
                case PcodeOp.CBRANCH:
                case PcodeOp.BRANCH:
                    if (!op.getInput(0).isConstant()) throw new AssertionError(f[0] + ": leaves the instruction " + op);
                    long next = pc + (op.getOpcode() == PcodeOp.BRANCH || b != 0 ? (int) op.getInput(0).getOffset() : 1);
                    if (next <= pc || next > ops.length) throw new AssertionError(f[0] + ": bad branch " + op);
                    pc = (int) next;
                    continue;
                case PcodeOp.COPY: temps.put(out.getOffset(), a); break;
                case PcodeOp.INT_EQUAL: temps.put(out.getOffset(), a == b ? 1L : 0L); break;
                case PcodeOp.INT_NOTEQUAL: temps.put(out.getOffset(), a != b ? 1L : 0L); break;
                case PcodeOp.BOOL_NEGATE: temps.put(out.getOffset(), a == 0 ? 1L : 0L); break;
                default: throw new AssertionError(f[0] + ": unexpected op " + op);
            }
            pc++;
        }
        return events;
    }

    private long input(Varnode node, Map<Long, Long> temps, Register predicate, long value, String[] f) {
        if (node.isConstant()) return node.getOffset();
        if (node.isUnique() && temps.containsKey(node.getOffset())) return temps.get(node.getOffset());
        if (predicate != null && node.isRegister() && node.getAddress().equals(predicate.getAddress()) &&
            node.getSize() == 4) {
            return value;
        }
        throw new AssertionError(f[0] + ": reads " + node);
    }
}
