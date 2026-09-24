// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Corpus-backed decode regression test for the C6000 processor module.
//
// Linearly decodes a C6000 image and reports:
//   * the number of instructions, their total byte length and the mnemonic
//     histogram,
//   * decoded instructions with an unimplemented-operation userop and
//     software-loop control userops, counted separately,
//   * per-instruction "address length mnemonic" listings that
//     tools/oracle_compare.py diffs against the GNU tic6x disassembler.
//
// It accepts an external image so that private firmware can be tested without
// committing it:
//
//   C6000CorpusTest.java stage1
//   C6000CorpusTest.java stage2
//   C6000CorpusTest.java image <path> <base> <startOffset> <length>
//
// Nothing firmware-derived is written back into the repository.

import java.io.File;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.Map;
import java.util.TreeMap;

import c6000.C6000PacketContext;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class C6000CorpusTest extends GhidraScript {

	/** Images live outside the repository; see README.md. */
	private static final long STAGE1_BASE = 0x11801da0L;
	private static final long STAGE2_BASE = 0xC0000000L;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		String mode = args.length == 0 ? "all" : args[0];

		if (mode.equals("stage1") || mode.equals("all")) {
			checkImage("stage1", STAGE1_BASE, 0L, 0x3000L);
		}
		if (mode.equals("stage2") || mode.equals("all")) {
			checkImage("stage2", STAGE2_BASE, 0L, 0x20000L);
		}
		if (mode.equals("image")) {
			if (args.length != 5) {
				throw new IllegalArgumentException(
					"image mode needs <path> <base> <startOffset> <length>");
			}
			checkImage(args[1], Long.decode(args[2]), Long.decode(args[3]),
				Long.decode(args[4]));
		}
		if (mode.equals("stage1")) {
			println("C6000_STAGE1_OK");
		}
		if (mode.equals("stage2")) {
			println("C6000_STAGE2_OK");
		}
		if (mode.equals("all")) {
			println("C6000_CORPUS_OK");
		}
		if (!mode.equals("stage1") && !mode.equals("stage2") &&
			!mode.equals("all") && !mode.equals("image")) {
			throw new IllegalArgumentException("unknown corpus mode: " + mode);
		}
	}

	/**
	 * Prime the compact-packet context, then linearly decode
	 * [base+startOffset, base+startOffset+length) and report on the result.
	 */
	private void checkImage(String label, long base, long startOffset, long length)
			throws Exception {
		int packets = C6000PacketContext.prime(currentProgram, monitor);
		println("C6000_PACKETS image=" + label + " compactPackets=" + packets);

		Address start = toAddr(base + startOffset);
		if (startOffset < 0 || length <= 0) {
			throw new IllegalArgumentException("offset must be nonnegative and length positive");
		}
		Address end = start.add(length - 1);
		if (currentProgram.getMemory().getBlock(start) == null ||
			!currentProgram.getMemory().getBlock(start).contains(end)) {
			throw new IllegalArgumentException("corpus window exceeds the loaded image");
		}
		AddressSet corpus = new AddressSet(start, end);

		Map<String, Integer> mnemonics = new TreeMap<>();
		Map<String, Integer> placeholderMnemonics = new TreeMap<>();
		int instructions = 0;
		int bytes = 0;
		int placeholders = 0;
		int loopCommands = 0;
		int compact = 0;
		int headerWords = 0;
		int branches = 0;
		int calls = 0;
		int undecoded = 0;
		int undecodedBytes = 0;
		int invalidPcode = 0;

		String outPath = System.getenv("C6000_LISTING");
		PrintWriter listing = null;
		if (outPath != null) {
			listing = new PrintWriter(new File(outPath));
		}

		Address cursor = start;
		while (cursor.compareTo(end) <= 0) {
			if (monitor.isCancelled()) {
				break;
			}
			Instruction insn = currentProgram.getListing().getInstructionAt(cursor);
			if (insn == null) {
				DisassembleCommand command = new DisassembleCommand(cursor, corpus, false);
				command.applyTo(currentProgram, monitor);
				insn = currentProgram.getListing().getInstructionAt(cursor);
			}
			// Ghidra may materialize an invalid pattern as a one-byte
			// BAD-Instruction.  It is not a decoded C6000 instruction and must
			// be counted using the slot width, just like a null decode.
			if (insn != null && insn.getMnemonicString().equals("BAD-Instruction")) {
				insn = null;
			}
			if (insn == null) {
				// Keep the packet cadence after an unknown compact opcode.
				// Advancing four bytes here would skip its 16-bit neighbor and
				// make the following header look undecodable too.
				BigInteger is16 = currentProgram.getProgramContext().getValue(
					currentProgram.getRegister("c_is16"), cursor, false);
				int step = BigInteger.ONE.equals(is16) ? 2 : 4;
				undecoded++;
				undecodedBytes += step;
				if (undecoded <= 8) {
					String raw = step == 2
						? Integer.toHexString(currentProgram.getMemory().getShort(cursor) & 0xffff)
						: Integer.toHexString(currentProgram.getMemory().getInt(cursor));
					println("C6000_UNDECODED " + cursor + " bytes=" + step + " word=0x" +
						raw);
				}
				cursor = cursor.add(step);
				continue;
			}
			String mnemonic = insn.getMnemonicString();
			mnemonics.merge(mnemonic, 1, Integer::sum);
			boolean hasPlaceholder = false;
			boolean hasLoopCommand = false;
			boolean hasZeroWidth = false;
			for (PcodeOp op : insn.getPcode()) {
				if (op.getOpcode() == PcodeOp.CALLOTHER) {
					int id = (int) op.getInput(0).getOffset();
					String userop = currentProgram.getLanguage().getUserDefinedOpName(id);
					hasPlaceholder |= userop.startsWith("c6000_unimpl") ||
						userop.equals("c6000_unimplemented");
					hasLoopCommand |= userop.startsWith("c6000_sp");
				}
				hasZeroWidth |= op.getOutput() != null && op.getOutput().getSize() == 0;
				for (Varnode input : op.getInputs()) {
					hasZeroWidth |= input.getSize() == 0;
				}
			}
			if (hasPlaceholder) {
				placeholders++;
				placeholderMnemonics.merge(mnemonic, 1, Integer::sum);
			}
			if (hasLoopCommand) loopCommands++;
			if (hasZeroWidth) invalidPcode++;
			if (mnemonic.equals("CPKT")) {
				headerWords++;
			}
			if (insn.getLength() == 2) {
				compact++;
			}
			if (insn.getFlowType().isCall()) {
				calls++;
			}
			else if (insn.getFlowType().isJump()) {
				branches++;
			}
			if (listing != null) {
				listing.printf("%08x %d %s%n", cursor.getOffset(),
					insn.getLength(), mnemonic);
			}
			instructions++;
			bytes += insn.getLength();
			cursor = cursor.add(insn.getLength());
		}
		if (listing != null) {
			listing.close();
		}

		int pct = instructions == 0 ? 0 : (placeholders * 100) / instructions;
		println("C6000_COVERAGE image=" + label + " instructions=" + instructions +
			" bytes=" + bytes + " compact16=" + compact + " headerWords=" +
			headerWords + " placeholders=" + placeholders + " (" + pct +
			"%) loopCommands=" + loopCommands + " branches=" + branches + " calls=" + calls +
			" undecoded=" + undecoded + " undecodedBytes=" + undecodedBytes);
		if (invalidPcode != 0) {
			throw new IllegalStateException(invalidPcode +
				" decoded instructions contain zero-width p-code operands");
		}
		println("C6000_PCODE_OK image=" + label);
		println("C6000_PLACEHOLDERS image=" + label + " " + placeholderMnemonics);
		if (instructions > 0) {
			println("C6000_MNEMONICS image=" + label + " " + mnemonics);
		}
		if (listing == null) {
			println("C6000_HINT set C6000_LISTING=<path> to dump a listing " +
				"for tools/oracle_compare.py");
		}
	}
}
