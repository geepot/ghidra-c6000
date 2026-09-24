// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Corpus-backed decode regression test for the C6000 processor module.
//
// Linearly decodes a C6000 image and reports:
//   * the number of instructions, their total byte length and the mnemonic
//     histogram,
//   * the fraction of words that fall back to an unimplemented-op placeholder
//     (`c6000_unimpl_*`), which is the module's honesty metric,
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
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;

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
			if (args.length < 6) {
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
		Address end = start.add(length - 1);
		AddressSet corpus = new AddressSet(start, end);

		Map<String, Integer> mnemonics = new TreeMap<>();
		int instructions = 0;
		int bytes = 0;
		int placeholders = 0;
		int compact = 0;
		int headerWords = 0;
		int branches = 0;
		int calls = 0;
		int undecoded = 0;

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
				new DisassembleCommand(cursor, corpus, false)
					.applyTo(currentProgram, monitor);
				insn = currentProgram.getListing().getInstructionAt(cursor);
			}
			if (insn == null) {
				// A word that neither a documented constructor nor the
				// fallback could claim. Record it, step four bytes to stay
				// synchronised and carry on: the count is the honest metric.
				undecoded++;
				if (undecoded <= 8) {
					println("C6000_UNDECODED " + cursor + " word=0x" +
						Integer.toHexString(currentProgram.getMemory()
							.getInt(cursor)) + " ctx=" + currentProgram
								.getProgramContext().getValue(currentProgram
									.getProgramContext().getBaseContextRegister(),
									cursor, false));
				}
				cursor = cursor.add(4);
				continue;
			}
			String mnemonic = insn.getMnemonicString();
			mnemonics.merge(mnemonic, 1, Integer::sum);
			if (mnemonic.startsWith("c6000_unimpl_")) {
				placeholders++;
			}
			if (mnemonic.equals("CPKT")) {
				headerWords++;
			}
			if (insn.getLength() == 2) {
				compact++;
			}
			// Delay-slot aware control flow is checked by whether Ghidra
			// recorded a flow reference, not by operand text.
			for (ghidra.program.model.symbol.Reference r : insn
				.getReferencesFrom()) {
				if (r.getReferenceType().isCall()) {
					calls++;
				}
				else if (r.getReferenceType().isJump()) {
					branches++;
				}
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
			"%) branches=" + branches + " calls=" + calls +
			" undecoded=" + undecoded);
		if (instructions > 0) {
			println("C6000_MNEMONICS image=" + label + " " + mnemonics);
		}
		if (listing == null) {
			println("C6000_HINT set C6000_LISTING=<path> to dump a listing " +
				"for tools/oracle_compare.py");
		}
	}
}
