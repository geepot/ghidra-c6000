/* ###
 * Copyright 2026 ghidra-c6000 contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package c6000;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Primes the compact fetch-packet context before disassembly.
 *
 * <p>This analyzer must run before Ghidra's disassembly pass, because the
 * context it writes changes how each 2-byte slot is decoded. It is enabled by
 * default for C6000 programs.
 */
public class C6000PacketAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "C6000 Compact Fetch Packets";
	private static final String DESCRIPTION =
		"Reads compact fetch-packet header words and primes the decode context " +
			"so that 16-bit compact instructions decode with the correct length.";

	public C6000PacketAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		// Ghidra's Disassemble Entry Points analyzer runs at BLOCK_ANALYSIS.
		// Context must be written before it creates any instruction; otherwise
		// ProgramContext rejects the slot change and compact flow targets decode
		// with the wrong width.
		setPriority(AnalysisPriority.BLOCK_ANALYSIS.before());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C6000PacketContext.isC6000(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		try {
			int n = C6000PacketContext.prime(program, monitor);
			log.appendMsg(NAME, "primed " + n + " compact fetch packet(s)");
			return true;
		}
		catch (Exception e) {
			log.appendException(e);
			return false;
		}
	}
}
