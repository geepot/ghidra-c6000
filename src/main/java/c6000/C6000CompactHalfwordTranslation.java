// SPDX-License-Identifier: Apache-2.0
package c6000;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.IncompatibleLanguageException;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.LanguageTranslatorAdapter;
import ghidra.util.task.TaskMonitor;

/**
 * Big-endian language version 1 to 2 (issue #31). Version 2 decodes each compact
 * slot from its halfword in context; version 1 read the slot's own address, which
 * holds the other instruction of the word. Context fields carry over by name.
 */
abstract class C6000CompactHalfwordTranslation extends LanguageTranslatorAdapter {
	C6000CompactHalfwordTranslation(String id) {
		super(new LanguageID(id), 1, new LanguageID(id), 2);
	}

	@Override
	public boolean isValid() {
		if (!super.isValid()) return false;
		try {
			validateDefaultSpaceMap();
			return true;
		}
		catch (IncompatibleLanguageException e) {
			return false;
		}
	}

	@Override
	public void fixupInstructions(Program program, Language oldLanguage, TaskMonitor monitor)
			throws Exception {
		// Ghidra has re-decoded without c_h16. Prime it, then re-decode in place,
		// which keeps references, overrides and comments. Context is unlocked
		// during the upgrade.
		if (C6000PacketContext.prime(program, monitor) > 0) {
			((ProgramDB) program).getCodeManager().reDisassembleAllInstructions(monitor);
		}
	}
}
