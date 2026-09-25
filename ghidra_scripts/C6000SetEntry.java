// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Mark a raw binary entry point before headless auto-analysis. Usage: <hexaddr>

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class C6000SetEntry extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 1) throw new IllegalArgumentException("expected entry address");
		Address address = toAddr(Long.parseUnsignedLong(args[0], 16));
		currentProgram.getSymbolTable().addExternalEntryPoint(address);
		println("C6000_ENTRY " + address);
	}
}
