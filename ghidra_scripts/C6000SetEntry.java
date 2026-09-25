// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Mark a raw binary entry point. In the GUI, run at the desired address;
// in headless Ghidra pass its hexadecimal address as the sole argument.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class C6000SetEntry extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length > 1) throw new IllegalArgumentException("expected at most one entry address");
		if (args.length == 0 && isRunningHeadless()) {
			throw new IllegalArgumentException("headless import requires an entry address");
		}
		Address address = args.length == 0 ? currentAddress :
			toAddr(Long.parseUnsignedLong(args[0], 16));
		if (address == null || !currentProgram.getMemory().contains(address)) {
			throw new IllegalArgumentException("entry address is not in loaded memory");
		}
		currentProgram.getSymbolTable().addExternalEntryPoint(address);
		println("C6000_ENTRY " + address);
	}
}
