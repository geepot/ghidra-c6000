// SPDX-License-Identifier: Apache-2.0
// @category C6000
// Disable Ghidra's unbounded Basic Constant Reference Analyzer on C6000.

import ghidra.app.script.GhidraScript;

public class C6000DisableBasicConstant extends GhidraScript {
	@Override
	protected void run() throws Exception {
		setAnalysisOption(currentProgram, "Basic Constant Reference Analyzer", "false");
		println("C6000_BASIC_CONSTANT_DISABLED");
	}
}
