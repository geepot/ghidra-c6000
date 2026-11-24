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
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Issue #104: a function may keep the link it was entered with in another register and return
 * through that. Whether a register holds that link is a fact about its function, so C6000 Returns,
 * which runs as code is decoded, asks again here once the function exists.
 */
public final class C6000LinkCopyAnalyzer extends AbstractAnalyzer {
	public C6000LinkCopyAnalyzer() {
		super("C6000 Link Copy Returns",
			"Marks a branch through a register that holds its function's entry link as a return",
			AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.before());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C6000PacketContext.isC6000(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		AddressSet bodies = new AddressSet();
		for (Function function : program.getFunctionManager().getFunctions(set, true)) bodies.add(function.getBody());
		int recovered = C6000ReturnAnalyzer.recover(program, bodies, monitor);
		if (recovered > 0) Msg.info(this, getName() + "> recovered " + recovered + " return(s)");
		return true;
	}
}
