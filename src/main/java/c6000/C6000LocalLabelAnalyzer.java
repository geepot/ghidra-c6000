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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.VoidPropertyMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** A recorded TI local symbol that reached code falls into or branches to conditionally, uncalled, is a label (SPRUFE8B 3.12). */
public class C6000LocalLabelAnalyzer extends AbstractAnalyzer {
	public C6000LocalLabelAnalyzer() {
		super("C6000 Local Code Labels",
			"Turns TI ELF local code labels that code falls into or branches to conditionally back into labels",
			AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.CODE_ANALYSIS.after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C6000PacketContext.isC6000(program) &&
			program.getUsrPropertyManager().getVoidPropertyMap(C6000_ElfExtension.LOCAL_CODE_SYMBOLS) != null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		VoidPropertyMap recorded =
			program.getUsrPropertyManager().getVoidPropertyMap(C6000_ElfExtension.LOCAL_CODE_SYMBOLS);
		if (recorded == null) return false;
		var functions = program.getFunctionManager();
		Map<Address, List<Address>> sources = new HashMap<>();
		Map<Address, AddressSetView> bodies = new HashMap<>();
		List<Address> entries = new ArrayList<>();
		for (Address entry : recorded.getPropertyIterator()) entries.add(entry);
		for (Address entry : entries) {
			monitor.checkCancelled();
			Function function = functions.getFunctionAt(entry);
			if (function == null || function.getSymbol().getSource() != SourceType.IMPORTED) {
				recorded.remove(entry);
				continue;
			}
			List<Address> from = labelSources(program, entry);
			if (from == null) {
				recorded.remove(entry);
				continue;
			}
			if (from.isEmpty()) continue;
			sources.put(entry, from);
			bodies.put(entry, new AddressSet(function.getBody()));
		}
		if (sources.isEmpty()) return false;
		for (Address entry : sources.keySet()) {
			functions.removeFunction(entry);
			recorded.remove(entry);
			for (Reference ref : program.getReferenceManager().getReferencesTo(entry)) {
				Instruction jump = program.getListing().getInstructionAt(ref.getFromAddress());
				if (jump != null && jump.getFlowOverride() == FlowOverride.CALL_RETURN) {
					jump.setFlowOverride(FlowOverride.NONE);
				}
			}
		}
		Set<Function> owners = new LinkedHashSet<>();
		for (List<Address> from : sources.values()) {
			for (Address source : from) {
				Function owner = owner(functions, source, sources, bodies, new LinkedHashSet<>());
				if (owner != null) owners.add(owner);
			}
		}
		for (Function owner : owners) {
			monitor.checkCancelled();
			CreateFunctionCmd.fixupFunctionBody(program, owner, monitor);
		}
		return true;
	}

	/** Fall-in and conditional-branch sources of a label; empty if none yet; null if it is called. */
	private static List<Address> labelSources(Program program, Address entry) {
		Instruction at = program.getListing().getInstructionAt(entry);
		if (at == null) return List.of();
		List<Address> from = new ArrayList<>();
		for (Reference ref : program.getReferenceManager().getReferencesTo(entry)) {
			var type = ref.getReferenceType();
			Instruction source = program.getListing().getInstructionAt(ref.getFromAddress());
			if (type.isCall() && (source == null || source.getFlowOverride() != FlowOverride.CALL_RETURN)) {
				return null;
			}
			if (type.isJump() && type.isConditional()) from.add(ref.getFromAddress());
		}
		Address fallFrom = at.getFallFrom();
		if (fallFrom != null && reached(program, fallFrom)) from.add(fallFrom);
		return from;
	}

	/** Whether straight-line code ending at an address starts at a function entry or a flow target, not padding. */
	private static boolean reached(Program program, Address address) {
		for (Address at = address; at != null; ) {
			if (program.getFunctionManager().getFunctionAt(at) != null) return true;
			for (Reference ref : program.getReferenceManager().getReferencesTo(at)) {
				if (ref.getReferenceType().isFlow()) return true;
			}
			Instruction instruction = program.getListing().getInstructionAt(at);
			at = instruction == null ? null : instruction.getFallFrom();
		}
		return false;
	}

	/** The function a source lies in, looking through sources inside other dropped labels' bodies. */
	private static Function owner(ghidra.program.model.listing.FunctionManager functions, Address source,
			Map<Address, List<Address>> sources, Map<Address, AddressSetView> bodies, Set<Address> seen) {
		for (var dropped : bodies.entrySet()) {
			if (!dropped.getValue().contains(source) || !seen.add(dropped.getKey())) continue;
			for (Address next : sources.get(dropped.getKey())) {
				Function owner = owner(functions, next, sources, bodies, seen);
				if (owner != null) return owner;
			}
			return null;
		}
		return functions.getFunctionContaining(source);
	}
}
