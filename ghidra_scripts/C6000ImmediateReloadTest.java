// SPDX-License-Identifier: Apache-2.0
// @category C6000
//
// Import the assembled tests/fixtures/loop-delay.s as a raw binary at 0x1000.

import java.util.ArrayList;
import java.util.List;

import c6000.C6000LoopBuffer;
import c6000.C6000LoopBuffer.Cycle;
import c6000.C6000LoopBuffer.Operation;
import c6000.C6000LoopBuffer.Origin;
import c6000.C6000LoopBuffer.ReplayResult;
import c6000.C6000PacketContext;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class C6000ImmediateReloadTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		Address base = currentProgram.getAddressFactory().getDefaultAddressSpace()
			.getAddress(0x1000);
		C6000PacketContext.prime(currentProgram, monitor);
		for (int off = 0; off < 0x9c; off += 4) disassemble(base.add(off));
		C6000LoopBuffer loop = C6000LoopBuffer.fromProgram(currentProgram,
			getInstructionAt(base.add(0x80)), getInstructionAt(base.add(0x90)));
		if (!loop.reloadable() || loop.initiationInterval() != 1 ||
			loop.dynamicLength() != 7 || loop.sourcePackets() != 4) {
			throw new AssertionError("wrong immediate reload source");
		}
		List<Cycle> trace = new ArrayList<>();
		ReplayResult result = loop.replayImmediateReload(7, 32, () -> 7,
			cycle -> cycle == 2, trace::add);
		if (result.cycles != 20 || result.reloads != 1 ||
			result.firstPostBodyCycle != 14 || result.remainingIlc != 0 ||
			trace.size() != 20 || !trace.get(6).reloadBoundary ||
			!trace.get(6).terminatingBoundary ||
			trace.get(6).ilcBefore != 0 || trace.get(6).ilcAfter != 6 ||
			trace.get(7).postBodyCycle != 0 ||
			trace.get(7).postBodyInvocation != 0 ||
			trace.get(14).postBodyInvocation != 1 ||
			trace.get(14).overlayPostBody(List.of(
				getInstructionAt(base.add(0x98)))).get(0).invocation != 1) {
			throw new AssertionError("wrong immediate reload control state");
		}
		assertIssued(trace.get(7), "LDW", 1, 0, Origin.BUFFER);
		assertIssued(trace.get(12), "STW", 0, 6, Origin.BUFFER);
		assertIssued(trace.get(12), "MV", 1, 5, Origin.BUFFER);
		assertIssued(trace.get(13), "STW", 1, 6, Origin.BUFFER);
		assertIssued(trace.get(19), "STW", 1, 6, Origin.BUFFER);
		if (!trace.get(13).terminatingBoundary ||
			trace.get(13).reloadBoundary || trace.get(19).reloadBoundary) {
			throw new AssertionError("wrong final invocation boundary");
		}
		List<Cycle> twice = new ArrayList<>();
		ReplayResult repeated = loop.replayImmediateReload(7, 40, () -> 7,
			cycle -> cycle == 2 || cycle == 9, twice::add);
		if (repeated.cycles != 27 || repeated.reloads != 2 ||
			repeated.firstPostBodyCycle != 21 || twice.size() != 27 ||
			!twice.get(13).reloadBoundary) {
			throw new AssertionError("wrong repeated reload schedule");
		}
		assertIssued(twice.get(14), "LDW", 2, 0, Origin.BUFFER);
		assertIssued(twice.get(26), "STW", 2, 6, Origin.BUFFER);
		List<Cycle> longer = new ArrayList<>();
		ReplayResult delayedFinal = loop.replayImmediateReload(7, 32, () -> 10,
			cycle -> cycle == 2, longer::add);
		if (delayedFinal.cycles != 23 || delayedFinal.reloads != 1 ||
			!longer.get(13).postBodyFetchEnabled ||
			longer.get(14).postBodyFetchEnabled ||
			!longer.get(17).postBodyFetchEnabled) {
			throw new AssertionError("wrong reload fetch window");
		}
		println("C6000_IMMEDIATE_RELOAD PASS cycles=20/27/23 reloads=1/2/1");
	}

	private static void assertIssued(Cycle cycle, String mnemonic,
			int invocation, int sourceCycle, Origin origin) {
		for (Operation op : cycle.operations) {
			if (op.instruction.getMnemonicString().contains(mnemonic) &&
				op.invocation == invocation && op.sourceCycle == sourceCycle &&
				op.origin == origin) return;
		}
		throw new AssertionError("missing " + mnemonic + " at cycle " +
			cycle.number + " invocation " + invocation);
	}
}
