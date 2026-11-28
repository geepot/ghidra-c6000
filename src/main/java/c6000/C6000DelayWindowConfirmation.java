// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.util.Collections;
import java.util.Set;
import java.util.WeakHashMap;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The full delay-window pass that confirms incremental recovery, queued as a one-time analysis task
 * behind every other analyzer. AutoAnalysisManager runs its queue highest priority first and, once the
 * queue is empty, ends analysis without looking at it again; so this runs when nothing else is left to
 * do, and analysis cannot end while an incremental pass is unconfirmed. What it repairs changes the
 * program, which queues the analyzers that react to it, as a repair mid-analysis would have; their
 * next incremental pass queues another confirmation. Analysis therefore ends only after a full pass has
 * found nothing to repair, the fixed point every pass used to be full for.
 * <p>
 * Not named *Analyzer, so Ghidra does not register it as an analyzer of its own.
 */
final class C6000DelayWindowConfirmation extends AbstractAnalyzer {
	/** Behind every analyzer: the lowest built-in priority is LOW_PRIORITY. */
	private static final AnalysisPriority LAST =
		new AnalysisPriority("C6000 delay-window confirmation", Integer.MAX_VALUE / 2);

	private static final Set<Program> QUEUED = Collections.synchronizedSet(Collections.newSetFromMap(new WeakHashMap<>()));

	private C6000DelayWindowConfirmation() {
		super("C6000 Delay-Window Confirmation", "Checks every delay window once after incremental recovery",
			AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(LAST);
	}

	/** Queue the confirmation for {@code program} unless it is queued already; false if no task could be queued. */
	static boolean queue(Program program) {
		if (!QUEUED.add(program)) return true;
		AutoAnalysisManager analysis = AutoAnalysisManager.getAnalysisManager(program);
		if (analysis == null) {
			QUEUED.remove(program);
			return false;
		}
		analysis.scheduleOneTimeAnalysis(new C6000DelayWindowConfirmation(), new AddressSet());
		return true;
	}

	/** Analysis has ended: a confirmation still queued will not run (analysis was cancelled, say). */
	static void forget(Program program) {
		QUEUED.remove(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		QUEUED.remove(program);
		try {
			C6000DelaySlots.confirm(program, monitor, log);
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (Exception e) {
			Msg.error(this, "C6000 delay-window confirmation failed", e);
		}
		return true;
	}
}
