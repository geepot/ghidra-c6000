// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.awt.*;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.*;
import javax.swing.event.*;
import docking.DialogComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

/** A source-bound preview followed by an explicit activation, independent of scripts. */
final class C6000ScheduleDialog extends DialogComponentProvider {
    private final PluginTool tool;
    private final Program program;
    private final Address entry;
    private final JTextArea evidence = new JTextArea(4, 48);
    private final JTextField writes = new JTextField();
    private final JTextField sourceStart = new JTextField();
    private final JTextField sourceEnd = new JTextField();
    private final JTextArea summary = new JTextArea(5, 48);
    private final JButton preview = new JButton("Preview schedule");
    private final AtomicReference<TaskMonitor> pendingMonitor = new AtomicReference<>();
    private C6000PipelineContracts.Review reviewed;
    private boolean busy;
    private volatile boolean closed;

    C6000ScheduleDialog(PluginTool tool, Program program, Function function) {
        super("Review C6000 Exact Schedule", true);
        this.tool = tool;this.program = program;entry = function.getEntryPoint();
        program.addConsumer(this);
        setHelpLocation(new HelpLocation("C6000", "Schedules"));
        var content = new JPanel(new BorderLayout(8, 12));
        content.add(new JLabel(function.getName() + " @ " + entry + " — " + program.getLanguageID()), BorderLayout.NORTH);
        var fields = new JPanel(new GridBagLayout());
        evidence.setLineWrap(true);evidence.setWrapStyleWord(true);
        evidence.getAccessibleContext().setAccessibleName("Evidence for an empty incoming pipeline");
        evidence.setToolTipText("Explain why all previous instructions and transfers have completed before this function starts");
        writes.setToolTipText("GPRs written in the preceding E1 cycle, separated by commas; leave empty if none");
        sourceStart.setText(Long.toHexString(entry.getOffset() & ~31L));
        sourceEnd.setText(Long.toHexString((entry.getOffset() & ~31L) + 31));
        row(fields, 0, "Evidence for an empty incoming pipeline", new JScrollPane(evidence));
        row(fields, 1, "Previous-cycle register writes", writes);
        row(fields, 2, "Evidence bytes: start address", sourceStart);
        row(fields, 3, "Evidence bytes: inclusive end address", sourceEnd);
        content.add(fields, BorderLayout.CENTER);
        summary.setEditable(false);summary.setLineWrap(true);summary.setWrapStyleWord(true);
        summary.setText("A function boundary does not prove an empty pipeline. Describe the entry evidence and pin its source bytes.\n\nPreview is read-only. Enabling rechecks the preview and records an undoable, per-function contract.");
        if (C6000PipelineContracts.isRecorded(program, function)) {
            try {
                var stored = C6000PipelineContracts.recordedReview(program, function);
                evidence.setText(stored.evidence());writes.setText(String.join(", ", stored.previousE1Writes()));
                if (stored.entrySources().size() == 1) {
                    var source = stored.entrySources().get(0);
                    sourceStart.setText(Long.toHexString(source.start()));
                    sourceEnd.setText(Long.toHexString(source.start() + source.length() - 1));
                    summary.setText("Previous review inputs restored. Check the evidence, then preview again to validate the current program. Nothing has been enabled or renewed.");
                } else summary.setText(stored.entrySources().size() > 1 ?
                    "This review pins multiple evidence ranges. Use its API/batch workflow to preserve every source assumption." :
                    "Previous entry evidence restored. Choose source bytes and preview again before renewing the review.");
            } catch (IllegalArgumentException invalid) {
                summary.setText("The stored review is invalid: " + invalid.getMessage() + "\nDisable it before creating a fresh review.");
            }
        }
        summary.getAccessibleContext().setAccessibleName("Schedule preview result");
        content.add(new JScrollPane(summary), BorderLayout.SOUTH);
        addWorkPanel(content);addButton(preview);addOKButton();setOkButtonText("Enable reviewed schedule");addCancelButton();
        setOkEnabled(false);
        preview.addActionListener(e -> preview());
        DocumentListener edited = new DocumentListener() {
            private void changed() { reviewed = null;setOkEnabled(false);summary.setText("Inputs changed. Preview again before enabling the schedule."); }
            @Override public void insertUpdate(DocumentEvent e) { changed(); }
            @Override public void removeUpdate(DocumentEvent e) { changed(); }
            @Override public void changedUpdate(DocumentEvent e) { changed(); }
        };
        for (var field : new JTextField[] {writes, sourceStart, sourceEnd}) field.getDocument().addDocumentListener(edited);
        evidence.getDocument().addDocumentListener(edited);
    }
    private static void row(JPanel panel, int y, String title, JComponent field) {
        var constraints = new GridBagConstraints();constraints.gridx = 0;constraints.gridy = y * 2;
        constraints.anchor = GridBagConstraints.WEST;constraints.insets = new Insets(4, 0, 3, 0);
        var label = new JLabel(title);label.setLabelFor(field);panel.add(label, constraints);
        constraints.gridy++;constraints.weightx = 1;constraints.fill = GridBagConstraints.HORIZONTAL;
        panel.add(field, constraints);
    }
    private void setBusy(boolean value) {
        busy = value;preview.setEnabled(!value);evidence.setEditable(!value);writes.setEditable(!value);
        sourceStart.setEditable(!value);sourceEnd.setEditable(!value);setOkEnabled(!value && reviewed != null && C6000ProgramActions.canModify(program));
    }
    private void preview() {
        if (busy) return;
        if (evidence.getText().isBlank()) { setStatusText("Describe the evidence for an empty incoming pipeline");return; }
        String reason = evidence.getText().trim(), registers = writes.getText();
        Address start, end;
        try {
            start = program.getAddressFactory().getAddress(sourceStart.getText().trim());
            end = program.getAddressFactory().getAddress(sourceEnd.getText().trim());
            if (start == null || end == null) throw new IllegalArgumentException();
        } catch (IllegalArgumentException invalid) { setStatusText("Enter valid hexadecimal evidence addresses");return; }
        reviewed = null;setBusy(true);setStatusText("Checking source and supported instruction phases...");
        tool.execute(new Task("Preview C6000 exact schedule", true, false, true) {
            { program.addConsumer(this); }
            @Override public void run(TaskMonitor monitor) {
                pendingMonitor.set(monitor);
                if (closed) monitor.cancel();
                C6000PipelineContracts.Review result = null;String error = null;
                try { result = C6000ProgramActions.preview(program, entry, reason, registers, start, end, monitor);
                } catch (CancelledException cancelled) { error = "Preview cancelled";
                } catch (Exception refused) { error = message(refused);
                } finally { pendingMonitor.set(null);program.release(this); }
                var accepted = result;var refusal = error;
                SwingUtilities.invokeLater(() -> {
                    if (closed) return;
                    reviewed = accepted;setBusy(false);
                    if (accepted == null) { summary.setText("Schedule was not enabled.\n\n" + refusal);setStatusText(refusal); }
                    else {
                        summary.setText("Supported exact schedule for " + entry + ".\n\nEntry evidence: " + reason +
                            "\nPrevious-cycle writes: " + (accepted.previousE1Writes().isEmpty() ? "none" : String.join(", ", accepted.previousE1Writes())) +
                            "\nEvidence bytes: " + start + "–" + end + "\n\nReady to enable. Source, ownership and flow will be checked again.");
                        summary.setCaretPosition(0);setStatusText(program.isChangeable() ? "Preview complete — no program changes" : "Preview complete — immutable view; open an editable program to enable");
                    }
                });
            }
        });
    }
    @Override protected void okCallback() {
        if (busy || reviewed == null || !C6000ProgramActions.canModify(program)) return;
        var plan = reviewed;setBusy(true);setStatusText("Enabling the reviewed schedule...");
        tool.execute(new Task("Enable reviewed C6000 schedule", true, false, true) {
            { program.addConsumer(this); }
            @Override public void run(TaskMonitor monitor) {
                pendingMonitor.set(monitor);
                if (closed) monitor.cancel();
                String error = null;
                try { C6000ProgramActions.activate(program, plan, monitor);
                } catch (CancelledException cancelled) { error = "Activation cancelled; changes rolled back";
                } catch (Exception refused) { error = message(refused);
                } finally { pendingMonitor.set(null);program.release(this); }
                var refusal = error;
                SwingUtilities.invokeLater(() -> {
                    if (closed) return;
                    setBusy(false);
                    if (refusal == null) { tool.setStatusInfo("Enabled exact C6000 schedule at " + entry + " (Undo available)");close(); }
                    else { reviewed = null;setOkEnabled(false);summary.setText("Schedule was not enabled.\n\n" + refusal);setStatusText(refusal); }
                });
            }
        });
    }
    private static String message(Throwable error) {
        while (error.getCause() != null && error instanceof java.lang.reflect.InvocationTargetException) error = error.getCause();
        return error.getMessage() == null ? error.toString() : error.getMessage();
    }
    @Override protected void dialogClosed() {
        closed = true;var monitor = pendingMonitor.get();if (monitor != null) monitor.cancel();
        program.release(this);super.dialogClosed();
    }
}
