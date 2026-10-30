// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import docking.*;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.util.HelpLocation;

/** A lightweight inspector: cursor movement never compiles or changes a program. */
final class C6000Provider extends ComponentProviderAdapter {
    private final C6000Plugin plugin;
    private final JPanel panel = new JPanel(new BorderLayout(8, 12));
    private final JTextArea details = new JTextArea(12, 46);
    private final JTextArea status = new JTextArea(2, 40);
    private final JButton entry = new JButton("Set entry point here");
    private final JButton review = new JButton("Review exact schedule...");
    private final JButton validate = new JButton("Validate review");
    private final JButton disable = new JButton("Disable exact schedule...");
    private Object displayedProgram;
    private Object displayedEntry;
    private long displayedVersion;

    C6000Provider(C6000Plugin plugin) {
        super(plugin.pluginTool(), "C6000 Processor Tools", plugin.getName(), ProgramLocationActionContext.class);
        this.plugin = plugin;
        setTitle("C6000 Processor Tools");
        setDefaultWindowPosition(WindowPosition.RIGHT);
        setHelpLocation(new HelpLocation("C6000", "ProcessorTools"));
        panel.setBorder(new EmptyBorder(12, 12, 12, 12));
        status.setEditable(false);status.setLineWrap(true);status.setWrapStyleWord(true);
        status.setBackground(panel.getBackground());status.setFont(new JLabel().getFont());
        status.getAccessibleContext().setAccessibleName("C6000 operation result");
        details.setEditable(false);details.setLineWrap(true);details.setWrapStyleWord(true);
        details.setBackground(panel.getBackground());details.setFont(new JLabel().getFont().deriveFont(Font.PLAIN));
        details.setMargin(new Insets(4, 4, 4, 4));
        details.getAccessibleContext().setAccessibleName("Current C6000 program and schedule");
        panel.add(new JScrollPane(details), BorderLayout.CENTER);
        var buttons = new JPanel(new GridLayout(0, 1, 4, 6));
        buttons.add(entry);buttons.add(review);buttons.add(validate);buttons.add(disable);
        entry.setToolTipText("Disassemble this address, create its entry function and register an entry point; supports Undo");
        review.setToolTipText("Preview an exact schedule using explicit entry evidence before enabling it");
        validate.setToolTipText("Check whether the recorded review still matches the program");
        entry.addActionListener(e -> plugin.markEntry());
        review.addActionListener(e -> plugin.reviewCurrent());
        validate.addActionListener(e -> plugin.validateCurrent());
        disable.addActionListener(e -> plugin.disableCurrent());
        var bottom = new JPanel(new BorderLayout(0, 10));bottom.add(buttons, BorderLayout.NORTH);bottom.add(status, BorderLayout.SOUTH);
        panel.add(bottom, BorderLayout.SOUTH);
        addToTool();
    }

    @Override public JComponent getComponent() { return panel; }
    @Override public ActionContext getActionContext(MouseEvent event) {
        return new ProgramLocationActionContext(this, plugin.program(), plugin.location(), null, null);
    }
    void message(String text) { status.setText(text);status.setToolTipText(text); }
    void refresh() {
        var program = plugin.program();
        boolean supported = C6000PacketContext.isC6000(program) && !program.isClosed();
        var at = supported && plugin.location() != null ? plugin.location().getAddress() : null;
        var function = at == null ? null : program.getFunctionManager().getFunctionContaining(at);
        var currentEntry = function == null ? null : function.getEntryPoint();
        long version = supported ? program.getModificationNumber() : -1;
        if (displayedProgram != program || !java.util.Objects.equals(displayedEntry, currentEntry) || displayedVersion != version) message(" ");
        displayedProgram = program;displayedEntry = currentEntry;displayedVersion = version;
        boolean address = supported && C6000ProgramActions.supportedAddress(program, at);
        entry.setEnabled(C6000ProgramActions.canSetEntry(program, at));review.setEnabled(address && function != null);
        boolean recorded = function != null && C6000PipelineContracts.isRecorded(program, function);
        validate.setEnabled(address && C6000ProgramActions.hasActiveReview(program, function));
        boolean active = function != null && BigInteger.ONE.equals(program.getProgramContext().getValue(program.getRegister("c_schedule_entry"), function.getEntryPoint(), false));
        disable.setEnabled(address && C6000ProgramActions.canModify(program) && (recorded || active));
        if (!supported) {
            details.setText("Open a C6000 program to inspect processor timing and exact schedules.\n\n" +
                "C6000 decoding and analyzers are available automatically. This panel adds native entry setup and reviewed scheduling.");
            return;
        }
        String variant = program.getLanguage().getLanguageDescription().getVariant();
        boolean c67x = variant.equals("c67x") || variant.equals("c67x-analysis");
        boolean analysis = variant.equals("analysis") || variant.equals("c67x-analysis");
        var text = new StringBuilder(program.getName()).append("\n\n")
            .append("Processor: ").append(c67x ? "C67x / C67x+" : "C64x / C64x+ / C674x").append('\n')
            .append("Language: ").append(program.getLanguageID()).append('\n')
            .append("Cross-path stalls: ").append(c67x ? "absent on C67x" : "modeled in exact schedules").append('\n')
            .append("Floating point: ").append(analysis ? "concise analysis (approximate flags)" : "exact model").append("\n\n");
        if (!program.isChangeable()) text.append("Immutable program view: preview and validation are available; open an editable program to enable changes.\n\n");
        if (at == null) text.append("Select an address in the Listing or Decompiler.");
        else {
            text.append("Address: ").append(at).append('\n');
            var instruction = program.getListing().getInstructionContaining(at);
            if (instruction != null) {
                text.append("Instruction: ").append(instruction).append('\n');
                try {
                    var info = C6000EncodingInfo.describe(instruction);
                    text.append("Fetch packet: ").append(Long.toHexString(info.packet().address()))
                        .append(!info.packet().readable() ? " (header unavailable)" : info.packet().headerBased() ? " (compact header)" : " (full-width)").append('\n');
                } catch (ghidra.program.model.mem.MemoryAccessException unavailable) { text.append("Packet details unavailable at this location\n"); }
            }
            text.append("Function: ").append(function == null ? "not defined" : function.getName() + " @ " + function.getEntryPoint()).append('\n');
            if (function != null) {
                text.append("Exact schedule: ").append(recorded ? (active ? "enabled; validate after edits" : "review recorded") :
                    active ? "legacy activation; review required" : "not enabled").append('\n');
            }
        }
        text.append("\nAll variants share the instruction decoder. C67x instruction-legality filtering and C66x-specific instructions remain known gaps.");
        details.setText(text.toString());details.setCaretPosition(0);
    }
}
