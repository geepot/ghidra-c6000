// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.awt.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import javax.swing.*;
import docking.action.DockingActionIf;
import ghidra.*;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.ProgramManager;
import ghidra.base.help.GhidraHelpService;
import ghidra.base.project.GhidraProject;
import ghidra.framework.*;
import ghidra.framework.project.tool.GhidraTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.*;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.*;

/** Headed, real PluginTool integration. Only generated fixture programs are opened. */
public class C6000GuiIntegration implements GhidraLaunchable {
    private GhidraTool tool;
    private GhidraProject project;
    private ProgramDB program, other, foreign;
    private C6000Plugin plugin;
    private int checks;
    private Path work;
    interface Throwing { void run() throws Exception; }
    private void check(boolean condition, String message) { if (!condition) throw new AssertionError(message);checks++; }
    private void swing(Throwing action) throws Exception {
        var error = new AtomicReference<Throwable>();
        SwingUtilities.invokeAndWait(() -> { try { action.run(); } catch (Throwable failure) { error.set(failure); } });
        if (error.get() != null) throw new AssertionError("Swing operation failed", error.get());
    }
    private void waitFor(BooleanSupplier ready, String label) throws Exception {
        long deadline = System.nanoTime() + 30_000_000_000L;
        while (System.nanoTime() < deadline) {
            var accepted = new AtomicReference<Boolean>();swing(() -> accepted.set(ready.getAsBoolean()));
            if (accepted.get()) return;
            Thread.sleep(50);
        }
        throw new AssertionError("Timed out waiting for " + label);
    }
    private DockingActionIf action(String name) {
        return tool.getDockingActionsByOwnerName("C6000Plugin").stream().filter(a -> a.getName().equals(name)).findFirst().orElseThrow();
    }
    private ProgramLocationActionContext context(Program p, long offset) {
        return new ProgramLocationActionContext(tool.getComponentProvider("C6000 Processor Tools"), p,
            new ProgramLocation(p, p.getAddressFactory().getDefaultAddressSpace().getAddress(offset)), null, null);
    }
    private ProgramDB create(String id, String name, String image) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
        var p = new ProgramDB(name, language, language.getDefaultCompilerSpec(), this);
        int tx = p.startTransaction("Synthetic fixture");
        try {
            byte[] bytes = Files.readAllBytes(work.resolve(image));
            p.getMemory().createInitializedBlock("code", p.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000),
                new ByteArrayInputStream(bytes), bytes.length, TaskMonitor.DUMMY, false).setExecute(true);
            p.getMemory().createInitializedBlock("entry_evidence", p.getAddressFactory().getDefaultAddressSpace().getAddress(0x9000),
                32, (byte) 0, TaskMonitor.DUMMY, false);
            GhidraProgramUtilities.markProgramAnalyzed(p);
        } finally { p.endTransaction(tx, true); }
        return p;
    }
    private List<Component> descendants(Container root) {
        var result = new ArrayList<Component>();
        for (var child : root.getComponents()) { result.add(child);if (child instanceof Container container) result.addAll(descendants(container)); }
        return result;
    }
    private JDialog reviewWindow() { return dialog("Review C6000 Exact Schedule"); }
    private JDialog dialog(String title) {
        for (var window : Window.getWindows()) if (window instanceof JDialog dialog && dialog.isShowing() &&
            dialog.getTitle().equals(title)) return dialog;
        return null;
    }
    private JButton button(Container root, String text) {
        return descendants(root).stream().filter(c -> c instanceof JButton b && b.getText().equals(text)).map(c -> (JButton)c).findFirst().orElseThrow();
    }
    private void capture(Component component, String filename) throws Exception {
        var image = new java.awt.image.BufferedImage(component.getWidth(), component.getHeight(), java.awt.image.BufferedImage.TYPE_INT_RGB);
        var graphics = image.createGraphics();component.paintAll(graphics);graphics.dispose();
        javax.imageio.ImageIO.write(image, "png", work.resolve(filename).toFile());
    }
    private void dialogFlow(ProgramDB program, Function function) throws Exception {
        int consumersBefore = program.getConsumerList().size();
        swing(() -> { ((C6000Provider) tool.getComponentProvider("C6000 Processor Tools")).refresh();capture(tool.getToolFrame(), "processor-panel.png"); });
        SwingUtilities.invokeLater(() -> action("Review C6000 Exact Schedule").actionPerformed(context(program, 0x1000)));
        waitFor(() -> reviewWindow() != null, "native review dialog");
        var window = new AtomicReference<JDialog>();swing(() -> window.set(reviewWindow()));
        swing(() -> {
            check(!button(window.get(), "Enable reviewed schedule").isEnabled(), "Activation enabled before preview");
            button(window.get(), "Preview schedule").doClick();
            check(!button(window.get(), "Enable reviewed schedule").isEnabled(), "Blank entry evidence accepted");
            var evidence = descendants(window.get()).stream().filter(c -> c instanceof JTextArea text && text.isEditable()).map(c -> (JTextArea)c).findFirst().orElseThrow();
            evidence.setText("Synthetic reset entry has no pending instructions or transfers");
            var label = descendants(window.get()).stream().filter(c -> c instanceof JLabel l && l.getText().equals("Evidence bytes: start address")).map(c -> (JLabel)c).findFirst().orElseThrow();
            var start = (JTextField)label.getLabelFor();start.setText("not-an-address");
            button(window.get(), "Preview schedule").doClick();
            check(!button(window.get(), "Enable reviewed schedule").isEnabled(), "Invalid source address accepted");
            start.setText("1000");button(window.get(), "Preview schedule").doClick();
        });
        waitFor(() -> button(window.get(), "Enable reviewed schedule").isEnabled(), "read-only schedule preview");
        check(!C6000PipelineContracts.isRecorded(program, function), "GUI preview changed the program");
        swing(() -> capture(window.get(), "schedule-review.png"));
        swing(() -> button(window.get(), "Enable reviewed schedule").doClick());
        waitFor(() -> !window.get().isShowing(), "GUI activation completion");
        quiet(program);
        check(C6000PipelineContracts.isRecorded(program, function), "GUI activation did not record review");
        C6000ProgramActions.validate(program, function.getEntryPoint(), TaskMonitor.DUMMY);checks++;
        SwingUtilities.invokeLater(() -> action("Review C6000 Exact Schedule").actionPerformed(context(program, 0x1000)));
        waitFor(() -> reviewWindow() != null, "renewal dialog");
        swing(() -> {
            var renewal = reviewWindow();
            var evidence = descendants(renewal).stream().filter(c -> c instanceof JTextArea text && text.isEditable()).map(c -> (JTextArea)c).findFirst().orElseThrow();
            check(evidence.getText().equals("Synthetic reset entry has no pending instructions or transfers"), "Renewal lost previous evidence");
            check(!button(renewal, "Enable reviewed schedule").isEnabled(), "Stored review bypassed fresh preview");
            button(renewal, "Cancel").doClick();
        });
        decompileInTool(program, function, "exact");
        history(program, "Undo");
        check(!C6000PipelineContracts.isRecorded(program, function), "GUI activation was not one undoable change");
        quiet(program);
        check(program.getConsumerList().size() == consumersBefore, "Review dialog leaked a program consumer");
    }
    private void decompileInTool(ProgramDB program, Function function, String stage) throws Exception {
        String className = "ghidra.app.plugin.core.decompile.DecompilePlugin";
        var provider = new AtomicReference<ghidra.app.plugin.core.decompile.DecompilerProvider>();
        swing(() -> {
            tool.addPlugin(className);
            provider.set((ghidra.app.plugin.core.decompile.DecompilerProvider)tool.getComponentProvider("Decompiler"));
            tool.showComponentProvider(provider.get(), true);
            check(provider.get().goTo(program, new ProgramLocation(program, function.getEntryPoint())), "Decompiler could not navigate to function");
        });
        try {
            waitFor(() -> !provider.get().getController().isDecompiling() && provider.get().getController().hasDecompileResults() &&
                function.equals(provider.get().getController().getFunction()), stage + " decompilation in native provider");
            swing(() -> {
                var result = provider.get().getController().getDecompileData().getDecompileResults();
                check(result.decompileCompleted(), "Native decompiler failed: " + result.getErrorMessage());
                check(result.getHighFunction() != null && result.getDecompiledFunction() != null, "Native decompiler has no usable result");
                String code = result.getDecompiledFunction().getC();
                check(!code.contains("c6000_pipeline") && !code.contains("c6000_schedule"), "Schedule helper leaked into native decompiler output");
                Files.writeString(work.resolve(stage + "-" + program.getLanguage().getLanguageDescription().getEndian() + ".c"), code);
                capture(tool.getToolFrame(), stage + "-decompiler.png");
                check(action("Review C6000 Exact Schedule").isEnabledForContext(provider.get().getActionContext(null)), "Review action unavailable in the Decompiler context");
            });
        } finally {
            swing(() -> tool.removePlugins(tool.getManagedPlugins().stream().filter(p -> p.getClass().getName().equals(className)).toList()));
        }
    }
    private JTextArea operationStatus() {
        var provider = tool.getComponentProvider("C6000 Processor Tools");
        return descendants(provider.getComponent()).stream().filter(c -> c instanceof JTextArea text &&
            "C6000 operation result".equals(text.getAccessibleContext().getAccessibleName())).map(c -> (JTextArea)c).findFirst().orElseThrow();
    }
    private void resourceRefusalDialogs() throws Exception {
        // SPRUFE8B 3.6/3.8.1/3.8.5: both complementary predicates still
        // allocate the issue unit and memory-transfer path in their packet.
        transaction(program, "Invalid physical resource fixtures", () -> {
            var memory = program.getMemory();
            var base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0xa000);
            memory.createInitializedBlock("resource_conflicts", base, 256, (byte)0, TaskMonitor.DUMMY, false);
            for (int n = 0; n < 2; n++) {
                var at = base.add(128*n);
                memory.setInt(at, n == 0 ? 0x23100fd9 : 0x23100265);
                memory.setInt(at.add(4), n == 0 ? 0x33900fd8 : 0x339002f4);
                memory.setInt(at.add(8), 0xc0362);memory.setInt(at.add(12), 0x8000);
                new ghidra.app.cmd.disassemble.DisassembleCommand(at, new AddressSet(at, at.add(3)), false).applyTo(program, TaskMonitor.DUMMY);
                program.getFunctionManager().createFunction("invalid_resources_"+n, at, new AddressSet(at, at.add(127)), SourceType.USER_DEFINED);
            }
        });
        quiet();
        for (int n = 0; n < 2; n++) {
            long offset = 0xa000+128*n;String refusal = n == 0 ? "functional-unit collision" : "memory-transfer path collision";
            var at = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
            var function = program.getFunctionManager().getFunctionAt(at);
            int consumers = program.getConsumerList().size();long version = program.getModificationNumber();
            swing(() -> tool.firePluginEvent(new ProgramLocationPluginEvent("test", new ProgramLocation(program, at), program)));
            SwingUtilities.invokeLater(() -> action("Review C6000 Exact Schedule").actionPerformed(context(program, offset)));
            waitFor(() -> reviewWindow() != null, "resource refusal review dialog");
            swing(() -> {
                var evidence = descendants(reviewWindow()).stream().filter(c -> c instanceof JTextArea text && text.isEditable()).map(c -> (JTextArea)c).findFirst().orElseThrow();
                evidence.setText("Synthetic reset has no incoming effects");button(reviewWindow(), "Preview schedule").doClick();
            });
            waitFor(() -> descendants(reviewWindow()).stream().anyMatch(c -> c instanceof JTextArea text && !text.isEditable() && text.getText().contains(refusal)), refusal+" displayed in preview");
            swing(() -> {
                check(!button(reviewWindow(), "Enable reviewed schedule").isEnabled(), "Invalid resource preview enabled activation");
                capture(reviewWindow(), "resource-refusal-"+offset+".png");button(reviewWindow(), "Cancel").doClick();
            });
            quiet();
            check(version == program.getModificationNumber(), "Refused resource preview mutated the program");
            check(!C6000PipelineContracts.isRecorded(program, function), "Refused resource preview recorded a contract");
            check(program.getConsumerList().size() == consumers, "Refused resource dialog leaked a consumer");
        }
        swing(() -> tool.firePluginEvent(new ProgramLocationPluginEvent("test", new ProgramLocation(program, program.getMinAddress()), program)));
    }
    private void cancelledReviewFlow() throws Exception {
        int consumers = program.getConsumerList().size();long version = program.getModificationNumber();
        SwingUtilities.invokeLater(() -> action("Review C6000 Exact Schedule").actionPerformed(context(program, 0x1000)));
        waitFor(() -> reviewWindow() != null, "cancellable review dialog");
        var window = new AtomicReference<JDialog>();swing(() -> window.set(reviewWindow()));
        var evidence = new AtomicReference<JTextArea>();
        swing(() -> {
            evidence.set(descendants(window.get()).stream().filter(c -> c instanceof JTextArea text && text.isEditable()).map(c -> (JTextArea)c).findFirst().orElseThrow());
            evidence.get().setText("Synthetic reset has no incoming effects");button(window.get(), "Preview schedule").doClick();
        });
        waitFor(() -> button(window.get(), "Enable reviewed schedule").isEnabled(), "cancellable preview");
        swing(() -> {
            evidence.get().append("; reviewer changed the evidence");
            check(!button(window.get(), "Enable reviewed schedule").isEnabled(), "Editing evidence did not invalidate preview");
            button(window.get(), "Cancel").doClick();
        });
        quiet();check(program.getModificationNumber() == version, "Cancelled review changed the program");
        check(program.getConsumerList().size() == consumers, "Cancelled dialog leaked a consumer");
    }
    private void validationStatus() throws Exception {
        swing(() -> action("Validate C6000 Exact Schedule").actionPerformed(context(program, 0x1000)));
        waitFor(() -> operationStatus().getText().startsWith("Review is current"), "native validation result");checks++;
        swing(() -> {
            tool.firePluginEvent(new ProgramLocationPluginEvent("test", new ProgramLocation(program, program.getAddressFactory().getDefaultAddressSpace().getAddress(0x9000)), program));
            ((C6000Provider)tool.getComponentProvider("C6000 Processor Tools")).refresh();
            check(operationStatus().getText().isBlank(), "Validation result leaked to another function/location");
            tool.firePluginEvent(new ProgramLocationPluginEvent("test", new ProgramLocation(program, program.getMinAddress()), program));
        });
        swing(() -> action("Validate C6000 Exact Schedule").actionPerformed(context(program, 0x1000)));
        waitFor(() -> operationStatus().getText().startsWith("Review is current"), "second native validation");
        transaction(program, "Change annotation after validation", () -> program.getListing().setComment(program.getMinAddress(), CommentType.EOL, "validation status invalidation"));
        swing(() -> {
            ((C6000Provider)tool.getComponentProvider("C6000 Processor Tools")).refresh();
            check(operationStatus().getText().isBlank(), "Validation success survived a program modification");
        });
    }
    private void disableWithConfirmation(Function function) throws Exception {
        long version = program.getModificationNumber();int consumers = program.getConsumerList().size();
        SwingUtilities.invokeLater(() -> action("Disable C6000 Exact Schedule").actionPerformed(context(program, 0x1000)));
        waitFor(() -> dialog("Disable Exact Schedule") != null, "disable confirmation");
        swing(() -> button(dialog("Disable Exact Schedule"), "No").doClick());
        quiet();
        check(C6000ProgramActions.hasActiveReview(program, function) && program.getModificationNumber() == version, "Declining disable changed the program");
        SwingUtilities.invokeLater(() -> action("Disable C6000 Exact Schedule").actionPerformed(context(program, 0x1000)));
        waitFor(() -> dialog("Disable Exact Schedule") != null, "second disable confirmation");
        swing(() -> button(dialog("Disable Exact Schedule"), "Yes").doClick());
        waitFor(() -> !C6000PipelineContracts.isRecorded(program, function), "confirmed native disable");
        quiet();check(program.getConsumerList().size() == consumers, "Disable task leaked a program consumer");
    }
    private void history(String name) throws Exception { history(program, name); }
    private void history(ProgramDB program, String name) throws Exception {
        quiet(program);
        swing(() -> {
            var action = tool.getAllActions().stream().filter(a -> a.getName().equals(name) && a.getOwner().equals("ProgramManagerPlugin")).findFirst().orElseThrow();
            check(action.isEnabledForContext(context(program, 0x1000)), name + " action is disabled");
            action.actionPerformed(context(program, 0x1000));
        });
        quiet(program);
    }
    private void quiet() throws Exception { quiet(program); }
    private void quiet(ProgramDB program) throws Exception {
        for (int attempt = 0; attempt < 10; attempt++) {
            program.flushEvents();
            AutoAnalysisManager.getAnalysisManager(program).waitForAnalysis(null, TaskMonitor.DUMMY);
            long before = program.getModificationNumber();Thread.sleep(250);
            if (before == program.getModificationNumber() && !AutoAnalysisManager.getAnalysisManager(program).isAnalyzing() && program.getCurrentTransactionInfo() == null) return;
        }
        throw new AssertionError("Program did not become idle");
    }
    private void transaction(Program p, String name, Throwing work) throws Exception {
        int tx = p.startTransaction(name);boolean commit = false;
        try { work.run();commit = true; } finally { p.endTransaction(tx, commit); }
    }
    @Override public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
        work = Path.of(args[0]);
        var configuration = new GhidraApplicationConfiguration();configuration.setShowSplashScreen(false);
        Application.initializeApplication(layout, configuration);GhidraHelpService.install();
        try { run();Files.writeString(work.resolve("result.txt"), "C6000_GUI_INTEGRATION_OK checks=" + checks + "\n");System.out.println("C6000_GUI_INTEGRATION_OK checks=" + checks);
        } catch (Throwable error) { error.printStackTrace();Files.writeString(work.resolve("failure.txt"), error.toString());System.exit(1);
        } finally {
            if (tool != null) swing(() -> tool.dispose());
            if (program != null) program.release(this);
            if (other != null) other.release(this);
            if (foreign != null) foreign.release(this);
            if (project != null) project.close();
        }
        System.exit(0);
    }
    private void run() throws Exception {
        check(ClassSearcher.getClasses(ghidra.framework.plugintool.Plugin.class).contains(C6000Plugin.class), "Native plugin was not discovered from the packaged extension");
        check(ClassSearcher.getClasses(ghidra.app.services.Analyzer.class).contains(C6000PacketAnalyzer.class), "Packet analyzer was not discovered");
        check(C6000Plugin.class.getResource("/help/C6000_HelpSet.hs") != null, "Native help was not packaged");
        project = GhidraProject.createProject(work.toString(), "native-ui", true);
        program = create("C6000:LE:32:c67x", "C67x UI fixture", "le.bin");
        other = create("C6000:BE:32:default", "C64x UI fixture", "be.bin");
        foreign = create("x86:LE:64:default", "Unrelated program", "le.bin");
        swing(() -> {
            tool = new GhidraTool(project.getProject(), "C6000 Native Integration");
            tool.addPlugins(List.of("ghidra.app.plugin.core.progmgr.ProgramManagerPlugin",
                "ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin", "ghidra.app.plugin.core.analysis.AutoAnalysisPlugin", C6000Plugin.class.getName()));
            plugin = (C6000Plugin) tool.getManagedPlugins().stream().filter(p -> p instanceof C6000Plugin).findFirst().orElseThrow();
            tool.getToolFrame().setSize(1100, 800);tool.setVisible(true);
            plugin.showProvider();
            check(action("Review C6000 Exact Schedule").supportsDefaultContext(), "Native action lacks default program-context support");
            check(!action("Review C6000 Exact Schedule").isEnabledForContext(context(program, 0x1000)), "Review enabled without a function");
            tool.getService(ProgramManager.class).openProgram(program);
            tool.firePluginEvent(new ProgramLocationPluginEvent("test", new ProgramLocation(program, program.getMinAddress()), program));
        });
        waitFor(() -> plugin.program() == program, "program activation");
        check(program.getRegister("c_is16").isHidden() && program.getRegister("C6000_PIPE_RET").isHidden(), "Internal state is not hidden in the native register model");
        check(!program.getRegister("A4").isHidden(), "Architectural registers were hidden");
        check(C6000ProgramActions.supportedAddress(program, program.getMinAddress()), "Valid address disabled");
        swing(() -> check(!action("Set C6000 Entry Point").isEnabledForContext(context(program, 0x9002)), "Entry action enabled at a halfword inside an ordinary instruction slot"));
        var invalidSlot = new C6000ProgramActions.SetEntry(program.getAddressFactory().getDefaultAddressSpace().getAddress(0x9002));
        check(!invalidSlot.applyTo(program, TaskMonitor.DUMMY), "Entry command accepted a misaligned full-width slot");
        check(program.getListing().getInstructionAt(program.getAddressFactory().getDefaultAddressSpace().getAddress(0x9002)) == null, "Invalid entry command left an instruction");
        // Invoke the actual CodeBrowser entry action and let its normal analyzer pipeline finish.
        swing(() -> { var action = action("Set C6000 Entry Point");check(action.isEnabledForContext(context(program, 0x1000)), "Entry action disabled");action.actionPerformed(context(program, 0x1000)); });
        waitFor(() -> program.getFunctionManager().getFunctionAt(program.getMinAddress()) != null &&
            program.getSymbolTable().isExternalEntryPoint(program.getMinAddress()), "native entry command");
        quiet();
        var function = program.getFunctionManager().getFunctionAt(program.getMinAddress());
        check(function != null, "Entry function missing");
        swing(() -> check(!action("Set C6000 Entry Point").isEnabledForContext(context(program, 0x1004)), "Entry action enabled in a function interior"));
        swing(() -> check(action("Review C6000 Exact Schedule").isEnabledForContext(context(program, 0x1000)), "Native review action unavailable"));
        decompileInTool(program, function, "ordinary");
        resourceRefusalDialogs();
        cancelledReviewFlow();
        dialogFlow(program, function);
        long before = program.getModificationNumber();
        var evidenceAt = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x9000);
        transaction(program, "Advanced observation fixture", () -> program.getOptions(C6000PipelineSchedules.OPTIONS).setString(
            C6000PipelineSchedules.storeTailKey(function), "{\"idleAdvances\":1,\"evidence\":\"Synthetic observation\"}"));
        try {
            C6000ProgramActions.preview(program, function.getEntryPoint(), "Synthetic reset", "", evidenceAt, evidenceAt.add(31), TaskMonitor.DUMMY);
            throw new AssertionError("Ordinary GUI preview accepted hidden advanced assumptions");
        } catch (IllegalArgumentException expected) { check(expected.getMessage().contains("advanced call or post-return"), "Wrong advanced-contract refusal");
        } finally { transaction(program, "Remove observation fixture", () -> program.getOptions(C6000PipelineSchedules.OPTIONS).removeOption(C6000PipelineSchedules.storeTailKey(function))); }
        quiet();before = program.getModificationNumber();
        C6000PipelineContracts.Review review = C6000ProgramActions.preview(program, function.getEntryPoint(),
            "Synthetic reset has no incoming effects", "", evidenceAt, evidenceAt.add(31), TaskMonitor.DUMMY);
        check(before == program.getModificationNumber(), "Preview was not read-only");
        check(review.language().endsWith(":c67x"), "Preview lost C67x profile");
        check(C6000ProgramActions.previousWrites(program, "a4, B5 a4").equals(Set.of("A4", "B5")), "Register input parsing failed");
        try { C6000ProgramActions.previousWrites(program, "A32");throw new AssertionError("Invalid GPR accepted"); } catch (IllegalArgumentException expected) { checks++; }
        // Mutate the source after preview. A native activation must leave no partial review or selector.
        var stale = review;
        transaction(program, "Change evidence after preview", () -> program.getMemory().setByte(evidenceAt.add(31), (byte) 1));
        try { C6000ProgramActions.activate(program, stale, TaskMonitor.DUMMY);throw new AssertionError("Stale preview activated");
        } catch (java.lang.reflect.InvocationTargetException expected) { check(expected.getCause() instanceof IllegalArgumentException, "Unexpected stale failure"); }
        check(!C6000PipelineContracts.isRecorded(program, function), "Failed activation left a review");
        check(!java.math.BigInteger.ONE.equals(program.getProgramContext().getValue(program.getRegister("c_schedule_entry"), function.getEntryPoint(), false)), "Failed activation left its selector");
        transaction(program, "Restore evidence", () -> program.getMemory().setByte(evidenceAt.add(31), (byte) 0));
        quiet();
        review = C6000ProgramActions.preview(program, function.getEntryPoint(), "Synthetic reset has no incoming effects", "", evidenceAt, evidenceAt.add(31), TaskMonitor.DUMMY);
        C6000ProgramActions.activate(program, review, TaskMonitor.DUMMY);
        quiet();
        check(C6000PipelineContracts.isRecorded(program, function), "Native activation did not record review");
        C6000ProgramActions.validate(program, function.getEntryPoint(), TaskMonitor.DUMMY);checks++;
        check(program.canUndo(), "Native activation is not undoable");
        history("Undo");
        check(!C6000PipelineContracts.isRecorded(program, function), "Undo did not remove activation");
        history("Redo");C6000ProgramActions.validate(program, function.getEntryPoint(), TaskMonitor.DUMMY);checks++;
        long beforeCancel = program.getModificationNumber();
        var cancelCompile = new TaskMonitorAdapter(true) {
            int checks;
            @Override public void checkCancelled() throws ghidra.util.exception.CancelledException {
                if (++checks == 4) throw new ghidra.util.exception.CancelledException();
            }
        };
        try { new C6000PipelineCompiler(program, function).compile(cancelCompile);throw new AssertionError("Compiler ignored cancellation");
        } catch (ghidra.util.exception.CancelledException expected) { checks++; }
        check(beforeCancel == program.getModificationNumber(), "Cancelled compiler changed the program");
        var cancelled = new TaskMonitorAdapter(true);cancelled.cancel();
        var rejected = new C6000ProgramActions.SetEntry(program.getMinAddress().add(128));
        check(!rejected.applyTo(program, cancelled), "Cancelled entry command succeeded");
        check(!program.getSymbolTable().isExternalEntryPoint(program.getMinAddress().add(128)), "Cancelled entry command changed program");
        validationStatus();
        var bodyBefore = new AddressSet(function.getBody());
        transaction(program, "Entry annotation", () -> program.getListing().setComment(function.getEntryPoint(), CommentType.EOL, "Keep this annotation"));
        disableWithConfirmation(function);
        decompileInTool(program, function, "disabled");
        check(!C6000PipelineContracts.isRecorded(program, function), "Disable retained the review");
        check(Arrays.stream(program.getListing().getInstructionAt(function.getEntryPoint()).getPcode()).noneMatch(op -> op.getOpcode() == ghidra.program.model.pcode.PcodeOp.CALLOTHER), "Disable retained the injected entry");
        check(!java.math.BigInteger.ONE.equals(program.getProgramContext().getValue(program.getRegister("c_schedule_entry"), function.getEntryPoint(), false)), "Disable retained the entry selector");
        check(bodyBefore.equals(function.getBody()), "Disable changed ownership");
        check("Keep this annotation".equals(program.getListing().getComment(CommentType.EOL, function.getEntryPoint())), "Disable lost annotation");
        history("Undo");quiet();C6000ProgramActions.validate(program, function.getEntryPoint(), TaskMonitor.DUMMY);checks++;
        // Opening a second program must retarget the provider and its actions; inactive edits must not retarget them.
        swing(() -> {
            tool.getService(ProgramManager.class).openProgram(other);
            tool.firePluginEvent(new ProgramLocationPluginEvent("test", new ProgramLocation(other, other.getMinAddress()), other));
        });
        waitFor(() -> plugin.program() == other, "program switch");
        swing(() -> check(!action("Validate C6000 Exact Schedule").isEnabledForContext(context(other, 0x1000)), "Review state leaked between programs"));
        swing(() -> action("Set C6000 Entry Point").actionPerformed(context(other, 0x1000)));
        waitFor(() -> other.getFunctionManager().getFunctionAt(other.getMinAddress()) != null, "BE native entry setup");quiet(other);
        dialogFlow(other, other.getFunctionManager().getFunctionAt(other.getMinAddress()));
        transaction(program, "Edit inactive program", () -> program.getListing().setComment(program.getMinAddress(), CommentType.EOL, "inactive"));
        swing(() -> check(plugin.program() == other, "Inactive event retargeted plugin"));
        swing(() -> tool.getService(ProgramManager.class).openProgram(foreign));
        waitFor(() -> plugin.program() == foreign, "unrelated program activation");
        swing(() -> {
            for (var nativeAction : tool.getDockingActionsByOwnerName("C6000Plugin"))
                if (nativeAction.getMenuBarData() != null && nativeAction.getMenuBarData().getMenuPath()[0].equals("Analysis"))
                    check(!nativeAction.isEnabledForContext(context(foreign, 0x1000)), "C6000 action enabled for unrelated processor");
        });
        swing(() -> {
            tool.removePlugins(List.of(plugin));
            check(tool.getComponentProvider("C6000 Processor Tools") == null, "Provider was not removed before reload");
            tool.addPlugin(C6000Plugin.class.getName());
            plugin = (C6000Plugin)tool.getManagedPlugins().stream().filter(p -> p instanceof C6000Plugin).findFirst().orElseThrow();
            check(plugin.program() == foreign, "Enabling the plugin in an already-open tool missed the active program");
            check(tool.getDockingActionsByOwnerName("C6000Plugin").stream().filter(a -> a.getName().equals("Review C6000 Exact Schedule")).count() == 1, "Reload duplicated native actions");
        });
        program.flushEvents();other.flushEvents();foreign.flushEvents();swing(() -> {});
        swing(() -> {
            tool.getService(ProgramManager.class).closeAllPrograms(true);
            check(plugin.program() == null, "Provider retained a closed program");
            check(!action("Show C6000 Processor Tools").isEnabledForContext(new ghidra.app.context.ProgramActionContext(null, null)), "Action enabled without a program");
        });
        // Persist and reopen the real program database with its activation contract.
        var saved = project.getProjectData().getRootFolder().createFile("saved-c67x", program, TaskMonitor.DUMMY);
        var prior = program;program.release(this);program = null;
        var immutable = (Program) saved.getImmutableDomainObject(this, ghidra.framework.model.DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
        try {
            check(!immutable.isChangeable(), "Persistence fixture did not open immutable");
            swing(() -> {
                tool.getService(ProgramManager.class).openProgram(immutable);
                tool.firePluginEvent(new ProgramLocationPluginEvent("test", new ProgramLocation(immutable, immutable.getMinAddress()), immutable));
                check(!action("Set C6000 Entry Point").isEnabledForContext(context(immutable, 0x1000)), "Entry mutation enabled in immutable view");
                check(!action("Disable C6000 Exact Schedule").isEnabledForContext(context(immutable, 0x1000)), "Disable mutation enabled in immutable view");
                check(action("Review C6000 Exact Schedule").isEnabledForContext(context(immutable, 0x1000)), "Immutable view cannot inspect/preview a review");
                check(action("Validate C6000 Exact Schedule").isEnabledForContext(context(immutable, 0x1000)), "Immutable view cannot validate");
            });
            var immutableFunction = immutable.getFunctionManager().getFunctionAt(immutable.getMinAddress());
            long immutableVersion = immutable.getModificationNumber();
            var readOnlyPreview = C6000ProgramActions.preview(immutable, immutableFunction.getEntryPoint(),
                "Synthetic reset has no incoming effects", "", immutable.getMinAddress(), immutable.getMinAddress().add(31), TaskMonitor.DUMMY);
            C6000ProgramActions.validate(immutable, immutableFunction.getEntryPoint(), TaskMonitor.DUMMY);checks++;
            check(!new C6000ProgramActions.SetEntry(immutable.getMinAddress()).applyTo(immutable, TaskMonitor.DUMMY), "Direct entry mutation accepted immutable program");
            try { C6000ProgramActions.activate(immutable, readOnlyPreview, TaskMonitor.DUMMY);throw new AssertionError("Immutable activation accepted");
            } catch (IllegalArgumentException expected) { check(expected.getMessage().contains("immutable"), "Immutable activation has no useful refusal"); }
            try { C6000ProgramActions.disable(immutable, immutableFunction.getEntryPoint(), TaskMonitor.DUMMY);throw new AssertionError("Immutable disable accepted");
            } catch (IllegalArgumentException expected) { checks++; }
            check(immutable.getModificationNumber() == immutableVersion, "Immutable inspection changed the program");
            SwingUtilities.invokeLater(() -> action("Review C6000 Exact Schedule").actionPerformed(context(immutable, 0x1000)));
            waitFor(() -> reviewWindow() != null, "immutable review dialog");
            swing(() -> button(reviewWindow(), "Preview schedule").doClick());
            waitFor(() -> descendants(reviewWindow()).stream().anyMatch(c -> c instanceof JLabel l && l.getText().contains("immutable view")), "immutable preview status");
            swing(() -> { check(!button(reviewWindow(), "Enable reviewed schedule").isEnabled(), "Immutable preview enabled activation");button(reviewWindow(), "Cancel").doClick(); });
            immutable.flushEvents();swing(() -> tool.getService(ProgramManager.class).closeAllPrograms(true));
        } finally { immutable.release(this); }
        program = (ProgramDB) saved.getDomainObject(this, false, false, TaskMonitor.DUMMY);
        check(program != prior, "Persistence check reused the open program");
        var reopenedFunction = program.getFunctionManager().getFunctionAt(program.getMinAddress());
        C6000ProgramActions.validate(program, reopenedFunction.getEntryPoint(), TaskMonitor.DUMMY);checks++;
        swing(() -> {
            var template = (ghidra.framework.project.tool.GhidraToolTemplate) tool.getToolTemplate(true);
            var restored = new GhidraTool(project.getProject(), template);
            check(restored.getManagedPlugins().stream().anyMatch(p -> p instanceof C6000Plugin), "Native plugin did not survive tool configuration save/restore");
            check(restored.getComponentProvider("C6000 Processor Tools") != null, "Restored tool lacks its provider");
            restored.dispose();
            tool.removePlugins(List.of(plugin));
            check(tool.getComponentProvider("C6000 Processor Tools") == null, "Provider survived plugin disposal");
            check(tool.getDockingActionsByOwnerName("C6000Plugin").isEmpty(), "Actions survived plugin disposal");
        });
    }
}
