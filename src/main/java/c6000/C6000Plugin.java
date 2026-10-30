// SPDX-License-Identifier: Apache-2.0
package c6000;

import java.util.*;
import javax.swing.SwingUtilities;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.*;
import ghidra.app.plugin.*;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

@PluginInfo(status = PluginStatus.RELEASED, packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS, shortDescription = "C6000 processor tools",
    description = "Inspect C6000 processor timing, set raw-image entry points and review exact packet schedules in CodeBrowser")
public final class C6000Plugin extends ProgramPlugin {
    private C6000Provider provider;
    private final List<ProgramContextAction> actions = new ArrayList<>();
    private final SwingUpdateManager updates = new SwingUpdateManager(100, 500, this::refresh);
    private final DomainObjectListener changes = event -> updates.update();
    private boolean disposed;

    public C6000Plugin(PluginTool tool) { super(tool); }
    @Override protected void init() {
        provider = new C6000Provider(this);
        action("Show C6000 Processor Tools", "Processor Tools", false, context -> showProvider());
        action("Set C6000 Entry Point", "Set Entry Point Here", true, context -> {
            Program program = context.getProgram();Address address = address(context);
            tool.executeBackgroundCommand(new C6000ProgramActions.SetEntry(address), program);
        });
        action("Review C6000 Exact Schedule", "Review Exact Schedule...", true, context -> review(context.getProgram(), address(context)));
        action("Validate C6000 Exact Schedule", "Validate Exact Schedule", true, context -> validate(context.getProgram(), address(context)));
        action("Disable C6000 Exact Schedule", "Disable Exact Schedule...", true, context -> disable(context.getProgram(), address(context)));
        refresh();
    }

    private void action(String name, String item, boolean popup, java.util.function.Consumer<ProgramActionContext> perform) {
        var action = new ProgramContextAction(name, getName()) {
            @Override protected boolean isEnabledForContext(ProgramActionContext context) {
                Program program = context.getProgram();
                if (!C6000PacketContext.isC6000(program) || program.isClosed()) return false;
                if (name.equals("Show C6000 Processor Tools")) return true;
                Address at = address(context);
                if (!C6000ProgramActions.supportedAddress(program, at)) return false;
                if (name.equals("Set C6000 Entry Point")) return C6000ProgramActions.canSetEntry(program, at);
                var function = program.getFunctionManager().getFunctionContaining(at);
                if (function == null) return false;
                if (name.equals("Validate C6000 Exact Schedule")) return C6000ProgramActions.hasActiveReview(program, function);
                if (name.equals("Disable C6000 Exact Schedule")) return C6000ProgramActions.canModify(program) && (C6000PipelineContracts.isRecorded(program, function) ||
                    java.math.BigInteger.ONE.equals(program.getProgramContext().getValue(program.getRegister("c_schedule_entry"), function.getEntryPoint(), false)));
                return true;
            }
            @Override public void actionPerformed(ProgramActionContext context) { perform.accept(context); }
        };
        action.setContextClass(ProgramActionContext.class, true);
        action.addToWindowWhen(ProgramActionContext.class);
        action.setMenuBarData(new MenuData(new String[] {"Analysis", "C6000", item}, null, "C6000"));
        if (popup) action.setPopupMenuData(new MenuData(new String[] {"C6000", item}, null, "C6000"));
        action.setDescription(item + " for the current C6000 program");
        action.setHelpLocation(new HelpLocation("C6000", name.contains("Schedule") ? "Schedules" : "ProcessorTools"));
        tool.addAction(action);actions.add(action);
    }

    private Address address(ProgramActionContext context) {
        if (context instanceof ProgramLocationActionContext location) return location.getAddress();
        return context.getProgram() == currentProgram && currentLocation != null ? currentLocation.getAddress() : null;
    }
    Program program() { return currentProgram; }
    ProgramLocation location() { return currentLocation; }
    PluginTool pluginTool() { return tool; }
    void showProvider() { tool.showComponentProvider(provider, true);refresh(); }
    void markEntry() {
        if (C6000ProgramActions.canSetEntry(currentProgram, currentLocation == null ? null : currentLocation.getAddress()))
            tool.executeBackgroundCommand(new C6000ProgramActions.SetEntry(currentLocation.getAddress()), currentProgram);
    }
    void reviewCurrent() { review(currentProgram, currentLocation == null ? null : currentLocation.getAddress()); }
    void validateCurrent() { validate(currentProgram, currentLocation == null ? null : currentLocation.getAddress()); }
    void disableCurrent() { disable(currentProgram, currentLocation == null ? null : currentLocation.getAddress()); }
    private void review(Program program, Address at) {
        if (at == null || !C6000PacketContext.isC6000(program)) return;
        var function = program.getFunctionManager().getFunctionContaining(at);
        if (function != null) tool.showDialog(new C6000ScheduleDialog(tool, program, function));
    }
    private void validate(Program program, Address at) {
        if (at == null || !C6000PacketContext.isC6000(program)) return;
        var function = program.getFunctionManager().getFunctionContaining(at);
        if (function == null) return;
        Address entry = function.getEntryPoint();
        var task = new Task("Validate C6000 exact schedule", true, false, true) {
            { program.addConsumer(this); }
            @Override public void run(TaskMonitor monitor) {
                String message;long version = -1;
                try { version = C6000ProgramActions.validate(program, entry, monitor);message = "Review is current for " + function.getName();
                } catch (CancelledException cancelled) { message = "Validation cancelled";
                } catch (Exception refused) { message = "Review needs attention: " + refused.getMessage();
                } finally { if (version == -1) version = program.getModificationNumber();program.release(this); }
                String result = message;long checkedVersion = version;
                SwingUtilities.invokeLater(() -> report(program, entry, checkedVersion, result));
            }
        };
        tool.execute(task);
    }
    private void disable(Program program, Address at) {
        if (at == null || !C6000ProgramActions.canModify(program)) return;
        var function = program.getFunctionManager().getFunctionContaining(at);
        if (function == null || OptionDialog.showYesNoDialog(tool.getToolFrame(), "Disable Exact Schedule",
                "Return " + function.getName() + " to ordinary instruction lifting?\n" +
                "This removes its exact-schedule review and observation contracts.\n" +
                "Parallel effects and pipeline latency will require renewed review to model exactly.\n" +
                "Function ownership and listing annotations are preserved. Undo is available.") != OptionDialog.OPTION_ONE) return;
        Address entry = function.getEntryPoint();
        tool.execute(new Task("Disable exact C6000 schedule", true, false, true) {
            { program.addConsumer(this); }
            @Override public void run(TaskMonitor monitor) {
                String message;long version;
                try { C6000ProgramActions.disable(program, entry, monitor);message = "Ordinary instruction lifting restored at " + entry;
                } catch (CancelledException cancelled) { message = "Disabling cancelled; changes rolled back";
                } catch (Exception refused) { message = "Cannot disable schedule: " + (refused.getCause() == null ? refused.getMessage() : refused.getCause().getMessage());
                } finally { version = program.getModificationNumber();program.release(this); }
                String result = message;
                SwingUtilities.invokeLater(() -> report(program, entry, version, result));
            }
        });
    }
    private void report(Program program, Address entry, long version, String result) {
        if (disposed || currentProgram != program || program.isClosed() || currentLocation == null ||
                version != program.getModificationNumber()) return;
        var current = program.getFunctionManager().getFunctionContaining(currentLocation.getAddress());
        if (current == null || !current.getEntryPoint().equals(entry)) return;
        showProvider();provider.message(result);
    }
    private void refresh() { if (!disposed && provider != null) { provider.refresh();tool.contextChanged(provider); } }
    @Override protected void programActivated(Program program) { if (C6000PacketContext.isC6000(program)) program.addListener(changes);refresh(); }
    @Override protected void programDeactivated(Program program) { program.removeListener(changes);updates.update(); }
    @Override protected void locationChanged(ProgramLocation location) { updates.update(); }
    @Override protected void dispose() {
        disposed = true;
        if (currentProgram != null) currentProgram.removeListener(changes);
        updates.dispose();
        for (var action : actions) { tool.removeAction(action);action.dispose(); }
        actions.clear();
        if (provider != null) provider.removeFromTool();
        super.dispose();
    }
}
