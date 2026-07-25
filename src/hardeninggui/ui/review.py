"""Review and Apply.

Review shows the literal unified diff per target file, the exact command list,
and a grouped risk summary. When one-way flags are staged the summary must be
scrolled past before Apply becomes clickable — that is the whole point of the
gate, so it is enforced by the scroll position, not by a checkbox nobody reads.
"""

from __future__ import annotations

import difflib
import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from .. import privileged, probe, render  # noqa: E402
from .style import mark_solid  # noqa: E402


def build_plan(window) -> render.Plan:
    """Render the staged selection into a plan, using current file contents."""
    current = probe.read_target_files(window.catalogue)
    return render.render(window.catalogue, window.staging.selection, current=current)


def unified_diff(path: str, before: str, after: str) -> str:
    lines = difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"{path} (now)",
        tofile=f"{path} (after apply)",
        n=3,
    )
    return "".join(lines)


class ReviewDialog(Adw.Window):
    """The diff, the commands, and the risk summary."""

    __gtype_name__ = "HardeningReviewDialog"

    def __init__(self, window, apply_callback) -> None:
        super().__init__(
            transient_for=window, modal=True, title="Review changes",
            default_width=860, default_height=680,
        )
        mark_solid(self)
        self.window = window
        self.apply_callback = apply_callback
        self.plan = build_plan(window)
        self.one_way = window.staging.one_way_staged()
        self._gate_cleared = not self.one_way

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        toolbar.add_top_bar(header)

        self.stack = Adw.ViewStack()
        switcher = Adw.ViewSwitcher(stack=self.stack, policy=Adw.ViewSwitcherPolicy.WIDE)
        header.set_title_widget(switcher)

        self.stack.add_titled(self._summary_page(), "summary", "Summary")
        self.stack.add_titled(self._diff_page(), "diff", "File diff")
        self.stack.add_titled(self._commands_page(), "commands", "Commands")
        toolbar.set_content(self.stack)
        toolbar.add_bottom_bar(self._footer())

        self.set_content(toolbar)

    # ------------------------------------------------------------------ #

    def _footer(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        box.set_margin_start(12)
        box.set_margin_end(12)
        box.set_margin_top(8)
        box.set_margin_bottom(8)

        self.gate_label = Gtk.Label(label="", xalign=0, wrap=True, hexpand=True)
        self.gate_label.add_css_class("reboot-hint")
        box.append(self.gate_label)

        close = Gtk.Button(label="Close")
        close.connect("clicked", lambda *_: self.close())
        box.append(close)

        if self.apply_callback is not None:
            self.apply_button = Gtk.Button(label="Apply")
            self.apply_button.add_css_class("suggested-action")
            self.apply_button.connect("clicked", self._on_apply)
            self.apply_button.set_sensitive(self._gate_cleared)
            box.append(self.apply_button)
            self._update_gate_label()
        return box

    def _update_gate_label(self) -> None:
        if self._gate_cleared:
            self.gate_label.set_label("")
        else:
            names = ", ".join(f.title for f in self.one_way[:3])
            more = f" and {len(self.one_way) - 3} more" if len(self.one_way) > 3 else ""
            self.gate_label.set_label(
                f"Scroll to the end of the summary to enable Apply — "
                f"{len(self.one_way)} irreversible change(s): {names}{more}."
            )

    def _on_apply(self, _button: Gtk.Button) -> None:
        self.close()
        if self.apply_callback is not None:
            self.apply_callback()

    # ------------------------------------------------------------------ #

    def _summary_page(self) -> Gtk.Widget:
        staging = self.window.staging
        page = Adw.PreferencesPage()

        counts = Adw.PreferencesGroup(title="What this will do")
        counts.add(
            self._row(
                f"{len(self.plan.writes)} file(s) written",
                ", ".join(w.path for w in self.plan.writes) or "none",
            )
        )
        if self.plan.removes:
            counts.add(
                self._row(
                    f"{len(self.plan.removes)} file(s) deleted",
                    ", ".join(r.path for r in self.plan.removes)
                    + "  — these sections go back to stock",
                )
            )
        counts.add(
            self._row(
                f"{len(self.plan.commands)} command(s) run as root",
                "; ".join(str(c) for c in self.plan.commands) or "none",
            )
        )
        if self.plan.user_commands:
            counts.add(
                self._row(
                    f"{len(self.plan.user_commands)} command(s) run as you",
                    "gsettings writes your own dconf database, so these "
                    "deliberately do not go through pkexec.",
                )
            )
        page.add(counts)

        reboot = staging.reboot_staged()
        if reboot:
            group = Adw.PreferencesGroup(
                title=f"{len(reboot)} change(s) need a reboot",
                description="These are written now but do nothing until you restart.",
            )
            for flag in reboot[:12]:
                group.add(self._row(flag.title, flag.key))
            page.add(group)

        breaking = staging.breaking_staged()
        if breaking:
            group = Adw.PreferencesGroup(
                title=f"{len(breaking)} change(s) will break something",
                description="Each of these has a known, specific consequence.",
            )
            for flag in breaking:
                group.add(self._row(flag.title, flag.breaks or flag.desc))
            page.add(group)

        for message in self._cross_checks():
            group = Adw.PreferencesGroup(title="Check this first")
            group.add(self._row("Conflict", message))
            page.add(group)

        if self.one_way:
            group = Adw.PreferencesGroup(
                title=f"{len(self.one_way)} irreversible change(s)",
                description=(
                    "These cannot be undone by deleting a file. Reversing them "
                    "needs a reboot at best, and reinstalling at worst."
                ),
            )
            for flag in self.one_way:
                group.add(self._row(flag.title, flag.help or flag.breaks or flag.desc))
            page.add(group)

        scroller = self._as_scroller(page)
        if self.one_way:
            # The gate: Apply stays disabled until the risk summary is at the end.
            adjustment = scroller.get_vadjustment()
            adjustment.connect("value-changed", self._on_summary_scrolled)
            GLib.idle_add(self._check_gate, adjustment)
        return scroller

    def _on_summary_scrolled(self, adjustment: Gtk.Adjustment) -> None:
        self._check_gate(adjustment)

    def _check_gate(self, adjustment: Gtk.Adjustment) -> bool:
        at_end = (
            adjustment.get_value() + adjustment.get_page_size()
            >= adjustment.get_upper() - 8
        )
        if at_end and not self._gate_cleared:
            self._gate_cleared = True
            if hasattr(self, "apply_button"):
                self.apply_button.set_sensitive(True)
            self._update_gate_label()
        return False

    def _cross_checks(self) -> list[str]:
        selection = self.window.staging.selection
        messages = []
        for check in (
            probe.kdump_conflict(self.window.facts, selection),
            probe.slab_debug_redundancy(selection),
            probe.dot_without_firewall_port(selection),
        ):
            if check:
                messages.append(check)
        return messages

    def _diff_page(self) -> Gtk.Widget:
        current = probe.read_target_files(self.window.catalogue)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_start(12)
        box.set_margin_end(12)
        box.set_margin_top(12)
        box.set_margin_bottom(12)

        any_diff = False
        for write in self.plan.writes:
            before = current.get(write.path, "")
            diff = unified_diff(write.path, before, write.content)
            if not diff:
                continue
            any_diff = True
            box.append(self._diff_widget(diff))

        for removal in self.plan.removes:
            before = current.get(removal.path, "")
            diff = unified_diff(removal.path, before, "")
            if diff:
                any_diff = True
                box.append(self._diff_widget(diff))

        if not any_diff:
            box.append(
                Adw.StatusPage(
                    title="No file changes",
                    description="This selection only runs commands.",
                    icon_name="text-x-generic-symbolic",
                )
            )
        return self._as_scroller(box)

    def _diff_widget(self, diff: str) -> Gtk.Widget:
        view = Gtk.TextView(editable=False, monospace=True)
        view.add_css_class("diff-view")
        view.set_wrap_mode(Gtk.WrapMode.NONE)
        view.get_buffer().set_text(diff)
        frame = Gtk.Frame(child=view)
        return frame

    def _commands_page(self) -> Gtk.Widget:
        page = Adw.PreferencesPage()
        root = Adw.PreferencesGroup(
            title="Run as root, in this order",
            description="Only commands on the helper's allowlist can appear here.",
        )
        for command in self.plan.commands:
            root.add(self._row(str(command), command.why))
        if not self.plan.commands:
            root.add(self._row("none", ""))
        page.add(root)

        if self.plan.user_commands:
            user = Adw.PreferencesGroup(
                title="Run as you",
                description="These change your own settings, not the system's.",
            )
            for command in self.plan.user_commands:
                user.add(self._row(str(command), command.why))
            page.add(user)
        return self._as_scroller(page)

    # ------------------------------------------------------------------ #

    @staticmethod
    def _row(title: str, subtitle: str) -> Adw.ActionRow:
        row = Adw.ActionRow(title=GLib.markup_escape_text(title))
        if subtitle:
            row.set_subtitle(GLib.markup_escape_text(subtitle))
        row.set_title_lines(2)
        row.set_subtitle_lines(6)
        return row

    @staticmethod
    def _as_scroller(child: Gtk.Widget) -> Gtk.ScrolledWindow:
        scroller = Gtk.ScrolledWindow(child=child, vexpand=True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        return scroller


class ApplyProgressDialog(Adw.Window):
    """Runs the helper on a worker thread and reports what actually happened."""

    __gtype_name__ = "HardeningApplyDialog"

    def __init__(self, window) -> None:
        super().__init__(
            transient_for=window, modal=True, title="Applying",
            default_width=760, default_height=560,
        )
        mark_solid(self)
        self.window = window
        self.outcome: privileged.ApplyOutcome | None = None

        self.status = Adw.StatusPage(
            title="Waiting for authentication",
            description="pkexec is asking for your password. Nothing has been "
            "written yet — cancelling here leaves the system untouched.",
            icon_name="dialog-password-symbolic",
        )
        self.spinner = Gtk.Spinner(spinning=True, width_request=32, height_request=32)
        self.status.set_child(self.spinner)

        self.toolbar = Adw.ToolbarView(content=self.status)
        self.toolbar.add_top_bar(Adw.HeaderBar(show_title=True))
        self.set_content(self.toolbar)

        self.connect("map", lambda *_: self._start())

    def _start(self) -> None:
        selection = dict(self.window.staging.selection)
        thread = threading.Thread(target=self._worker, args=(selection,), daemon=True)
        thread.start()

    def _worker(self, selection: dict[str, str]) -> None:
        outcome = privileged.apply(selection)
        user_results = []
        if outcome.ok:
            plan = build_plan(self.window)
            if plan.user_commands:
                user_results = privileged.run_user_commands(plan.user_commands)
        GLib.idle_add(self._finish, outcome, user_results)

    def _finish(self, outcome: privileged.ApplyOutcome, user_results: list) -> bool:
        self.outcome = outcome
        self.spinner.stop()

        if outcome.cancelled:
            self.status.set_icon_name("action-unavailable-symbolic")
            self.status.set_title("Cancelled")
            self.status.set_description("Nothing was changed.")
            self.status.set_child(self._close_button())
            return False

        if not outcome.ok:
            self.status.set_icon_name("dialog-error-symbolic")
            self.status.set_title("Apply failed")
            detail = outcome.error or "The helper reported a failure."
            if outcome.rolled_back:
                detail += "\n\nEvery file was restored from its backup, so the system is as it was."
            self.status.set_description(detail)
            self.status.set_child(self._details_view(outcome, user_results))
            return False

        applied = sum(1 for v in outcome.outcomes.values() if v == "applied")
        pending = len(outcome.needs_reboot)
        failed = outcome.failed_flags

        self.status.set_icon_name(
            "dialog-warning-symbolic" if failed else "emblem-ok-symbolic"
        )
        self.status.set_title("Applied")
        parts = [f"{applied} in effect now"]
        if pending:
            parts.append(f"{pending} waiting for a reboot")
        if failed:
            parts.append(f"{len(failed)} did not take")
        self.status.set_description(" · ".join(parts))
        self.status.set_child(self._details_view(outcome, user_results))

        self.window.refresh_from_system()
        if pending:
            self.window.toast(f"{pending} change(s) take effect after a reboot.")
        return False

    def _details_view(self, outcome: privileged.ApplyOutcome, user_results: list) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)

        if outcome.failed_flags:
            group = Adw.PreferencesGroup(
                title="These did not take",
                description="Written, but the system did not end up in that state. "
                "An invalid key fails silently, which is exactly why we read back.",
            )
            for flag_id in outcome.failed_flags:
                flag = self.window.catalogue.get(flag_id)
                group.add(
                    ReviewDialog._row(
                        flag.title if flag else flag_id,
                        f"{flag.key if flag else ''} — {outcome.outcomes[flag_id]}",
                    )
                )
            box.append(group)

        for command, ok, output in user_results:
            if not ok:
                group = Adw.PreferencesGroup(title="A desktop setting failed")
                group.add(ReviewDialog._row(command, output))
                box.append(group)

        steps = Adw.PreferencesGroup(title="What the helper did")
        for step in outcome.steps:
            title = f"{step.get('kind', '?')}: {step.get('detail', '')}"
            subtitle = step.get("output", "")
            if not step.get("ok", True):
                subtitle = f"FAILED — {subtitle}"
            steps.add(ReviewDialog._row(title, subtitle))
        box.append(steps)

        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, halign=Gtk.Align.CENTER)
        if outcome.needs_reboot:
            reboot = Gtk.Button(label="Reboot now")
            reboot.add_css_class("suggested-action")
            reboot.connect("clicked", self._on_reboot)
            buttons.append(reboot)
        buttons.append(self._close_button())
        box.append(buttons)

        return ReviewDialog._as_scroller(box)

    def _close_button(self) -> Gtk.Widget:
        button = Gtk.Button(label="Close", halign=Gtk.Align.CENTER)
        button.connect("clicked", lambda *_: self.close())
        return button

    def _on_reboot(self, _button: Gtk.Button) -> None:
        # Ask the session to reboot rather than calling systemctl ourselves: the
        # desktop gets to prompt about unsaved work, and we never need root here.
        Gio.DBusProxy.new_for_bus_sync(
            Gio.BusType.SESSION,
            Gio.DBusProxyFlags.NONE,
            None,
            "org.gnome.SessionManager",
            "/org/gnome/SessionManager",
            "org.gnome.SessionManager",
            None,
        ).call_sync("Reboot", None, Gio.DBusCallFlags.NONE, -1, None)
