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

from .. import privileged, probe, render, sysctl_chain  # noqa: E402
from .. import apparmor as apparmor_module  # noqa: E402
from .. import ufw as ufw_module, units as units_module  # noqa: E402
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

    __gtype_name__ = "OssReviewDialog"

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

        if self.window.unit_changes:
            masked = [n for n, a in self.window.unit_changes.items() if a == "mask"]
            counts.add(
                self._row(
                    f"{len(self.window.unit_changes)} unit change(s)",
                    (f"{len(masked)} masked. " if masked else "")
                    + "A masked unit cannot be started at all, including as a "
                    "dependency of something else that needs it.",
                )
            )

        firewall = self.window.firewall_changes()
        if firewall:
            counts.add(
                self._row(
                    f"{len(firewall)} firewall change(s)",
                    "Run last in the transaction, because a firewall rule is the "
                    "thing most likely to cut the connection you are working over.",
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
        messages = [
            f"{section_id}: {detail}"
            for section_id, detail in probe.broken_includes(self.window.catalogue)
        ]
        sysctl_keys = [
            self.window.catalogue.flags[i].key
            for i in selection
            if i in self.window.catalogue.flags
            and self.window.catalogue.flags[i].section == "sysctl"
        ]
        if sysctl_keys:
            chain = sysctl_chain.read()
            shadowed = sysctl_chain.overridden_by_legacy(chain, sysctl_keys)
            if shadowed:
                listed = ", ".join(f"{k}={v}" for k, v in list(shadowed.items())[:6])
                messages.append(
                    f"{len(shadowed)} setting(s) would be overridden by "
                    f"/etc/sysctl.conf, which `sysctl --system` applies after "
                    f"/etc/sysctl.d: {listed}. They would be written and then "
                    f"immediately undone — and would then start working after a "
                    f"reboot, because systemd-sysctl does not read that file. "
                    f"Remove them from /etc/sysctl.conf first."
                )

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

        extras = self.window.extras_payload()
        if extras:
            group = Adw.PreferencesGroup(
                title="Other sections",
                description="Each of these is validated again by the helper before anything runs.",
            )
            labels = {
                "sandbox": "systemd unit drop-in",
                "permissions": "permission change",
                "fstab": "mount option change (remount-tested first)",
                "bootloader": "boot password",
                "usb": "USB policy",
            }
            for key, value in extras.items():
                count = len(value) if isinstance(value, dict) else 1
                group.add(self._row(f"{count} {labels[key]}(s)", ", ".join(map(str, value))[:200]))
            page.add(group)

        if self.window.apparmor_changes:
            group = Adw.PreferencesGroup(
                title="AppArmor",
                description="Mode is a symlink plus an apparmor_parser reload.",
            )
            for change in apparmor_module.plan_changes(self.window.apparmor_changes):
                group.add(self._row(" ".join(change.command), change.why))
            page.add(group)

        if self.window.unit_changes:
            group = Adw.PreferencesGroup(
                title="Units",
                description="Masking symlinks the unit to /dev/null so nothing can start it.",
            )
            for argv, why in units_module.plan_commands(self.window.unit_changes):
                group.add(self._row(" ".join(argv), why))
            page.add(group)

        firewall = self.window.firewall_changes()
        if firewall:
            group = Adw.PreferencesGroup(
                title="Firewall",
                description="Applied last, through the ufw command line.",
            )
            for argv, why in firewall:
                group.add(self._row(" ".join(argv), why))
            page.add(group)

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

    __gtype_name__ = "OssApplyDialog"

    def __init__(self, window) -> None:
        super().__init__(
            transient_for=window, modal=True, title="Applying",
            default_width=820, default_height=680,
        )
        mark_solid(self)
        self.window = window
        self.outcome: privileged.ApplyOutcome | None = None
        #: The buttons live in a bottom bar; showing a result twice would stack a
        #: second one, so the bar is kept and replaced rather than appended to.
        self._button_bar: Gtk.Widget | None = None
        self._settled = False

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
        firewall = (
            ufw_module.to_payload(self.window.firewall)
            if self.window.firewall_dirty
            else None
        )
        unit_changes = dict(self.window.unit_changes)
        apparmor_changes = dict(self.window.apparmor_changes)
        extras = self.window.extras_payload()
        thread = threading.Thread(
            target=self._worker,
            args=(selection, firewall, unit_changes, apparmor_changes, extras),
            daemon=True,
        )
        thread.start()

    def _worker(
        self,
        selection: dict[str, str],
        firewall: dict | None,
        unit_changes: dict,
        apparmor_changes: dict,
        extras: dict,
    ) -> None:
        outcome = privileged.apply(
            selection,
            firewall=firewall,
            unit_changes=unit_changes,
            apparmor_changes=apparmor_changes,
            extras=extras,
        )
        user_results = []
        if outcome.ok:
            plan = build_plan(self.window)
            if plan.user_commands:
                user_results = privileged.run_user_commands(plan.user_commands)
        GLib.idle_add(self._finish, outcome, user_results)

    def _finish(self, outcome: privileged.ApplyOutcome, user_results: list) -> bool:
        if self._settled:
            return False
        self._settled = True
        self.outcome = outcome
        self.spinner.stop()

        if outcome.cancelled:
            self._show_result(
                "action-unavailable-symbolic", "Cancelled", "Nothing was changed.",
                outcome, user_results, reboot=False,
            )
            return False

        if not outcome.ok:
            detail = outcome.error or "The helper reported a failure."
            if outcome.rolled_back:
                detail += (
                    "  Every file was restored from its backup, so the system is "
                    "as it was."
                )
            self._show_result(
                "dialog-error-symbolic", "Apply failed", detail,
                outcome, user_results, reboot=False,
            )
            return False

        applied = sum(1 for v in outcome.outcomes.values() if v == "applied")
        pending = len(outcome.needs_reboot)
        failed = outcome.failed_flags

        parts = [f"{applied} in effect now"]
        if pending:
            parts.append(f"{pending} waiting for a reboot")
        if failed:
            parts.append(f"{len(failed)} did not take")

        self._show_result(
            "dialog-warning-symbolic" if failed else "emblem-ok-symbolic",
            "Applied",
            " · ".join(parts),
            outcome,
            user_results,
            reboot=bool(pending),
        )

        self.window.refresh_from_system()
        return False

    def _show_result(
        self,
        icon: str,
        title: str,
        description: str,
        outcome: privileged.ApplyOutcome,
        user_results: list,
        reboot: bool,
    ) -> None:
        """Swap the spinner for the outcome, with the log given the window height.

        Deliberately not an Adw.StatusPage with the log as its child: a status page
        sizes itself around a short message, so a scrollable list put inside it gets
        squeezed into whatever vertical space is left over — which was a few lines.
        A compact banner plus a scroller that expands, and the buttons in a bottom
        bar where they cannot be scrolled away from.
        """
        banner = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        banner.set_margin_top(14)
        banner.set_margin_bottom(4)
        banner.set_margin_start(14)
        banner.set_margin_end(14)

        image = Gtk.Image.new_from_icon_name(icon)
        image.set_pixel_size(40)
        image.set_valign(Gtk.Align.START)
        banner.append(image)

        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3, hexpand=True)
        heading = Gtk.Label(label=title, xalign=0)
        heading.add_css_class("title-2")
        text.append(heading)
        subtitle = Gtk.Label(label=description, xalign=0, wrap=True)
        subtitle.add_css_class("dim-label")
        text.append(subtitle)
        banner.append(text)

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        body.append(banner)
        body.append(self._details_view(outcome, user_results))

        self.toolbar.set_content(body)
        if self._button_bar is not None:
            self.toolbar.remove(self._button_bar)
        self._button_bar = self._buttons(reboot)
        self.toolbar.add_bottom_bar(self._button_bar)
        self.set_title(title)

    def _buttons(self, reboot: bool) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        box.set_margin_start(12)
        box.set_margin_end(12)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        box.append(Gtk.Box(hexpand=True))
        if reboot:
            button = Gtk.Button(label="Reboot now")
            button.add_css_class("suggested-action")
            button.connect("clicked", self._on_reboot)
            box.append(button)
        close = Gtk.Button(label="Close")
        close.connect("clicked", lambda *_: self.close())
        box.append(close)
        return box

    def _details_view(self, outcome: privileged.ApplyOutcome, user_results: list) -> Gtk.Widget:
        page = Adw.PreferencesPage()

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
            page.add(group)

        if outcome.needs_reboot:
            group = Adw.PreferencesGroup(
                title=f"{len(outcome.needs_reboot)} change(s) waiting for a reboot",
                description="Written to disk, but not in effect until you restart.",
            )
            for flag_id in outcome.needs_reboot[:20]:
                flag = self.window.catalogue.get(flag_id)
                group.add(ReviewDialog._row(flag.title if flag else flag_id,
                                            flag.key if flag else ""))
            page.add(group)

        failed_user = [(c, o) for c, ok, o in user_results if not ok]
        if failed_user:
            group = Adw.PreferencesGroup(title="Desktop settings that failed")
            for command, output in failed_user:
                group.add(ReviewDialog._row(command, output))
            page.add(group)

        steps = Adw.PreferencesGroup(
            title="What the helper did",
            description=f"{len(outcome.steps)} step(s), in order.",
        )
        for step in outcome.steps:
            title = f"{step.get('kind', '?')}: {step.get('detail', '')}"
            subtitle = step.get("output", "")
            if not step.get("ok", True):
                subtitle = f"FAILED — {subtitle}"
            steps.add(ReviewDialog._row(title, subtitle))
        page.add(steps)

        scroller = Gtk.ScrolledWindow(child=page, vexpand=True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        return scroller

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
