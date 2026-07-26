"""AppArmor page — per-profile enforce/complain/disable (§4.15).

Configured modes come from symlinks anyone can read, so the list is on screen
immediately. What each profile is *actually* running is in
/sys/kernel/security/apparmor, which is root-only, so it takes one explicit
privileged read — the same pattern as the firewall rules.
"""

from __future__ import annotations

import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from .. import apparmor as apparmor_module, privileged  # noqa: E402

PAGE_LIMIT = 50

MODE_LABELS = {
    "enforce": "enforce (block violations)",
    "complain": "complain (log, allow)",
    "disable": "disable (unload)",
}


class ApparmorPage(Gtk.Box):
    """Profile list with mode control."""

    __gtype_name__ = "HardeningApparmorPage"

    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.window = window
        self.search = ""
        self.changed_only = False
        self.append(self._build())

    @property
    def state(self) -> apparmor_module.State:
        return self.window.apparmor

    def _rebuild(self) -> None:
        self.window._show_section(self.window.current_section)

    def _build(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_margin_bottom(14)
        box.append(self._status_group())
        if self.state.unconfined:
            box.append(self._unconfined_group())
        box.append(self._profiles_group())
        return box

    # -- status ---------------------------------------------------------- #

    def _status_group(self) -> Adw.PreferencesGroup:
        state = self.state
        counts = state.counts()
        group = Adw.PreferencesGroup(
            title="AppArmor",
            description=(
                "A profile in enforce mode blocks what it does not allow. In "
                "complain mode it logs the violation and allows it anyway, which "
                "is how you find out what a profile would break before enforcing it."
            ),
        )

        summary = Adw.ActionRow(
            title=f"{len(state.profiles)} profile(s) in /etc/apparmor.d",
            subtitle=(
                f"{counts.get('enforce', 0)} enforce · "
                f"{counts.get('complain', 0)} complain · "
                f"{counts.get('disable', 0)} disabled"
                + ("" if state.live_loaded else "  —  configured modes only, not yet read from the kernel")
            ),
        )
        summary.set_subtitle_lines(2)
        if not state.live_loaded:
            button = Gtk.Button(label="Read live state", valign=Gtk.Align.CENTER)
            button.add_css_class("suggested-action")
            button.connect("clicked", self._on_read_live)
            summary.add_suffix(button)
        group.add(summary)

        if not state.enabled:
            group.add(
                Adw.ActionRow(
                    title="AppArmor is not enabled in the kernel",
                    subtitle="Profiles here will not take effect until it is. See the "
                    "grub section: apparmor=1 and lsm must include apparmor.",
                )
            )

        drifted = [p for p in state.profiles if p.drifted]
        if drifted:
            row = Adw.ActionRow(
                title=f"{len(drifted)} profile(s) are running a different mode than configured",
                subtitle=", ".join(f"{p.name}: {p.live} vs {p.configured}" for p in drifted[:6]),
            )
            row.set_subtitle_lines(3)
            icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
            icon.add_css_class("status-differs")
            row.add_prefix(icon)
            group.add(row)
        return group

    def _unconfined_group(self) -> Adw.PreferencesGroup:
        group = Adw.PreferencesGroup(
            title="Unconfined processes with a listening socket",
            description=(
                "These accept input from the network with no AppArmor profile "
                "mediating what they can do if that input goes wrong."
            ),
        )
        for pid, name in self.state.unconfined[:20]:
            group.add(Adw.ActionRow(title=name, subtitle=f"pid {pid}"))
        return group

    # -- profiles -------------------------------------------------------- #

    def _visible(self) -> tuple[list, int]:
        profiles = self.state.profiles
        if self.changed_only:
            profiles = [
                p
                for p in profiles
                if p.name in self.window.apparmor_changes or p.drifted
            ]
        if self.search:
            profiles = [p for p in profiles if self.search in p.name.lower()]
        total = len(profiles)
        staged = [p for p in profiles if p.name in self.window.apparmor_changes]
        rest = [p for p in profiles if p.name not in self.window.apparmor_changes]
        return (staged + rest)[:PAGE_LIMIT], total

    def _profiles_group(self) -> Adw.PreferencesGroup:
        shown, total = self._visible()
        group = Adw.PreferencesGroup(title="Profiles", description=f"{total} shown.")

        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        controls.set_margin_top(4)
        controls.set_margin_bottom(4)
        entry = Gtk.SearchEntry(placeholder_text="Filter profiles", hexpand=True)
        entry.set_text(self.search)
        entry.connect("search-changed", self._on_search)
        controls.append(entry)
        toggle = Gtk.ToggleButton(label="Staged or drifted")
        toggle.set_active(self.changed_only)
        toggle.connect("toggled", self._on_changed_toggle)
        controls.append(toggle)
        holder = Adw.PreferencesRow(activatable=False, selectable=False)
        holder.set_child(controls)
        group.add(holder)

        if not shown:
            group.add(Adw.ActionRow(title="No profiles match"))
            return group

        for profile in shown:
            group.add(self._profile_row(profile))
        if total > len(shown):
            group.add(
                Adw.ActionRow(
                    title=f"{total - len(shown)} more not shown",
                    subtitle="Narrow the filter to reach them.",
                )
            )
        return group

    def _profile_row(self, profile: apparmor_module.Profile) -> Adw.ActionRow:
        staged = self.window.apparmor_changes.get(profile.name)
        row = Adw.ActionRow(title=profile.name, subtitle=profile.summary)

        modes = list(apparmor_module.MODES)
        drop = Gtk.DropDown.new_from_strings([MODE_LABELS[m] for m in modes])
        drop.set_valign(Gtk.Align.CENTER)
        current = staged or profile.live or profile.configured
        if current in modes:
            drop.set_selected(modes.index(current))
        drop.connect("notify::selected", self._on_mode, profile, modes)
        row.add_suffix(drop)

        if staged:
            badge = Gtk.Label(label="staged")
            badge.add_css_class("changed-counter")
            badge.add_css_class("caption")
            row.add_suffix(badge)
        if profile.drifted:
            icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
            icon.add_css_class("status-differs")
            row.add_prefix(icon)
        return row

    # -- handlers -------------------------------------------------------- #

    def _on_search(self, entry: Gtk.SearchEntry) -> None:
        self.search = entry.get_text().strip().lower()
        self._rebuild()

    def _on_changed_toggle(self, button: Gtk.ToggleButton) -> None:
        self.changed_only = button.get_active()
        self._rebuild()

    def _on_mode(self, drop: Gtk.DropDown, _param, profile, modes: list[str]) -> None:
        index = drop.get_selected()
        if not 0 <= index < len(modes):
            return
        mode = modes[index]
        baseline = profile.live or profile.configured
        if mode == baseline:
            self.window.apparmor_changes.pop(profile.name, None)
        else:
            try:
                apparmor_module.validate(profile.name)
                apparmor_module.validate_mode(mode)
            except apparmor_module.ApparmorError as exc:
                self.window.toast(str(exc))
                return
            self.window.apparmor_changes[profile.name] = mode
        self.window._refresh_chrome()

    def _on_read_live(self, button: Gtk.Button) -> None:
        button.set_sensitive(False)
        button.set_label("Reading…")

        def worker() -> None:
            outcome = privileged.read_apparmor()
            GLib.idle_add(self._live_loaded, outcome)

        threading.Thread(target=worker, daemon=True).start()

    def _live_loaded(self, outcome: privileged.ApplyOutcome) -> bool:
        if not outcome.ok:
            self.window.toast(outcome.error or "Could not read AppArmor state.")
            self._rebuild()
            return False
        modes = outcome.apparmor.get("modes") or {}
        unconfined = outcome.apparmor.get("unconfined") or []
        state = apparmor_module.match_live(self.state, modes)
        state.unconfined = [tuple(entry) for entry in unconfined if len(entry) == 2]
        self.window.apparmor = state
        self.window.toast(f"Read {len(modes)} loaded profile(s).")
        self._rebuild()
        return False
