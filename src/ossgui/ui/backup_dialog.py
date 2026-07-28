"""Back up the config files, and restore them.

Two directions, one dialog. Backing up reads and writes nothing on the system.
Restoring shows what would change and then goes through the same transaction an
ordinary Apply uses, so the current files are saved first and a failure at any
point puts them all back.
"""

from __future__ import annotations

import socket
import threading
from datetime import date

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from .. import __version__, backup as backup_module, privileged, probe  # noqa: E402
from .style import mark_solid  # noqa: E402

#: A human hook for each backup location. Locations without an entry are
#: shown by their path alone, which is descriptive enough for most.
LOCATION_HINTS = {
    "/etc/sudoers.d": "sudo rules — skip when the machines have different users",
    "/etc/pam.d": "login and authentication policy",
    "/etc/sysctl.d": "kernel and network hardening drop-ins",
    "/etc/sysctl.conf": "the legacy top-level sysctl file",
    "/etc/modprobe.d": "module blacklists",
    "/etc/default/grub": "boot-time kernel options",
    "/etc/ufw": "firewall rules",
    "/etc/ssh/sshd_config.d": "SSH server hardening drop-ins",
    "/etc/fstab": "mount options — skip across machines with different disks",
    "/etc/usbguard": "USB device policy",
}


class BackupDialog(Adw.Window):
    """Choose a direction, then do it."""

    __gtype_name__ = "OssBackupDialog"

    def __init__(self, window) -> None:
        super().__init__(
            transient_for=window, modal=True, title="Back up and restore",
            default_width=760, default_height=600,
        )
        mark_solid(self)
        self.window = window
        self.toolbar = Adw.ToolbarView()
        self.toolbar.add_top_bar(Adw.HeaderBar())
        self.set_content(self.toolbar)
        #: The current bottom bar. Swapping pages must replace it, not stack
        #: another on top (same lesson as ApplyProgressDialog._button_bar).
        self._button_bar: Gtk.Widget | None = None
        self._show_choice()

    # ------------------------------------------------------------------ #

    def _page(self) -> Adw.PreferencesPage:
        page = Adw.PreferencesPage()
        scroller = Gtk.ScrolledWindow(child=page, vexpand=True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.toolbar.set_content(scroller)
        return page

    @staticmethod
    def _row(title: str, subtitle: str = "") -> Adw.ActionRow:
        row = Adw.ActionRow(title=GLib.markup_escape_text(title))
        if subtitle:
            row.set_subtitle(GLib.markup_escape_text(subtitle))
        row.set_title_lines(2)
        row.set_subtitle_lines(4)
        return row

    def _busy(self, title: str, description: str) -> None:
        status = Adw.StatusPage(title=title, description=description)
        status.set_child(Gtk.Spinner(spinning=True, width_request=32, height_request=32))
        self.toolbar.set_content(status)

    # ------------------------------------------------------------------ #

    def _show_choice(self) -> None:
        page = self._page()
        group = Adw.PreferencesGroup(
            title="Your configuration, as a file",
            description=(
                "This copies the configuration files themselves — everything in "
                "/etc/sysctl.d, /etc/modprobe.d, /etc/default/grub and the rest, "
                "including settings you made by hand that this application knows "
                "nothing about. It is not a list of toggles; it is your files."
            ),
        )

        back_up = Adw.ActionRow(
            title="Back up to a file",
            subtitle="Choose which locations to include, then write one archive. "
                     "Changes nothing.",
        )
        back_up_button = Gtk.Button(label="Choose what…", valign=Gtk.Align.CENTER)
        back_up_button.add_css_class("suggested-action")
        back_up_button.connect("clicked", self._show_backup_choices)
        back_up.add_suffix(back_up_button)
        group.add(back_up)

        restore = Adw.ActionRow(
            title="Restore from a file",
            subtitle="Shows you what would change before anything is written, "
                     "and puts everything back if any step fails.",
        )
        restore_button = Gtk.Button(label="Choose a file…", valign=Gtk.Align.CENTER)
        restore_button.connect("clicked", self._on_pick_restore)
        restore.add_suffix(restore_button)
        group.add(restore)
        page.add(group)

        note = Adw.PreferencesGroup()
        note.add(self._row(
            "Both ask for your password",
            "/etc/sudoers.d is readable only by root, so the archive is built by "
            "the privileged helper rather than the interface.",
        ))
        page.add(note)

    # -- backing up ----------------------------------------------------- #

    def _show_backup_choices(self, _button: Gtk.Button) -> None:
        """Which locations go into the archive. Everything, by default."""
        page = self._page()
        locations = backup_module.backup_paths(self.window.catalogue)
        self._backup_selected = set(locations)

        group = Adw.PreferencesGroup(
            title="What goes into the archive",
            description="Every ticked location is copied in full — your own "
                        "files included, not just what this app wrote.",
        )
        for location in locations:
            row = self._row(location, LOCATION_HINTS.get(location, ""))
            check = Gtk.CheckButton(active=True, valign=Gtk.Align.CENTER)
            check.connect("toggled", self._on_toggle_backup_location, location)
            row.add_suffix(check)
            group.add(row)
        page.add(group)
        self._footer(back_up=True)

    def _on_toggle_backup_location(self, button: Gtk.CheckButton, location: str) -> None:
        if button.get_active():
            self._backup_selected.add(location)
        else:
            self._backup_selected.discard(location)

    def _on_pick_backup(self, _button: Gtk.Button) -> None:
        if not self._backup_selected:
            return
        dialog = Gtk.FileDialog(
            title="Save the backup",
            initial_name=f"oss-backup-{socket.gethostname()}-{date.today().isoformat()}.tar.gz",
        )
        dialog.save(self, None, self._on_backup_chosen)

    def _on_backup_chosen(self, dialog: Gtk.FileDialog, result) -> None:
        try:
            gfile = dialog.save_finish(result)
        except GLib.Error:
            return  # cancelled
        if gfile is None:
            return
        self._start_backup(gfile.get_path())

    def _start_backup(self, destination: str) -> None:
        self._busy("Backing up", "Reading every configuration location.")

        locations = sorted(self._backup_selected)

        def worker() -> None:
            outcome = privileged.make_backup(
                destination, hostname=socket.gethostname(), version=__version__,
                locations=locations, on_progress=self._progress,
            )
            GLib.idle_add(self._backup_done, outcome, destination)

        threading.Thread(target=worker, daemon=True).start()

    def _progress(self, text: str) -> None:
        def update() -> bool:
            content = self.toolbar.get_content()
            if isinstance(content, Adw.StatusPage):
                content.set_description(text)
            return False

        GLib.idle_add(update)

    def _backup_done(self, outcome, destination: str) -> bool:
        page = self._page()
        if not outcome.ok:
            group = Adw.PreferencesGroup(title="The backup could not be made")
            group.add(self._row(outcome.error or "no detail given", ""))
            page.add(group)
            self._footer()
            return False

        info = outcome.integrity.get("backup", {})
        group = Adw.PreferencesGroup(
            title="Backed up",
            description=f"{info.get('summary', '')} — written to {destination}",
        )
        for path in info.get("files", [])[:200]:
            group.add(self._row(path))
        remaining = len(info.get("files", [])) - 200
        if remaining > 0:
            group.add(self._row(f"… and {remaining} more file(s)"))
        page.add(group)

        skipped = info.get("skipped", [])
        if skipped:
            group = Adw.PreferencesGroup(
                title=f"{len(skipped)} location(s) not present on this machine",
                description="Nothing to take from these — they are listed so the "
                            "archive's contents are never a surprise.",
            )
            for path in skipped:
                group.add(self._row(path))
            page.add(group)

        self._footer()
        return False

    # -- restoring ------------------------------------------------------ #

    def _on_pick_restore(self, _button: Gtk.Button) -> None:
        dialog = Gtk.FileDialog(title="Choose a backup")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        archives = Gtk.FileFilter(name="Backups")
        archives.add_pattern("*.tar.gz")
        filters.append(archives)
        dialog.set_filters(filters)
        dialog.open(self, None, self._on_restore_chosen)

    def _on_restore_chosen(self, dialog: Gtk.FileDialog, result) -> None:
        try:
            gfile = dialog.open_finish(result)
        except GLib.Error:
            return
        if gfile is None:
            return
        source = gfile.get_path()
        self._busy("Reading the backup", "Nothing is written yet.")

        def worker() -> None:
            outcome = privileged.restore_plan(source)
            GLib.idle_add(self._show_restore_plan, outcome, source)

        threading.Thread(target=worker, daemon=True).start()

    def _show_restore_plan(self, outcome, source: str) -> bool:
        page = self._page()
        if not outcome.ok:
            group = Adw.PreferencesGroup(title="That backup could not be read")
            group.add(self._row(outcome.error or "no detail given", ""))
            page.add(group)
            self._footer()
            return False

        info = outcome.integrity.get("restore", {})
        manifest = info.get("manifest", {})
        changes = info.get("changes", [])
        self._restore_source = source
        self._restore_selected = {
            change["path"] for change in changes if change["state"] != "same"
        }

        group = Adw.PreferencesGroup(
            title="Where this came from",
            description=f"{manifest.get('distro') or 'unknown system'} · "
                        f"{manifest.get('hostname') or 'unknown host'} · "
                        f"{manifest.get('created') or 'no date'}",
        )
        warning = info.get("warning", "")
        if warning:
            row = self._row("Worth checking first", warning)
            row.add_prefix(Gtk.Image.new_from_icon_name("dialog-warning-symbolic"))
            group.add(row)
        page.add(group)

        pending = [c for c in changes if c["state"] != "same"]
        same = [c for c in changes if c["state"] == "same"]

        # Grouped by backup location, so a whole category — all of
        # /etc/sudoers.d on a machine with different users — can be left out
        # with one checkbox instead of hunting its files down one by one.
        locations = backup_module.backup_paths(self.window.catalogue)
        by_location: dict[str, list[dict]] = {}
        for change in pending:
            key = backup_module.location_of(change["path"], locations)
            by_location.setdefault(key, []).append(change)

        self._path_checks: dict[str, Gtk.CheckButton] = {}
        for location in sorted(by_location):
            entries = by_location[location]
            replaced = sum(1 for c in entries if c["state"] == "differs")
            created = len(entries) - replaced
            parts = []
            if replaced:
                parts.append(f"{replaced} replaced (.bak kept)")
            if created:
                parts.append(f"{created} created")
            group = Adw.PreferencesGroup(
                title=location,
                description=" · ".join(
                    p for p in (LOCATION_HINTS.get(location, ""), *parts) if p
                ),
            )
            everything = Gtk.CheckButton(active=True, valign=Gtk.Align.CENTER)
            everything.set_tooltip_text("Include or skip this whole location")
            everything.connect("toggled", self._on_toggle_location, location)
            group.set_header_suffix(everything)
            for change in entries:
                row = self._row(
                    change["path"],
                    "would be replaced — the current file is kept as .bak"
                    if change["state"] == "differs"
                    else "would be created",
                )
                check = Gtk.CheckButton(active=True, valign=Gtk.Align.CENTER)
                check.connect("toggled", self._on_toggle_path, change["path"])
                self._path_checks[change["path"]] = check
                row.add_suffix(check)
                group.add(row)
            page.add(group)
        self._restore_locations = by_location

        if same:
            group = Adw.PreferencesGroup(
                title=f"{len(same)} file(s) already match",
                description="Identical to what is on disk, so they are left alone.",
            )
            for change in same[:40]:
                group.add(self._row(change["path"]))
            page.add(group)

        self._footer(restore=bool(pending))
        return False

    def _on_toggle_path(self, button: Gtk.CheckButton, path: str) -> None:
        if button.get_active():
            self._restore_selected.add(path)
        else:
            self._restore_selected.discard(path)

    def _on_toggle_location(self, button: Gtk.CheckButton, location: str) -> None:
        for change in self._restore_locations.get(location, []):
            check = self._path_checks.get(change["path"])
            if check is not None:
                # Drives _on_toggle_path, which keeps the selection in step.
                check.set_active(button.get_active())

    def _on_restore(self, _button: Gtk.Button) -> None:
        if not self._restore_selected:
            return
        self._busy("Restoring", "Backing up what is there now, then writing.")

        def worker() -> None:
            outcome = privileged.restore_apply(
                self._restore_source, sorted(self._restore_selected),
                on_progress=self._progress,
            )
            facts = None
            if outcome.ok:
                # Gathered here for the same reason ApplyProgressDialog does:
                # probe.gather() on the main thread freezes the whole window.
                self._progress("Re-reading system state")
                facts = probe.gather(self.window.catalogue)
            GLib.idle_add(self._restore_done, outcome, facts)

        threading.Thread(target=worker, daemon=True).start()

    def _restore_done(self, outcome, facts=None) -> bool:
        page = self._page()
        if outcome.ok:
            group = Adw.PreferencesGroup(
                title="Restored",
                description="Your files are back. Some settings need a reboot to "
                            "take effect.",
            )
        else:
            detail = outcome.error or "no detail given"
            if outcome.rolled_back:
                detail += "  Every file was put back, so nothing changed."
            group = Adw.PreferencesGroup(title="The restore failed")
            group.add(self._row(detail, ""))

        for step in outcome.steps[:60]:
            group.add(self._row(
                f"{step.get('kind', '?')}: {step.get('detail', '')}",
                step.get("output", "")[:200],
            ))
        page.add(group)
        self._footer()

        if outcome.ok:
            self.window.refresh_from_system(facts)
        return False

    # ------------------------------------------------------------------ #

    def _footer(self, restore: bool = False, back_up: bool = False) -> None:
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        box.set_margin_start(12)
        box.set_margin_end(12)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        box.append(Gtk.Label(hexpand=True))

        close = Gtk.Button(label="Close")
        close.connect("clicked", lambda *_: self.close())
        box.append(close)

        if restore:
            button = Gtk.Button(label="Restore these files")
            button.add_css_class("destructive-action")
            button.connect("clicked", self._on_restore)
            box.append(button)
        if back_up:
            button = Gtk.Button(label="Choose where…")
            button.add_css_class("suggested-action")
            button.connect("clicked", self._on_pick_backup)
            box.append(button)

        if self._button_bar is not None:
            self.toolbar.remove(self._button_bar)
        self._button_bar = box
        self.toolbar.add_bottom_bar(box)
