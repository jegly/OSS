"""Set the mode of any file or folder, without touching a terminal.

A file picker, a grid of checkboxes, and a running explanation of what the choice
actually means. The explanation is the point: `0644` tells you nothing unless you
already know, and the meaning of the execute bit on a directory is the single
thing people most often get wrong.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from .. import filemode  # noqa: E402
from .style import mark_solid  # noqa: E402

#: (label, mask, bit) per row of the grid.
ROWS = [
    ("Owner", 0o400, 0o200, 0o100),
    ("Group", 0o040, 0o020, 0o010),
    ("Everyone else", 0o004, 0o002, 0o001),
]


class ModeDialog(Adw.Window):
    """Pick a path, pick a mode, see what it means, stage it."""

    __gtype_name__ = "OssModeDialog"

    def __init__(self, window) -> None:
        super().__init__(
            transient_for=window, modal=True, title="Set permissions",
            default_width=680, default_height=760,
        )
        mark_solid(self)
        self.window = window
        self.target: filemode.Target | None = None
        self.mode = 0o644
        self._updating = False

        self.toolbar = Adw.ToolbarView()
        self.toolbar.add_top_bar(Adw.HeaderBar())
        # A plain box in a scroller, not an Adw.PreferencesPage: a preferences
        # page owns its own scroller, so get_first_child() returns that rather
        # than the groups and remove() refuses it — the whole page cannot be
        # cleared and rebuilt, which is what every keystroke here needs to do.
        self.page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        self.page.set_margin_top(12)
        self.page.set_margin_bottom(12)
        self.page.set_margin_start(14)
        self.page.set_margin_end(14)
        scroller = Gtk.ScrolledWindow(child=self.page, vexpand=True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.toolbar.set_content(scroller)
        self.toolbar.add_bottom_bar(self._footer())
        self.set_content(self.toolbar)

        self._build()

    # ------------------------------------------------------------------ #

    def _footer(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        for side in ("start", "end"):
            getattr(box, f"set_margin_{side}")(12)
        box.set_margin_top(8)
        box.set_margin_bottom(8)

        self.footer_note = Gtk.Label(label="", xalign=0, wrap=True, hexpand=True)
        self.footer_note.add_css_class("lock-hint")
        box.append(self.footer_note)

        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda *_: self.close())
        box.append(cancel)

        self.stage_button = Gtk.Button(label="Stage change")
        self.stage_button.add_css_class("suggested-action")
        self.stage_button.set_sensitive(False)
        self.stage_button.connect("clicked", self._on_stage)
        box.append(self.stage_button)
        return box

    def _build(self) -> None:
        child = self.page.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self.page.remove(child)
            child = nxt

        self.page.append(self._path_group())
        if self.target is not None and self.target.exists:
            self.page.append(self._presets_group())
            self.page.append(self._grid_group())
            self.page.append(self._special_group())
            self.page.append(self._meaning_group())
            self.page.append(self._durability_group())
        self._refresh_footer()

    # -- choosing a path -------------------------------------------------- #

    def _path_group(self) -> Adw.PreferencesGroup:
        group = Adw.PreferencesGroup(
            title="File or folder",
            description=(
                "Pick anything on the system. Permissions decide who can read it, "
                "change it, and run or enter it."
            ),
        )

        row = Adw.ActionRow(
            title=self.target.path if self.target else "Nothing chosen yet",
            subtitle=(
                f"{self.target.mode_octal}  {self.target.mode_symbolic}  "
                f"{self.target.owner}:{self.target.group}"
                + ("  (folder)" if self.target.is_dir else "")
                if self.target and self.target.exists
                else "Choose a file or a folder to see its current permissions."
            ),
        )
        row.set_title_lines(2)

        pick_file = Gtk.Button(label="Choose file…", valign=Gtk.Align.CENTER)
        pick_file.connect("clicked", self._on_pick_file)
        row.add_suffix(pick_file)

        pick_folder = Gtk.Button(label="Choose folder…", valign=Gtk.Align.CENTER)
        pick_folder.connect("clicked", self._on_pick_folder)
        row.add_suffix(pick_folder)
        group.add(row)

        if self.target is not None and not self.target.exists:
            group.add(
                self._row("That path does not exist", "Nothing to change.")
            )
        if self.target is not None and self.target.protected:
            warn = self._row("This one is not offered", self.target.protected)
            icon = Gtk.Image.new_from_icon_name("dialog-error-symbolic")
            icon.add_css_class("status-differs")
            warn.add_prefix(icon)
            group.add(warn)
        if self.target is not None and self.target.override:
            group.add(
                self._row(
                    "dpkg already has an override for this path",
                    self.target.override,
                )
            )
        return group

    def _on_pick_file(self, _button: Gtk.Button) -> None:
        dialog = Gtk.FileDialog(title="Choose a file")
        dialog.open(self, None, self._picked)

    def _on_pick_folder(self, _button: Gtk.Button) -> None:
        dialog = Gtk.FileDialog(title="Choose a folder")
        dialog.select_folder(self, None, self._picked_folder)

    def _picked(self, dialog: Gtk.FileDialog, result, _data=None) -> None:
        try:
            file = dialog.open_finish(result)
        except GLib.Error:
            return  # cancelled
        self._use(file)

    def _picked_folder(self, dialog: Gtk.FileDialog, result, _data=None) -> None:
        try:
            file = dialog.select_folder_finish(result)
        except GLib.Error:
            return
        self._use(file)

    def _use(self, file: Gio.File | None) -> None:
        if file is None:
            return
        path = file.get_path()
        if not path:
            self.window.toast("That location is not a local path.")
            return
        try:
            self.target = filemode.inspect(path)
        except filemode.ModeError as exc:
            self.window.toast(str(exc))
            return
        # Start from what the path already has, so the grid shows reality first.
        self.mode = self.target.mode if self.target.exists else 0o644
        self._build()

    # -- presets ---------------------------------------------------------- #

    def _presets_group(self) -> Adw.PreferencesGroup:
        group = Adw.PreferencesGroup(
            title="Common choices",
            description="Each of these just sets the boxes below.",
        )
        seen: set[int] = set()
        for label, mode, note in filemode.PRESETS:
            if mode in seen:
                continue
            seen.add(mode)
            row = Adw.ActionRow(title=label, subtitle=f"{mode:04o} — {note}")
            button = Gtk.Button(label="Use", valign=Gtk.Align.CENTER)
            button.connect("clicked", self._on_preset, mode)
            row.add_suffix(button)
            group.add(row)
        return group

    def _on_preset(self, _button: Gtk.Button, mode: int) -> None:
        self.mode = mode
        self._build()

    # -- the grid --------------------------------------------------------- #

    def _grid_group(self) -> Adw.PreferencesGroup:
        is_dir = bool(self.target and self.target.is_dir)
        kind = 1 if is_dir else 0

        group = Adw.PreferencesGroup(
            title="Who can do what",
            description=(
                "On a folder these mean something different from a file: read "
                "lists the names inside, write adds and deletes entries, and "
                "execute is what lets you enter it at all."
                if is_dir
                else "Read looks at the contents, write changes them, execute runs "
                "the file as a program."
            ),
        )

        grid = Gtk.Grid(column_spacing=18, row_spacing=8)
        grid.set_margin_top(8)
        grid.set_margin_bottom(8)
        grid.set_margin_start(6)

        for column, (letter, heading) in enumerate(
            (("r", "Read"), ("w", "Write"), ("x", "Execute" if not is_dir else "Enter")),
            start=1,
        ):
            label = Gtk.Label(label=heading, xalign=0.5)
            label.add_css_class("heading")
            label.set_tooltip_text(filemode.BIT_HELP[letter][kind])
            grid.attach(label, column, 0, 1, 1)

        self._checks: dict[int, Gtk.CheckButton] = {}
        for row_index, (who, read, write, execute) in enumerate(ROWS, start=1):
            label = Gtk.Label(label=who, xalign=0)
            grid.attach(label, 0, row_index, 1, 1)
            for column, (bit, letter) in enumerate(
                ((read, "r"), (write, "w"), (execute, "x")), start=1
            ):
                check = Gtk.CheckButton(active=bool(self.mode & bit), halign=Gtk.Align.CENTER)
                check.set_tooltip_text(
                    f"{who}: {filemode.BIT_HELP[letter][kind]}"
                )
                check.connect("toggled", self._on_bit, bit)
                grid.attach(check, column, row_index, 1, 1)
                self._checks[bit] = check

        holder = Adw.PreferencesRow(activatable=False, selectable=False)
        holder.set_child(grid)
        group.add(holder)

        readout = Adw.ActionRow(
            title=f"{self.mode:04o}      {filemode.mode_string(self.mode)}",
            subtitle="What you would type as `chmod` — shown so the two match up.",
        )
        readout.add_css_class("monospace")
        group.add(readout)
        return group

    def _on_bit(self, check: Gtk.CheckButton, bit: int) -> None:
        if self._updating:
            return
        if check.get_active():
            self.mode |= bit
        else:
            self.mode &= ~bit
        self._build()

    # -- special bits ----------------------------------------------------- #

    def _special_group(self) -> Adw.PreferencesGroup:
        is_dir = bool(self.target and self.target.is_dir)
        group = Adw.PreferencesGroup(
            title="Special bits",
            description="Rarely needed, and worth understanding before setting.",
        )
        for label, bit, key in (
            ("Setuid", 0o4000, "setuid"),
            ("Setgid", 0o2000, "setgid"),
            ("Sticky", 0o1000, "sticky"),
        ):
            row = Adw.SwitchRow(
                title=label,
                subtitle=filemode.SPECIAL_HELP[key],
                active=bool(self.mode & bit),
            )
            row.set_subtitle_lines(3)
            if key == "setuid" and is_dir:
                row.set_sensitive(False)
                row.set_subtitle("Has no effect on a folder.")
            row.connect("notify::active", self._on_special, bit)
            group.add(row)
        return group

    def _on_special(self, row: Adw.SwitchRow, _param, bit: int) -> None:
        if self._updating:
            return
        if row.get_active():
            self.mode |= bit
        else:
            self.mode &= ~bit
        self._build()

    # -- what it means ---------------------------------------------------- #

    def _meaning_group(self) -> Adw.PreferencesGroup:
        is_dir = bool(self.target and self.target.is_dir)
        group = Adw.PreferencesGroup(title="What this means")

        for line in filemode.describe_mode(self.mode, is_dir).split("\n"):
            group.add(Adw.ActionRow(title=line))

        if self.target is not None:
            for note in filemode.consequences(self.mode, self.target):
                row = self._row("Worth knowing", note)
                icon = Gtk.Image.new_from_icon_name("dialog-information-symbolic")
                row.add_prefix(icon)
                group.add(row)
        return group

    # -- durability ------------------------------------------------------- #

    def _durability_group(self) -> Adw.PreferencesGroup:
        packaged = bool(self.target and self.target.packaged)
        group = Adw.PreferencesGroup(
            title="Make it stick",
            description=(
                "A plain chmod on a file that belongs to a package is undone the "
                "next time that package is upgraded. dpkg-statoverride records the "
                "mode instead, and dpkg honours it every time."
                if packaged
                else "Nothing owns this path, so a chmod will not be reverted."
            ),
        )

        self.durable_row = Adw.SwitchRow(
            title="Survive package upgrades",
            subtitle=(
                f"Records it with dpkg-statoverride. {self.target.package} would "
                f"otherwise put the old mode back."
                if packaged
                else "Only meaningful for a path a package owns."
            ),
            active=packaged,
        )
        self.durable_row.set_sensitive(packaged)
        self.durable_row.set_subtitle_lines(2)
        group.add(self.durable_row)

        self.immutable_row = Adw.SwitchRow(
            title="Also make it immutable",
            subtitle=(
                "chattr +i. Nothing can modify, rename or delete it, including "
                "root, until this is cleared. It also blocks apt from updating "
                "the file, so a package upgrade will fail with a confusing error."
            ),
            active=False,
        )
        self.immutable_row.set_subtitle_lines(3)
        group.add(self.immutable_row)
        return group

    # -- staging ---------------------------------------------------------- #

    def _refresh_footer(self) -> None:
        if self.target is None or not self.target.exists:
            self.footer_note.set_label("Choose a file or folder first.")
            self.stage_button.set_sensitive(False)
            return
        try:
            filemode.check_allowed(self.target.path, self.mode)
        except filemode.ModeError as exc:
            self.footer_note.set_label(str(exc))
            self.stage_button.set_sensitive(False)
            return
        if self.mode == self.target.mode:
            self.footer_note.set_label("That is what it is set to already.")
            self.stage_button.set_sensitive(False)
            return
        self.footer_note.set_label(
            f"{self.target.mode_octal} → {self.mode:04o}. Nothing is written until "
            f"you Apply."
        )
        self.stage_button.set_sensitive(True)

    def _on_stage(self, _button: Gtk.Button) -> None:
        if self.target is None:
            return
        try:
            filemode.check_allowed(self.target.path, self.mode)
        except filemode.ModeError as exc:
            self.window.toast(str(exc))
            return

        self.window.filemode_changes[self.target.path] = {
            "mode": self.mode,
            "owner": self.target.owner or "root",
            "group": self.target.group or "root",
            "durable": self.durable_row.get_active(),
            "immutable": self.immutable_row.get_active(),
        }
        self.window.toast(
            f"Staged {self.target.path} at {self.mode:04o}. Review shows the "
            f"exact command."
        )
        self.window._refresh_chrome()
        self.window._show_section(self.window.current_section)
        self.close()

    @staticmethod
    def _row(title: str, subtitle: str) -> Adw.ActionRow:
        row = Adw.ActionRow(title=GLib.markup_escape_text(title))
        if subtitle:
            row.set_subtitle(GLib.markup_escape_text(subtitle))
        row.set_title_lines(2)
        row.set_subtitle_lines(5)
        return row
