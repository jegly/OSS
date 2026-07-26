"""Snap permissions — what each snap is allowed to reach.

Snaps have no permission UI outside `snap connections` and `snap disconnect`, so
this is the whole feature: pick a snap, see what it has access to, revoke what it
does not need.

Everything shown is read unprivileged. Only the changes need root, and they go
through the same review-then-apply path as the rest of the app.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from .. import snapd  # noqa: E402


class SnapPage(Gtk.Box):
    """Per-snap interface list with connect/disconnect."""

    __gtype_name__ = "OssSnapPage"

    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.window = window
        if not hasattr(window, "snaps"):
            window.snaps = snapd.read_all()
        self.append(self._build())

    def _rebuild(self) -> None:
        self.window._show_section(self.window.current_section)

    def _build(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_margin_bottom(14)

        if not snapd.available():
            group = Adw.PreferencesGroup(title="Snap permissions")
            group.add(
                self._row(
                    "snapd is not installed",
                    "Nothing to configure. This section is for controlling what "
                    "installed snaps are allowed to reach.",
                )
            )
            box.append(group)
            return box

        interesting = [s for s in self.window.snaps if not s.is_base and s.plugs]
        if not interesting:
            group = Adw.PreferencesGroup(title="Snap permissions")
            group.add(self._row("No snaps with adjustable permissions", ""))
            box.append(group)
            return box

        box.append(self._intro_group(interesting))
        box.append(self._picker_group(interesting))

        chosen = getattr(self.window, "snap_selected", interesting[0].name)
        snap = next((s for s in interesting if s.name == chosen), interesting[0])
        self.window.snap_selected = snap.name
        box.append(self._interfaces_group(snap))
        return box

    # ------------------------------------------------------------------ #

    def _intro_group(self, snaps: list) -> Adw.PreferencesGroup:
        staged = len(self.window.snap_changes)
        total_sensitive = sum(
            1 for s in snaps for c in s.plugs if c.connected and c.sensitive
        )
        return Adw.PreferencesGroup(
            title="Snap permissions",
            description=(
                f"{len(snaps)} snap(s) with adjustable interfaces. A snap's *plugs* "
                f"are the things it asks for; a plug connected to a slot is a "
                f"granted permission, and disconnecting it revokes that access "
                f"immediately — no reinstall, no reboot.\n\n"
                f"{total_sensitive} connected interface(s) across all snaps grant a "
                f"real capability worth reviewing: the camera, the microphone, your "
                f"SSH keys, removable media."
                + (f"\n\n{staged} change(s) staged." if staged else "")
            ),
        )

    def _picker_group(self, snaps: list) -> Adw.PreferencesGroup:
        group = Adw.PreferencesGroup()
        names = [s.name for s in snaps]
        labels = [
            f"{s.name}   {s.connected_count}/{len(s.plugs)} connected" for s in snaps
        ]
        row = Adw.ComboRow(
            title="Snap",
            subtitle="Publisher and version are shown below",
            model=Gtk.StringList.new(labels),
        )
        chosen = getattr(self.window, "snap_selected", names[0])
        if chosen in names:
            row.set_selected(names.index(chosen))
        row.connect("notify::selected", self._on_snap, names)
        group.add(row)
        return group

    def _interfaces_group(self, snap) -> Adw.PreferencesGroup:
        group = Adw.PreferencesGroup(
            title=f"{snap.name} — {len(snap.plugs)} interface(s)",
            description=f"{snap.version} from {snap.publisher}",
        )

        # Sensitive first, then the rest: the ones worth a decision at the top.
        def sort_key(connection):
            return (
                0 if connection.sensitive else (2 if connection.essential else 1),
                connection.interface,
            )

        for connection in sorted(snap.plugs, key=sort_key):
            group.add(self._interface_row(connection))
        return group

    def _interface_row(self, connection) -> Adw.ActionRow:
        staged = self.window.snap_changes.get(connection.plug)
        wanted = (
            connection.connected if staged is None else (staged == "connect")
        )

        subtitle_parts = [connection.plug]
        if connection.describe:
            subtitle_parts.append(connection.describe)
        if connection.essential:
            subtitle_parts.append("Disconnecting this is likely to break the snap.")
        if connection.slot:
            subtitle_parts.append(f"connected to {connection.slot}")

        row = Adw.SwitchRow(
            title=connection.interface,
            subtitle=" · ".join(subtitle_parts),
            active=wanted,
        )
        row.set_subtitle_lines(3)

        if connection.sensitive:
            badge = Gtk.Label(label="capability")
            badge.add_css_class("risk-badge")
            badge.add_css_class("caution")
            badge.set_valign(Gtk.Align.CENTER)
            row.add_suffix(badge)
        if connection.essential:
            icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
            icon.add_css_class("status-pending-reboot")
            row.add_prefix(icon)
        if staged is not None:
            tag = Gtk.Label(label="staged")
            tag.add_css_class("changed-counter")
            tag.add_css_class("caption")
            row.add_suffix(tag)

        row.connect("notify::active", self._on_toggle, connection)
        return row

    # ------------------------------------------------------------------ #

    def _on_snap(self, row: Adw.ComboRow, _param, names: list[str]) -> None:
        index = row.get_selected()
        if 0 <= index < len(names):
            self.window.snap_selected = names[index]
            self._rebuild()

    def _on_toggle(self, row: Adw.SwitchRow, _param, connection) -> None:
        wanted = row.get_active()
        if wanted == connection.connected:
            self.window.snap_changes.pop(connection.plug, None)
        else:
            action = "connect" if wanted else "disconnect"
            try:
                snapd.validate(connection.plug, action)
            except snapd.SnapError as exc:
                self.window.toast(str(exc))
                return
            self.window.snap_changes[connection.plug] = action
        self.window._refresh_chrome()

    @staticmethod
    def _row(title: str, subtitle: str) -> Adw.ActionRow:
        row = Adw.ActionRow(title=GLib.markup_escape_text(title))
        if subtitle:
            row.set_subtitle(GLib.markup_escape_text(subtitle))
        row.set_title_lines(2)
        row.set_subtitle_lines(4)
        return row
