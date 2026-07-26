"""Unit browser — mask or disable any systemd unit on the system (§4.13).

The catalogue's curated service flags are still the grid below this, because
those are what presets can carry. This page is for everything else: 500-odd
units, searchable, each showing what it listens on so it is obvious what closes
when you turn it off.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from .. import units as units_module  # noqa: E402

#: How many units to show before requiring a search — the full list is ~500 rows
#: and building them all makes the page crawl.
PAGE_LIMIT = 60

ACTION_LABELS = {
    "": "leave alone",
    "disable": "disable (won't start at boot)",
    "mask": "mask (cannot be started at all)",
    "enable": "enable",
    "unmask": "unmask",
}


class ServicesPage(Gtk.Box):
    """Search, inspect and stage changes to any unit."""

    __gtype_name__ = "OssServicesPage"

    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.window = window
        self.sockets = units_module.read_sockets()
        self.search = ""
        self.show_listening_only = False
        self.append(self._build())

    # ------------------------------------------------------------------ #

    def _units(self) -> list[units_module.Unit]:
        out = []
        for name, state in sorted(self.window.facts.units.items()):
            sockets = units_module.sockets_for(name, self.sockets)
            out.append(units_module.Unit(name=name, state=state, sockets=sockets))
        return out

    def _filtered(self) -> tuple[list[units_module.Unit], int]:
        units = self._units()
        if self.show_listening_only:
            units = [u for u in units if u.sockets]
        if self.search:
            units = [u for u in units if self.search in u.name.lower()]
        total = len(units)
        # Staged units always stay visible, or they would vanish as you type.
        staged = [u for u in units if u.name in self.window.unit_changes]
        rest = [u for u in units if u.name not in self.window.unit_changes]
        return (staged + rest)[:PAGE_LIMIT], total

    def _rebuild(self) -> None:
        self.window._show_section(self.window.current_section)

    def _build(self) -> Gtk.Widget:
        # Plain groups in a box, not an Adw.PreferencesPage: this page shares the
        # scroller with the curated flag grid below it, and a PreferencesPage
        # brings its own scroller that collapses to nothing when it is not the
        # only child.
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_margin_bottom(14)
        box.append(self._exposure_group())
        box.append(self._browser_group())
        return box

    # -- what is listening ---------------------------------------------- #

    def _exposure_group(self) -> Adw.PreferencesGroup:
        public = [s for s in self.sockets if s.public]
        group = Adw.PreferencesGroup(
            title="What is listening",
            description=(
                f"{len(self.sockets)} listening socket(s), {len(public)} of them "
                f"reachable from the network rather than loopback only. Process "
                f"names are missing for root-owned sockets, which an unprivileged "
                f"read cannot see."
            ),
        )
        if not public:
            group.add(
                Adw.ActionRow(
                    title="Nothing is listening on a network address",
                    subtitle="Every open socket is bound to loopback.",
                )
            )
            return group

        seen: set[tuple[int, str]] = set()
        for socket in sorted(public, key=lambda s: s.port):
            if (socket.port, socket.proto) in seen:
                continue
            seen.add((socket.port, socket.proto))
            title = f"{socket.port}/{socket.proto}"
            if socket.name:
                title += f"  —  {socket.name}"
            row = Adw.ActionRow(
                title=title,
                subtitle=f"bound to {socket.address}",
            )
            icon = Gtk.Image.new_from_icon_name("network-transmit-receive-symbolic")
            row.add_prefix(icon)
            group.add(row)
        return group

    # -- browser --------------------------------------------------------- #

    def _browser_group(self) -> Adw.PreferencesGroup:
        shown, total = self._filtered()
        group = Adw.PreferencesGroup(
            title="All units",
            description=(
                f"{total} unit(s) match. Masking is stronger than disabling: a "
                f"masked unit is symlinked to /dev/null and cannot be started at "
                f"all, even as a dependency of something else."
            ),
        )

        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        controls.set_margin_top(4)
        controls.set_margin_bottom(4)

        entry = Gtk.SearchEntry(placeholder_text="Filter units", hexpand=True)
        entry.set_text(self.search)
        entry.connect("search-changed", self._on_search)
        controls.append(entry)

        toggle = Gtk.ToggleButton(label="Listening only")
        toggle.set_active(self.show_listening_only)
        toggle.connect("toggled", self._on_listening_toggle)
        controls.append(toggle)

        holder = Adw.PreferencesRow(activatable=False, selectable=False)
        holder.set_child(controls)
        group.add(holder)

        if not shown:
            group.add(Adw.ActionRow(title="No units match", subtitle="Try a different filter."))
            return group

        for unit in shown:
            group.add(self._unit_row(unit))

        if total > len(shown):
            group.add(
                Adw.ActionRow(
                    title=f"{total - len(shown)} more not shown",
                    subtitle="Narrow the filter to reach them.",
                )
            )
        return group

    def _unit_row(self, unit: units_module.Unit) -> Adw.ActionRow:
        staged = self.window.unit_changes.get(unit.name, "")
        subtitle_parts = [f"currently {unit.state}"]
        if unit.ports:
            subtitle_parts.append(f"listening on {unit.ports}")
        if unit.warning:
            subtitle_parts.append(unit.warning)
        if not unit.can_mask:
            subtitle_parts.append("Required by the system — masking is refused.")

        row = Adw.ActionRow(title=unit.name, subtitle=" · ".join(subtitle_parts))
        row.set_subtitle_lines(3)

        options = ["", "disable", "mask"] if unit.can_mask else ["", "disable"]
        if unit.state == "masked":
            options = ["", "unmask"]
        elif unit.state == "disabled":
            options = ["", "enable"] + options[1:]

        drop = Gtk.DropDown.new_from_strings([ACTION_LABELS[o] for o in options])
        drop.set_valign(Gtk.Align.CENTER)
        if staged in options:
            drop.set_selected(options.index(staged))
        drop.connect("notify::selected", self._on_action, unit.name, options)
        row.add_suffix(drop)

        if staged:
            badge = Gtk.Label(label="staged")
            badge.add_css_class("changed-counter")
            badge.add_css_class("caption")
            row.add_suffix(badge)
        if unit.warning:
            icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
            icon.add_css_class("status-pending-reboot")
            row.add_prefix(icon)
        return row

    # -- handlers -------------------------------------------------------- #

    def _on_search(self, entry: Gtk.SearchEntry) -> None:
        self.search = entry.get_text().strip().lower()
        self._rebuild()

    def _on_listening_toggle(self, button: Gtk.ToggleButton) -> None:
        self.show_listening_only = button.get_active()
        self._rebuild()

    def _on_action(self, drop: Gtk.DropDown, _param, name: str, options: list[str]) -> None:
        index = drop.get_selected()
        if not 0 <= index < len(options):
            return
        action = options[index]
        if action:
            try:
                units_module.validate(name, action)
            except units_module.UnitError as exc:
                self.window.toast(str(exc))
                return
            self.window.unit_changes[name] = action
        else:
            self.window.unit_changes.pop(name, None)
        self.window._refresh_chrome()
