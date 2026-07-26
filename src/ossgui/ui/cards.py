"""The flag card — the visual unit of the grid, per the mockup.

Anatomy (GUI_MOCKUP.html): toggle (or a dropdown for multi-value flags, or an
entry for editable ones) · title · one-line desc · the key in small mono · risk
badge · status dot in the corner. Cards with caution/breaking/one-way risk get a
coloured border so they are scannable.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk, Pango  # noqa: E402

from ..catalogue import Flag, Section  # noqa: E402
from ..probe import FlagState, State  # noqa: E402
from ..staging import Staging  # noqa: E402

#: Status dot glyphs, matching the mockup's legend.
DOT = {
    State.APPLIED: "●",
    State.PENDING_REBOOT: "◐",
    State.DIFFERS: "◍",
    State.NOT_SET: "○",
    State.INVALID: "✕",
    State.UNKNOWN: "◌",
}

DOT_TOOLTIP = {
    State.APPLIED: "Applied — the live value matches",
    State.PENDING_REBOOT: "Written to disk, takes effect after a reboot",
    State.DIFFERS: "Drift — the live value does not match our file",
    State.NOT_SET: "Not set — system default",
    State.INVALID: "Not available on this system",
    State.UNKNOWN: "Could not be read without root",
}

RISK_LABEL = {"caution": "caution", "breaking": "breaks things", "one-way": "one-way"}


class FlagCard(Gtk.Box):
    """One flag, staged or not."""

    __gtype_name__ = "OssFlagCard"

    def __init__(
        self,
        flag: Flag,
        section: Section,
        staging: Staging,
        state: FlagState | None = None,
        unavailable_reason: str = "",
    ) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        self.flag = flag
        self.section = section
        self.staging = staging
        self.state = state
        self._updating = False

        self.add_css_class("flag-card")
        if flag.risk != "safe":
            self.add_css_class(f"risk-{flag.risk}")
        self.set_focusable(True)
        # The grid is `repeat(auto-fit, minmax(220px, 1fr))` in the mockup. A
        # FlowBox lays out on each child's *natural* width, so without a cap the
        # long title and desc labels demand enough room to force two columns.
        self.set_size_request(220, -1)

        self._build_top_row()
        self._build_body()

        if unavailable_reason:
            self.add_css_class("unavailable")
            self.set_sensitive(False)
            self.set_tooltip_text(unavailable_reason)
        else:
            self.set_tooltip_text(self._tooltip())

        self.refresh()

    # -- construction ------------------------------------------------------ #

    def _build_top_row(self) -> None:
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        row.set_valign(Gtk.Align.CENTER)

        self.control: Gtk.Widget
        if self.flag.is_choice:
            # A multi-value flag keeps a switch for on/off plus a dropdown for
            # which value — otherwise there is no way to express "not set".
            self.switch = Gtk.Switch(valign=Gtk.Align.CENTER)
            self.switch.connect("state-set", self._on_switch)
            row.append(self.switch)
        elif self.flag.editable:
            self.switch = Gtk.Switch(valign=Gtk.Align.CENTER)
            self.switch.connect("state-set", self._on_switch)
            row.append(self.switch)
        else:
            self.switch = Gtk.Switch(valign=Gtk.Align.CENTER)
            self.switch.connect("state-set", self._on_switch)
            row.append(self.switch)

        title = Gtk.Label(label=self.flag.title, xalign=0)
        title.add_css_class("flag-title")
        title.set_wrap(True)
        title.set_max_width_chars(18)
        title.set_hexpand(True)
        row.append(title)

        if self.flag.risk in RISK_LABEL:
            badge = Gtk.Label(label=RISK_LABEL[self.flag.risk])
            badge.add_css_class("risk-badge")
            badge.add_css_class(self.flag.risk)
            badge.set_valign(Gtk.Align.CENTER)
            row.append(badge)

        if self.flag.hw:
            hw = Gtk.Label(label="hardware")
            hw.add_css_class("risk-badge")
            hw.add_css_class("hw-badge")
            hw.set_tooltip_text(
                "Specific to the hardware this was captured from — skipped by "
                "default when the preset is applied to a different machine."
            )
            row.append(hw)

        self.dot = Gtk.Label(label="○")
        self.dot.add_css_class("status-dot")
        self.dot.set_valign(Gtk.Align.START)
        row.append(self.dot)

        self.append(row)

    def _build_body(self) -> None:
        if self.flag.desc:
            desc = Gtk.Label(label=self.flag.desc, xalign=0)
            desc.add_css_class("flag-desc")
            desc.set_wrap(True)
            desc.set_max_width_chars(26)
            self.append(desc)

        if self.flag.is_choice:
            self.dropdown = Gtk.DropDown.new_from_strings(
                [self.flag.label_for(v) for v in self.flag.values]
            )
            self.dropdown.set_halign(Gtk.Align.START)
            self.dropdown.connect("notify::selected", self._on_dropdown)
            self.append(self.dropdown)
        elif self.flag.editable:
            self.entry = Gtk.Entry(text=self.flag.value)
            self.entry.set_placeholder_text(self.flag.default or "value")
            self.entry.connect("changed", self._on_entry)
            self.append(self.entry)

        key_line = self._key_line()
        if key_line:
            key = Gtk.Label(label=key_line, xalign=0)
            key.add_css_class("flag-key")
            key.set_ellipsize(Pango.EllipsizeMode.END)
            # Without a cap the natural width of a long key (an audit rule, a
            # dotted sysctl path) sets the whole column width, and a homogeneous
            # FlowBox then only fits two per row instead of three.
            key.set_max_width_chars(24)
            key.set_width_chars(0)
            key.set_selectable(True)
            key.set_tooltip_text(key_line)
            self.append(key)

    def _key_line(self) -> str:
        syntax = self.section.syntax_for(self.flag)
        if syntax == "modprobe":
            return f"blacklist {self.flag.key}"
        if syntax == "services":
            return self.flag.key
        if syntax == "grub" and not self.flag.key.startswith("GRUB_"):
            value = self.staging.value(self.flag.id) or self.flag.value
            return self.flag.key if not value else f"{self.flag.key}={value}"
        if syntax == "auditd":
            return self.flag.key[:60]
        value = self.staging.value(self.flag.id) or self.flag.value
        return f"{self.flag.key} = {value}" if value else self.flag.key

    def _tooltip(self) -> str:
        parts = []
        if self.flag.why:
            parts.append(self.flag.why)
        if self.flag.help:
            parts.append(self.flag.help)
        if self.flag.breaks:
            parts.append(f"Breaks: {self.flag.breaks}")
        if self.flag.default:
            parts.append(f"System default: {self.flag.default}")
        if self.state and self.state.note:
            parts.append(self.state.note)
        return "\n\n".join(parts)

    # -- signal handlers --------------------------------------------------- #

    def _on_switch(self, _switch: Gtk.Switch, active: bool) -> bool:
        if self._updating:
            return False
        if active:
            self.staging.set(self.flag.id, self._current_control_value())
        else:
            self.staging.set(self.flag.id, None)
        return False

    def _on_dropdown(self, *_args) -> None:
        if self._updating:
            return
        if self.staging.is_set(self.flag.id):
            self.staging.set(self.flag.id, self._current_control_value())

    def _on_entry(self, *_args) -> None:
        if self._updating:
            return
        value = self.entry.get_text().strip()
        valid = self.flag.value_is_allowed(value)
        if valid:
            self.entry.remove_css_class("error")
            if self.staging.is_set(self.flag.id):
                self.staging.set(self.flag.id, value)
        else:
            self.entry.add_css_class("error")

    def _current_control_value(self) -> str:
        if self.flag.is_choice:
            index = self.dropdown.get_selected()
            if 0 <= index < len(self.flag.values):
                return self.flag.values[index]
            return self.flag.value
        if self.flag.editable:
            value = self.entry.get_text().strip()
            return value if self.flag.value_is_allowed(value) else self.flag.value
        return self.flag.value

    # -- refresh ----------------------------------------------------------- #

    def refresh(self, state: FlagState | None = None) -> None:
        """Re-read staging (and optionally a new probe state) into the widgets."""
        if state is not None:
            self.state = state
        self._updating = True
        try:
            staged = self.staging.is_set(self.flag.id)
            self.switch.set_active(staged)

            value = self.staging.value(self.flag.id)
            if self.flag.is_choice and value in self.flag.values:
                self.dropdown.set_selected(self.flag.values.index(value))
            elif self.flag.editable and value is not None:
                if self.entry.get_text() != value:
                    self.entry.set_text(value)

            if hasattr(self, "dropdown"):
                self.dropdown.set_sensitive(staged)
            if hasattr(self, "entry"):
                self.entry.set_sensitive(staged)

            if self.staging.is_changed(self.flag.id):
                self.add_css_class("selected")
            else:
                self.remove_css_class("selected")

            if self.state is not None:
                self.dot.set_label(DOT.get(self.state.state, "○"))
                self.dot.set_tooltip_text(
                    self.state.note or DOT_TOOLTIP.get(self.state.state, "")
                )
                for name in list(DOT):
                    self.dot.remove_css_class(f"status-{name.value}")
                self.dot.add_css_class(f"status-{self.state.state.value}")
        finally:
            self._updating = False


class GroupHeader(Gtk.Box):
    """`kernel / memory` on the left, `select all (33)` on the right."""

    __gtype_name__ = "OssGroupHeader"

    def __init__(self, section: Section, group: str, staging: Staging) -> None:
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.section = section
        self.group = group
        self.staging = staging

        label = Gtk.Label(label=group, xalign=0)
        label.add_css_class("group-header")
        label.set_hexpand(True)
        self.append(label)

        count = sum(1 for f in section.flags if f.group == group)
        self.button = Gtk.Button(label=f"select all ({count})")
        self.button.add_css_class("flat")
        self.button.connect("clicked", self._on_clicked)
        self.append(self.button)

        self.refresh()

    def _on_clicked(self, _button: Gtk.Button) -> None:
        full = self.staging.group_is_full(self.section.id, self.group)
        self.staging.select_group(self.section.id, self.group, not full)

    def refresh(self) -> None:
        count = sum(1 for f in self.section.flags if f.group == self.group)
        if self.staging.group_is_full(self.section.id, self.group):
            self.button.set_label(f"clear all ({count})")
        else:
            self.button.set_label(f"select all ({count})")
