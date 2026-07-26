"""Dashboard — how this machine is configured right now.

Read-only, and the first thing you see. The grids answer "what do I want to
change"; this answers "what have I got, where did it come from, and what is
quietly wrong with it".
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from .. import probe, sysctl_chain  # noqa: E402
from ..probe import State  # noqa: E402

#: Order and presentation of the five states (§6).
STATE_ROWS = [
    (State.APPLIED, "in effect", "status-applied", "●"),
    (State.PENDING_REBOOT, "waiting for reboot", "status-pending-reboot", "◐"),
    (State.DIFFERS, "drifted", "status-differs", "◍"),
    (State.NOT_SET, "not set", "status-not-set", "○"),
    (State.INVALID, "not available here", "status-invalid", "✕"),
    (State.UNKNOWN, "needs root to read", "status-unknown", "◌"),
]

SEVERITY_ICON = {
    "high": "dialog-warning-symbolic",
    "info": "dialog-information-symbolic",
}


class Dashboard(Gtk.Box):
    """The read-only status view."""

    __gtype_name__ = "OssDashboard"

    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.window = window
        self.chain = sysctl_chain.read()
        self.append(self._build())

    # ------------------------------------------------------------------ #

    def _build(self) -> Gtk.Widget:
        page = Adw.PreferencesPage()
        page.add(self._summary_group())
        page.add(self._findings_group())
        page.add(self._layers_group())
        page.add(self._sections_group())
        return page

    # -- summary -------------------------------------------------------- #

    def _counts(self) -> dict[State, int]:
        counts = {state: 0 for state, *_ in STATE_ROWS}
        for flag_state in self.window.states.values():
            counts[flag_state.state] = counts.get(flag_state.state, 0) + 1
        return counts

    def _summary_group(self) -> Adw.PreferencesGroup:
        counts = self._counts()
        applied = counts.get(State.APPLIED, 0)
        # "Available" excludes what this kernel or this machine cannot do, so the
        # number is not diluted by flags that were never on the table.
        unavailable = counts.get(State.INVALID, 0)
        total = max(1, len(self.window.states) - unavailable)
        percent = round(100 * applied / total)

        group = Adw.PreferencesGroup(
            title="Current configuration",
            description=(
                f"{applied} of {total} available settings are in effect "
                f"({percent}%). This counts what the machine is actually doing, "
                f"however it got that way — not just what this app wrote."
            ),
        )

        # One proportional bar: the shape of the configuration at a glance,
        # before any of the numbers underneath it.
        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=2)
        bar.set_margin_top(4)
        bar.set_margin_bottom(10)
        total_flags = max(1, len(self.window.states))
        for state, label, css, _glyph in STATE_ROWS:
            count = counts.get(state, 0)
            if not count:
                continue
            segment = Gtk.Box(height_request=12)
            segment.set_hexpand(True)
            # hexpand distributes leftover space evenly, so the proportion comes
            # from the size request rather than the expand flag.
            segment.set_size_request(max(6, int(700 * count / total_flags)), 12)
            segment.add_css_class(css.replace("status-", "meter-"))
            segment.set_tooltip_text(f"{count} {label}")
            bar.append(segment)

        holder = Adw.PreferencesRow(activatable=False, selectable=False)
        holder.set_child(bar)
        group.add(holder)

        for state, label, css, glyph in STATE_ROWS:
            count = counts.get(state, 0)
            if not count:
                continue
            row = Adw.ActionRow(title=f"{count} {label}")
            dot = Gtk.Label(label=glyph)
            dot.add_css_class(css)
            row.add_prefix(dot)
            group.add(row)
        return group

    # -- findings ------------------------------------------------------- #

    def _findings(self) -> list[tuple[str, str, str]]:
        out = list(sysctl_chain.findings(self.chain))

        selection = self.window.staging.selection
        kdump = probe.kdump_conflict(self.window.facts, {})
        if kdump:
            out.append(("high", "kdump can never fire", kdump))
        redundant = probe.slab_debug_redundancy(selection)
        if redundant:
            out.append(("info", "Redundant pair of boot flags", redundant))
        dot = probe.dot_without_firewall_port(selection)
        if dot:
            out.append(("high", "DNS over TLS would break", dot))

        for section_id, detail in probe.broken_includes(self.window.catalogue):
            out.append((
                "high",
                f"{section_id}: its drop-in directory is not included",
                detail,
            ))

        loaded_but_blacklisted = [
            flag_id
            for flag_id, state in self.window.states.items()
            if state.state is State.PENDING_REBOOT
            and (flag := self.window.catalogue.get(flag_id))
            and flag.section == "modprobe"
        ]
        if loaded_but_blacklisted:
            names = ", ".join(
                self.window.catalogue.flags[i].key for i in loaded_but_blacklisted[:6]
            )
            out.append((
                "info",
                f"{len(loaded_but_blacklisted)} blacklisted module(s) still loaded",
                f"Blacklisting stops a module loading; it does not unload one that "
                f"is already in the kernel. These need a reboot: {names}"
                + ("…" if len(loaded_but_blacklisted) > 6 else ""),
            ))
        return out

    def _findings_group(self) -> Adw.PreferencesGroup:
        findings = self._findings()
        high = sum(1 for severity, *_ in findings if severity == "high")

        group = Adw.PreferencesGroup(
            title="Findings",
            description=(
                "Things that are wrong or misleading in the configuration as it "
                "stands — read from the files, not from what anyone intended."
            ),
        )
        if not findings:
            group.add(Adw.ActionRow(title="Nothing to report", subtitle="No conflicts, no dead keys."))
            return group

        group.set_title(f"Findings — {high} worth acting on" if high else "Findings")
        for severity, title, detail in findings:
            row = Adw.ActionRow(title=GLib.markup_escape_text(title))
            row.set_subtitle(GLib.markup_escape_text(detail))
            row.set_title_lines(2)
            row.set_subtitle_lines(8)
            icon = Gtk.Image.new_from_icon_name(SEVERITY_ICON.get(severity, "dialog-information-symbolic"))
            if severity == "high":
                icon.add_css_class("status-pending-reboot")
            row.add_prefix(icon)
            group.add(row)
        return group

    # -- layers --------------------------------------------------------- #

    def _layers_group(self) -> Adw.PreferencesGroup:
        vendor = self.chain.vendor_layer_edits()
        group = Adw.PreferencesGroup(
            title="Where your sysctl settings come from",
            description=(
                f"{len(self.chain.keys)} keys are in effect across "
                f"{len(sysctl_chain.ordered_files())} files. Later filenames win, "
                f"and a file in /etc shadows the same name in /usr/lib entirely."
            ),
        )

        by_layer: dict[str, int] = {}
        for result in self.chain.keys.values():
            layer = str(result.winner.source.parent)
            by_layer[layer] = by_layer.get(layer, 0) + 1

        for layer, count in sorted(by_layer.items(), key=lambda item: -item[1]):
            if layer == sysctl_chain.VENDOR_LAYER:
                subtitle = (
                    "Vendor layer — the next procps or systemd upgrade replaces "
                    "these files and takes your changes with them."
                )
            elif layer == sysctl_chain.OUR_LAYER:
                subtitle = "Your layer — survives upgrades. This is where the app writes."
            else:
                subtitle = "Applied last of all, so it overrides every directory."
            row = Adw.ActionRow(title=f"{layer}  —  {count} key(s)", subtitle=subtitle)
            group.add(row)

        if vendor:
            migratable = sysctl_chain.migration_selection(self.chain, self.window.catalogue)
            row = Adw.ActionRow(
                title=f"Move {len(migratable)} of them into /etc/sysctl.d",
                subtitle=(
                    "Stages the same values as changes you can review and apply, so "
                    "they land in the layer that is yours. The vendor files are left "
                    "alone — /etc wins over them anyway."
                ),
            )
            row.set_subtitle_lines(4)
            button = Gtk.Button(label="Stage migration", valign=Gtk.Align.CENTER)
            button.add_css_class("suggested-action")
            button.set_sensitive(bool(migratable))
            button.connect("clicked", self._on_migrate, migratable)
            row.add_suffix(button)
            group.add(row)
        return group

    def _on_migrate(self, _button: Gtk.Button, migratable: dict[str, str]) -> None:
        self.window.staging.set_many(migratable, preset_name="Vendor-layer migration")
        self.window.toast(
            f"Staged {len(migratable)} setting(s) to move into /etc/sysctl.d. "
            "Review shows exactly what gets written."
        )

    # -- per-section ---------------------------------------------------- #

    def _sections_group(self) -> Adw.PreferencesGroup:
        group = Adw.PreferencesGroup(
            title="By section",
            description="Click a section in the sidebar to work through it.",
        )
        for section in self.window.catalogue.sections:
            if not section.flags:
                continue
            counts: dict[State, int] = {}
            for flag in section.flags:
                state = self.window.states.get(flag.id)
                if state is not None:
                    counts[state.state] = counts.get(state.state, 0) + 1

            parts = [
                f"{counts[state]} {label}"
                for state, label, _css, _glyph in STATE_ROWS
                if counts.get(state)
            ]
            row = Adw.ActionRow(
                title=section.title,
                subtitle=" · ".join(parts) or "nothing to report",
            )
            applied = counts.get(State.APPLIED, 0)
            total = len(section.flags) - counts.get(State.INVALID, 0)
            badge = Gtk.Label(label=f"{applied}/{max(total, 0)}")
            badge.add_css_class("changed-counter")
            row.add_suffix(badge)
            group.add(row)
        return group
