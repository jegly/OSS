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


def _row(title: str, subtitle: str = "", lines: int = 3) -> Adw.ActionRow:
    """A plain text row. Escaped, because sysfs strings reach this verbatim."""
    row = Adw.ActionRow(title=GLib.markup_escape_text(title))
    if subtitle:
        row.set_subtitle(GLib.markup_escape_text(subtitle))
    row.set_title_lines(2)
    row.set_subtitle_lines(lines)
    return row

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

#: Which Overview filter answers "which ones?" for each state row.
STATE_FILTER = {
    State.APPLIED: "in effect",
    State.PENDING_REBOOT: "needs reboot",
    State.DIFFERS: "drift",
    State.NOT_SET: "not applied",
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
        page.add(self._vulnerabilities_group())
        page.add(self._layers_group())
        page.add(self._sections_group())
        return page

    # -- CPU vulnerabilities -------------------------------------------- #

    #: How each verdict is presented. The CSS classes are the same ones the
    #: state dots use, so "vulnerable" reads like drift and "mitigated" like
    #: applied without inventing a second colour vocabulary.
    VERDICT_STYLE = {
        "vulnerable": ("status-differs", "dialog-warning-symbolic", "vulnerable"),
        "unknown": ("status-unknown", "dialog-question-symbolic", "unknown"),
        "mitigated": ("status-applied", "emblem-ok-symbolic", "mitigated"),
        "not-affected": ("status-not-set", "emblem-default-symbolic", "not affected"),
    }

    def _vulnerabilities_group(self) -> Adw.PreferencesGroup:
        """What the CPU itself is exposed to, straight from sysfs.

        This is the one part of the dashboard the catalogue cannot change: the
        kernel decides what it can mitigate, and some of these have no fix
        available at all. Worth showing precisely because a machine can be fully
        hardened by this app and still be vulnerable here.
        """
        report = probe.vulnerability_report(self.window.facts)
        if not report:
            group = Adw.PreferencesGroup(title="CPU vulnerabilities")
            group.add(
                _row(
                    "This kernel reports nothing",
                    "/sys/devices/system/cpu/vulnerabilities does not exist, which "
                    "means the kernel was built without the reporting it needs.",
                )
            )
            return group

        counts: dict[str, int] = {}
        for _name, verdict, _raw in report:
            counts[verdict] = counts.get(verdict, 0) + 1
        vulnerable = counts.get("vulnerable", 0)

        group = Adw.PreferencesGroup(
            title="CPU vulnerabilities",
            description=(
                f"{len(report)} hardware bug(s) this kernel knows about: "
                f"{counts.get('mitigated', 0)} mitigated, "
                f"{counts.get('not-affected', 0)} this CPU is not affected by, "
                f"{vulnerable} still vulnerable. Read from "
                f"/sys/devices/system/cpu/vulnerabilities."
            ),
        )

        for name, verdict, raw in report:
            # "Not affected" is the boring majority; folding it keeps the panel
            # to what is actually actionable.
            if verdict == "not-affected":
                continue
            group.add(self._vulnerability_row(name, verdict, raw))

        unaffected = [n for n, v, _ in report if v == "not-affected"]
        if unaffected:
            expander = Adw.ExpanderRow(
                title=f"{len(unaffected)} this CPU is not affected by",
                subtitle="Mitigating these costs performance for no benefit here. "
                "Their flags are still selectable — the verdict can change with a "
                "microcode update, and a preset captured here may be applied on a "
                "machine that is affected.",
            )
            expander.set_subtitle_lines(2)
            for name in unaffected:
                expander.add_row(_row(name.replace("_", " "), "Not affected"))
            group.add(expander)
        return group

    def _vulnerability_row(self, name: str, verdict: str, raw: str) -> Adw.ActionRow:
        css, icon_name, label = self.VERDICT_STYLE.get(
            verdict, ("status-unknown", "dialog-question-symbolic", verdict)
        )
        row = _row(f"{name.replace('_', ' ')}  —  {label}", raw)

        icon = Gtk.Image.new_from_icon_name(icon_name)
        icon.add_css_class(css)
        row.add_prefix(icon)

        # Point at the flag that would mitigate this, when the catalogue has one
        # and it is not already in effect.
        flag_ids = [
            flag_id
            for flag_id, bug in probe.MITIGATION_FLAGS.items()
            if bug == name and flag_id in self.window.catalogue.flags
        ]
        actionable = [
            flag_id
            for flag_id in flag_ids
            if self.window.states.get(flag_id) is not None
            and self.window.states[flag_id].state is not State.APPLIED
        ]
        if verdict == "vulnerable" and actionable:
            button = Gtk.Button(label="Show the flag", valign=Gtk.Align.CENTER)
            button.connect("clicked", self._on_show_mitigation, actionable[0])
            row.add_suffix(button)
        return row

    def _on_show_mitigation(self, _button: Gtk.Button, flag_id: str) -> None:
        flag = self.window.catalogue.get(flag_id)
        if flag is None:
            return
        self.window.search_text = flag.key.lower()
        self.window._show_section(flag.section)

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
            filter_name = STATE_FILTER.get(state)
            if filter_name:
                row.set_subtitle("Click to see which")
                row.set_activatable(True)
                row.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
                row.connect("activated", self._on_state_row, filter_name)
            group.add(row)

        # Settings that are on but came from the user's own files: the app can
        # show them but not manage them until they are adopted. Capture is the
        # feature for exactly that, and the preset menu alone hides it too well.
        unmanaged = sum(
            1
            for flag_id, flag_state in self.window.states.items()
            if flag_state.state in (State.APPLIED, State.PENDING_REBOOT)
            and flag_id not in self.window.staging.baseline
        )
        if unmanaged:
            row = Adw.ActionRow(
                title=f"Let this app manage the {unmanaged} settings it did not write",
                subtitle=(
                    "They are in effect from this machine's own config files, so "
                    "their switches are on but locked. Capture stages them as this "
                    "app's own, reviewable before anything is written."
                ),
            )
            row.set_subtitle_lines(4)
            button = Gtk.Button(label="Capture…", valign=Gtk.Align.CENTER)
            button.add_css_class("suggested-action")
            button.connect("clicked", self._on_capture)
            row.add_suffix(button)
            group.add(row)
        return group

    def _on_capture(self, _button: Gtk.Button) -> None:
        application = self.window.get_application()
        if application is not None:
            application.activate_action("capture", None)

    def _on_state_row(self, _row: Adw.ActionRow, filter_name: str) -> None:
        self.window.show_filtered(filter_name)

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
        clobbered = probe.core_pattern_clobbered_by_apport(self.window.facts, selection)
        if clobbered:
            out.append(("high", "apport will overwrite core_pattern", clobbered))

        managed = [
            f.key for f in self.window.catalogue.flags.values() if f.section == "sysctl"
        ]
        shadowed = sysctl_chain.overridden_by_legacy(self.chain, managed)
        if shadowed:
            out.append((
                "high",
                f"/etc/sysctl.conf overrides {len(shadowed)} setting(s) this app manages",
                f"`sysctl --system` applies /etc/sysctl.conf after /etc/sysctl.d, so "
                f"anything set in both is written by this app and then undone: "
                + ", ".join(sorted(shadowed)[:8])
                + ". Moving those keys out of /etc/sysctl.conf and into "
                "/etc/sysctl.d lets them be managed here.",
            ))

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
            description="Click a section to open it. Each card's switch shows "
            "whether the setting is on right now, however it got that way.",
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
            row.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
            row.set_activatable(True)
            row.connect("activated", self._on_section_row, section.id)
            group.add(row)
        return group

    def _on_section_row(self, _row: Adw.ActionRow, section_id: str) -> None:
        self.window.show_section(section_id)
