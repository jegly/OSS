"""Integrity page — package verification and the baseline lifecycle (§4.24).

Tier 1 needs no setup: it asks dpkg whether every packaged file still matches
what it shipped. Tier 2 is a baseline you capture while the machine is trusted
and compare against later.

Both run in the helper, because a plain-user scan silently skips every path it
cannot read, and a partial integrity check is worse than none — it reports
"clean" for the parts an attacker would actually touch.
"""

from __future__ import annotations

import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from .. import integrity as integrity_module, privileged  # noqa: E402

SEVERITY_ICON = {
    "critical": "dialog-error-symbolic",
    "high": "dialog-warning-symbolic",
    "info": "dialog-information-symbolic",
}
SEVERITY_CSS = {
    "critical": "status-differs",
    "high": "status-pending-reboot",
    "info": "status-not-set",
}

SHOW_LIMIT = 40


class IntegrityPage(Gtk.Box):
    """Tier 1 verification, Tier 2 baseline, and the findings list."""

    __gtype_name__ = "OssIntegrityPage"

    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.window = window
        self.busy = False
        self.append(self._build())

    @property
    def result(self) -> dict:
        return self.window.integrity_result

    def _rebuild(self) -> None:
        self.window._show_section(self.window.current_section)

    def _build(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_margin_bottom(14)
        box.append(self._tier1_group())
        box.append(self._tier2_group())
        if self.result.get("findings"):
            box.append(self._findings_group())
        return box

    # -- tier 1 ---------------------------------------------------------- #

    def _tier1_group(self) -> Adw.PreferencesGroup:
        group = Adw.PreferencesGroup(
            title="Tier 1 — package verification",
            description=(
                "Checks every file that came from a .deb against the distro's own "
                "checksums. Instant and needs no setup, but only covers packaged "
                "files — it is blind to anything added that no package owns."
            ),
        )

        row = Adw.ActionRow(
            title="Verify packaged files",
            subtitle=(
                "Runs dpkg -V as root. A plain-user run cannot read every path and "
                "quietly skips what it cannot see."
            ),
        )
        row.set_subtitle_lines(2)
        button = Gtk.Button(label="Run check", valign=Gtk.Align.CENTER)
        button.add_css_class("suggested-action")
        button.set_sensitive(not self.busy)
        button.connect("clicked", self._on_verify)
        row.add_suffix(button)
        group.add(row)

        if self.result.get("action") == "verify":
            explained = sum(1 for f in self.result["findings"] if f.get("explained_by"))
            total = len(self.result["findings"])
            group.add(
                Adw.ActionRow(
                    title=f"{total - explained} finding(s) with no package event behind them",
                    subtitle=(
                        f"{explained} of {total} were explained by an apt upgrade and "
                        f"dropped from the list. What is left is the part worth reading."
                    ),
                )
            )
        return group

    # -- tier 2 ---------------------------------------------------------- #

    def _tier2_group(self) -> Adw.PreferencesGroup:
        entries, created = integrity_module.load_baseline()
        group = Adw.PreferencesGroup(
            title="Tier 2 — full baseline",
            description=(
                "Hashes /etc, /boot and the binary directories now, so a later scan "
                "can show exactly what changed — including files no package owns, "
                "which is where persistence actually lives."
            ),
        )

        if entries:
            row = Adw.ActionRow(
                title=f"Baseline of {len(entries)} file(s)",
                subtitle=f"captured {created or 'at an unknown time'}",
            )
        else:
            row = Adw.ActionRow(
                title="No baseline yet",
                subtitle=(
                    "Capture one while you still trust this machine. A baseline "
                    "taken after a compromise records the compromise as normal."
                ),
            )
        row.set_subtitle_lines(3)

        capture = Gtk.Button(label="Capture baseline", valign=Gtk.Align.CENTER)
        capture.set_sensitive(not self.busy)
        capture.connect("clicked", self._on_baseline)
        row.add_suffix(capture)

        if entries:
            check = Gtk.Button(label="Check against it", valign=Gtk.Align.CENTER)
            check.add_css_class("suggested-action")
            check.set_sensitive(not self.busy)
            check.connect("clicked", self._on_check)
            row.add_suffix(check)
        group.add(row)

        if self.result.get("action") == "baseline":
            group.add(
                Adw.ActionRow(
                    title="Baseline stored",
                    subtitle=(
                        f"{self.result.get('count', 0)} files. Its own SHA-256 is "
                        f"{self.result.get('sha256', '')[:32]}… — write that down "
                        f"somewhere off this machine and check it before you trust "
                        f"a future scan."
                    ),
                )
            )

        warning = Adw.ActionRow(
            title="What a baseline on the same disk is worth",
            subtitle=(
                "It catches opportunistic malware and accidents. It does not catch "
                "someone who already has root, because they can rewrite the baseline "
                "along with the files. Storing it on read-only or offline media, and "
                "recording its hash elsewhere, is what closes that gap."
            ),
        )
        warning.set_subtitle_lines(4)
        warning.add_prefix(Gtk.Image.new_from_icon_name("dialog-information-symbolic"))
        group.add(warning)

        if not integrity_module.aide_available():
            group.add(
                Adw.ActionRow(
                    title="AIDE is not installed",
                    subtitle=(
                        "The built-in baseline above needs nothing extra. Installing "
                        "aide would add its rule language and its own database format, "
                        "which this does not depend on."
                    ),
                )
            )
        return group

    # -- findings -------------------------------------------------------- #

    def _findings_group(self) -> Adw.PreferencesGroup:
        findings = [f for f in self.result.get("findings", []) if not f.get("explained_by")]
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1

        summary = " · ".join(
            f"{counts[s]} {s}" for s in ("critical", "high", "info") if counts.get(s)
        )
        group = Adw.PreferencesGroup(
            title="Findings",
            description=summary or "Nothing worth reporting.",
        )

        order = {"critical": 0, "high": 1, "info": 2}
        findings.sort(key=lambda f: (order.get(f["severity"], 3), f["path"]))

        for finding in findings[:SHOW_LIMIT]:
            row = Adw.ActionRow(title=GLib.markup_escape_text(finding["path"]))
            subtitle = finding.get("reason", "")
            if finding.get("package"):
                subtitle = f"{finding['package']} — {subtitle}"
            row.set_subtitle(GLib.markup_escape_text(subtitle))
            row.set_title_lines(2)
            row.set_subtitle_lines(3)
            icon = Gtk.Image.new_from_icon_name(
                SEVERITY_ICON.get(finding["severity"], "dialog-information-symbolic")
            )
            icon.add_css_class(SEVERITY_CSS.get(finding["severity"], ""))
            row.add_prefix(icon)
            group.add(row)

        if len(findings) > SHOW_LIMIT:
            group.add(
                Adw.ActionRow(
                    title=f"{len(findings) - SHOW_LIMIT} more not shown",
                    subtitle="The most severe are listed first.",
                )
            )
        return group

    # -- handlers -------------------------------------------------------- #

    def _run(self, call, label: str) -> None:
        self.busy = True
        self.window.toast(f"{label} — this runs as root and can take a few minutes.")
        self._rebuild()

        def worker() -> None:
            outcome = call()
            GLib.idle_add(self._done, outcome, label)

        threading.Thread(target=worker, daemon=True).start()

    def _done(self, outcome: privileged.ApplyOutcome, label: str) -> bool:
        self.busy = False
        if not outcome.ok:
            self.window.toast(outcome.error or f"{label} failed.")
        else:
            self.window.integrity_result = outcome.integrity
            count = len(outcome.integrity.get("findings", []))
            if outcome.integrity.get("action") == "baseline":
                self.window.toast(f"Baseline captured: {outcome.integrity.get('count', 0)} files.")
            else:
                self.window.toast(f"{label} finished — {count} finding(s).")
        self._rebuild()
        return False

    def _on_verify(self, _button: Gtk.Button) -> None:
        self._run(privileged.integrity_verify, "Package verification")

    def _on_baseline(self, _button: Gtk.Button) -> None:
        self._run(privileged.integrity_baseline, "Baseline capture")

    def _on_check(self, _button: Gtk.Button) -> None:
        self._run(privileged.integrity_check, "Baseline check")
