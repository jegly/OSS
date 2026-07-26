"""Capture this system — the §5.2 dialog.

Reads the effective state, shows the findings before anything is saved, then
offers to stage it, save it as a preset, or write the report out.
"""

from __future__ import annotations

import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from .. import capture as capture_module, paths, presets as presets_module  # noqa: E402
from .style import mark_solid  # noqa: E402


class CaptureDialog(Adw.Window):
    """The capture result and what to do with it."""

    __gtype_name__ = "HardeningCaptureDialog"

    def __init__(self, window) -> None:
        super().__init__(
            transient_for=window, modal=True, title="Capture this system",
            default_width=820, default_height=640,
        )
        mark_solid(self)
        self.window = window
        self.result: capture_module.Capture | None = None

        self.status = Adw.StatusPage(
            title="Reading the system",
            description=(
                "Reading the effective configuration — the merged sysctl chain, the "
                "live kernel values, the boot command line, the module blacklists "
                "and the firewall. Nothing is written."
            ),
            icon_name="system-search-symbolic",
        )
        self.spinner = Gtk.Spinner(spinning=True, width_request=32, height_request=32)
        self.status.set_child(self.spinner)

        self.toolbar = Adw.ToolbarView(content=self.status)
        self.toolbar.add_top_bar(Adw.HeaderBar())
        self.set_content(self.toolbar)

        self.connect("map", lambda *_: self._start())

    def _start(self) -> None:
        def worker() -> None:
            result = capture_module.run(self.window.catalogue, self.window.facts)
            GLib.idle_add(self._finish, result)

        threading.Thread(target=worker, daemon=True).start()

    def _finish(self, result: capture_module.Capture) -> bool:
        self.result = result
        self.spinner.stop()
        self.toolbar.set_content(self._results_view(result))
        return False

    def _results_view(self, result: capture_module.Capture) -> Gtk.Widget:
        page = Adw.PreferencesPage()

        summary = Adw.PreferencesGroup(
            title="What was found",
            description=(
                "Read from the effective live state rather than copied from the "
                "config files, so settings that were written but have never done "
                "anything are not carried forward."
            ),
        )
        summary.add(self._row(f"{len(result.selection)} settings in effect", "Mapped onto catalogue flags."))
        if result.unknown_keys:
            summary.add(
                self._row(
                    f"{len(result.unknown_keys)} key(s) this app does not manage",
                    "Recorded in the preset as custom entries so carrying it "
                    "elsewhere does not silently drop them.",
                )
            )
        if result.unknown_modules:
            summary.add(
                self._row(
                    f"{len(result.unknown_modules)} blacklisted module(s) not in the catalogue",
                    ", ".join(result.unknown_modules[:10]),
                )
            )
        page.add(summary)

        for severity, title in (("high", "Worth acting on"), ("info", "For information")):
            matching = [f for f in result.findings if f.severity == severity]
            if not matching:
                continue
            group = Adw.PreferencesGroup(title=f"{title} — {len(matching)}")
            for finding in matching:
                row = self._row(finding.title, finding.detail)
                icon = Gtk.Image.new_from_icon_name(
                    "dialog-warning-symbolic" if severity == "high"
                    else "dialog-information-symbolic"
                )
                if severity == "high":
                    icon.add_css_class("status-pending-reboot")
                row.add_prefix(icon)
                group.add(row)
            page.add(group)

        scroller = Gtk.ScrolledWindow(child=page, vexpand=True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        toolbar = Adw.ToolbarView(content=scroller)
        toolbar.add_top_bar(Adw.HeaderBar())
        toolbar.add_bottom_bar(self._footer())
        return toolbar

    def _footer(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        for margin in ("start", "end", "top", "bottom"):
            getattr(box, f"set_margin_{margin}")(10 if margin in ("start", "end") else 8)

        hint = Gtk.Label(
            label="Capturing writes nothing. Staging only pre-fills the grid.",
            xalign=0, hexpand=True, wrap=True,
        )
        hint.add_css_class("lock-hint")
        box.append(hint)

        for label, handler, css in (
            ("Save report…", self._on_save_report, None),
            ("Save as preset…", self._on_save_preset, None),
            ("Stage it", self._on_stage, "suggested-action"),
        ):
            button = Gtk.Button(label=label)
            if css:
                button.add_css_class(css)
            button.connect("clicked", handler)
            box.append(button)
        return box

    # -- actions --------------------------------------------------------- #

    def _on_stage(self, _button: Gtk.Button) -> None:
        if self.result is None:
            return
        selection: dict[str, str | None] = {
            flag_id: None for flag_id in self.window.catalogue.flags
        }
        selection.update(self.result.selection)
        self.window.staging.set_many(selection, preset_name="Captured")
        self.window._show_section(self.window.current_section)
        self.window.toast(
            f"Staged {len(self.result.selection)} captured setting(s). "
            "The counter shows what differs from the machine as it is now."
        )
        self.close()

    def _on_save_preset(self, _button: Gtk.Button) -> None:
        if self.result is None:
            return
        directory = paths.user_presets_dir()
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "captured.toml"
        try:
            path.write_text(capture_module.to_toml(self.result), encoding="utf-8")
        except OSError as exc:
            self.window.toast(f"Could not save: {exc}")
            return
        self.window.preset_button.set_menu_model(self.window._preset_menu())
        self.window.toast(f"Saved to {path}")

    def _on_save_report(self, _button: Gtk.Button) -> None:
        if self.result is None:
            return
        path = paths.user_config_dir() / "capture-findings.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.write_text(capture_module.findings_report(self.result), encoding="utf-8")
        except OSError as exc:
            self.window.toast(f"Could not save: {exc}")
            return
        self.window.toast(f"Report written to {path}")

    @staticmethod
    def _row(title: str, subtitle: str) -> Adw.ActionRow:
        row = Adw.ActionRow(title=GLib.markup_escape_text(title))
        if subtitle:
            row.set_subtitle(GLib.markup_escape_text(subtitle))
        row.set_title_lines(2)
        row.set_subtitle_lines(6)
        return row
