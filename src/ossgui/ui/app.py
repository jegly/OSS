"""The Adw.Application: load the catalogue, probe the system, show the window."""

from __future__ import annotations

import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from .. import __version__, catalogue as catalogue_module  # noqa: E402
from .. import paths, presets as presets_module, probe  # noqa: E402
from .. import settings as settings_module  # noqa: E402
from ..staging import Staging  # noqa: E402
from .style import StyleManager, mark_solid  # noqa: E402
from .window import MainWindow  # noqa: E402


class OssApplication(Adw.Application):
    """One window, one catalogue, one probe of the system at startup."""

    def __init__(self) -> None:
        super().__init__(
            application_id=paths.APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS
        )
        self.style_manager = StyleManager()
        self.app_settings = settings_module.load()
        self.catalogue = None
        self.window: MainWindow | None = None

        self._add_actions()

    def _add_actions(self) -> None:
        for name, handler in (
            ("about", self._on_about),
            ("appearance", self._on_appearance),
            ("capture", self._on_capture),
            ("backup", self._on_backup),
            ("save-preset", self._on_save_preset),
            ("clear-preset", self._on_clear_preset),
        ):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", handler)
            self.add_action(action)

        preset_action = Gio.SimpleAction.new("preset", GLib.VariantType.new("s"))
        preset_action.connect("activate", self._on_preset)
        self.add_action(preset_action)

    # ------------------------------------------------------------------ #

    def do_activate(self) -> None:  # noqa: N802 (GObject naming)
        if self.window is not None:
            self.window.present()
            return

        self.style_manager.apply(self.app_settings)

        try:
            self.catalogue = catalogue_module.load()
        except catalogue_module.CatalogueError as exc:
            self._fatal(
                "The flag catalogue could not be loaded",
                f"{exc}\n\nThis is a packaging problem, not something you did. "
                f"Looked in: {paths.catalogue_dir()}",
            )
            return

        facts = probe.gather(self.catalogue)
        staging = Staging.from_system(self.catalogue, facts)

        self.window = MainWindow(
            application=self,
            catalogue=self.catalogue,
            facts=facts,
            staging=staging,
            style_manager=self.style_manager,
            app_settings=self.app_settings,
        )
        self.window.present()

    def _fatal(self, title: str, detail: str) -> None:
        window = Adw.ApplicationWindow(application=self, title="Hardening settings")
        mark_solid(window)
        window.set_default_size(560, 340)
        status = Adw.StatusPage(
            title=title, description=detail, icon_name="dialog-error-symbolic"
        )
        toolbar = Adw.ToolbarView(content=status)
        toolbar.add_top_bar(Adw.HeaderBar())
        window.set_content(toolbar)
        window.present()

    # ------------------------------------------------------------------ #

    def _on_about(self, *_args) -> None:
        about = Adw.AboutWindow(
            transient_for=self.window,
            application_name="OSS",
            application_icon=paths.APP_ID,
            version=__version__,
            developer_name="jegly",
            # Written without a scheme, and deliberately not passed as the
            # `website` or `issue_url` properties. Those make Adw.AboutWindow
            # render a clickable link that hands a URI to the browser, and this
            # app has no network capability of any kind — the packaging gate
            # greps the whole source for URL schemes and fails on a match, which
            # is exactly the promise it should be enforcing. These are here to
            # be read and typed, not clicked.
            comments=(
                "Pick hardening flags, review the exact diff, apply once.\n\n"
                "Most sections are one drop-in file — deleting it reverts that "
                "section to stock. A few edit a file the distribution owns "
                "(/etc/default/grub, /etc/login.defs); those keep a .bak beside "
                "the original instead.\n\n"
                "jegly.xyz  ·  github.com/jegly"
            ),
            # Apache-2.0, matching the LICENSE file. This said GPL_3_0, which is
            # a different licence with different obligations for anyone
            # redistributing the app.
            license_type=Gtk.License.APACHE_2_0,
        )
        mark_solid(about)
        about.present()

    def _on_appearance(self, *_args) -> None:
        if self.window is None:
            return
        from .prefs import AppearanceDialog

        AppearanceDialog(self.window).present()

    def _on_preset(self, _action, parameter: GLib.Variant) -> None:
        if self.window is None or self.catalogue is None:
            return
        key = parameter.get_string()
        preset = presets_module.get(key)
        if preset is None:
            self.window.toast(f"Preset {key!r} is no longer there.")
            return
        try:
            values = presets_module.selection_for(self.catalogue, preset)
        except presets_module.PresetError as exc:
            self.window.toast(str(exc))
            return
        self.window.staging.set_many(values, preset_name=preset.name)
        self.window._show_section(self.window.current_section)
        staged = self.window.staging.changed_count
        self.window.toast(
            f"Loaded {preset.name} — {staged} change(s) staged. Nothing is written until you Apply."
        )

    def _on_capture(self, *_args) -> None:
        if self.window is None or self.catalogue is None:
            return
        from .capture_dialog import CaptureDialog

        CaptureDialog(self.window).present()

    def _on_backup(self, *_args) -> None:
        from .backup_dialog import BackupDialog

        BackupDialog(self.window).present()

    def _on_clear_preset(self, *_args) -> None:
        """Unload the preset and drop every staged change.

        Nothing has been written at this point — staging is deliberately
        separate from the system — so this needs no confirmation and cannot
        lose anything that was applied.
        """
        staged = self.window.staging.changed_count()
        self.window._on_discard(None)
        self.window.toast(
            f"Cleared {staged} staged change(s). Nothing was written."
            if staged else "No preset. Nothing was staged."
        )

    def _on_save_preset(self, *_args) -> None:
        if self.window is None or self.catalogue is None:
            return

        dialog = Adw.MessageDialog(
            transient_for=self.window,
            heading="Save selection as preset",
            body="It lands in ~/.config/oss/presets/ and can be copied "
            "to another machine as-is.",
        )
        entry = Gtk.Entry(placeholder_text="my-laptop")
        dialog.set_extra_child(entry)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("save", "Save")
        dialog.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("save")

        def on_response(_dialog, response: str) -> None:
            if response != "save":
                return
            name = entry.get_text().strip()
            if not name:
                self.window.toast("A preset needs a name.")
                return
            try:
                path = presets_module.save_user_preset(
                    self.catalogue, name, dict(self.window.staging.selection)
                )
            except (presets_module.PresetError, OSError) as exc:
                self.window.toast(f"Could not save: {exc}")
                return
            self.window.staging.preset_name = name
            self.window.preset_button.set_menu_model(self.window._preset_menu())
            self.window.toast(f"Saved to {path}")

        dialog.connect("response", on_response)
        dialog.present()


def main(argv: list[str] | None = None) -> int:
    return OssApplication().run(argv if argv is not None else sys.argv)
