#!/usr/bin/python3
"""Render the app's own window to a PNG, for checking the design against the mockup.

The compositor's screenshot API is not available to unsandboxed callers, so this
asks GTK to render the widget tree into a texture instead — which also means it
captures exactly what the app drew, with no window decorations in the way.

    python3 tools/screenshot.py out.png [--theme ptyxis:ptyxis_nord] [--glass]
                                        [--section sysctl] [--dialog review]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import gi  # noqa: E402

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from ossgui import catalogue as catalogue_module  # noqa: E402
from ossgui import probe, theme  # noqa: E402
from ossgui.staging import Staging  # noqa: E402
from ossgui.ui.style import StyleManager  # noqa: E402
from ossgui.ui.window import MainWindow  # noqa: E402


def capture(widget: Gtk.Widget, path: Path) -> bool:
    """Snapshot a realized widget into a PNG."""
    width = widget.get_allocated_width()
    height = widget.get_allocated_height()
    if width <= 1 or height <= 1:
        print(f"widget not laid out yet ({width}x{height})", file=sys.stderr)
        return False

    paintable = Gtk.WidgetPaintable.new(widget)
    snapshot = Gtk.Snapshot()
    paintable.snapshot(snapshot, width, height)
    node = snapshot.to_node()
    if node is None:
        print("nothing was drawn", file=sys.stderr)
        return False

    native = widget.get_native()
    renderer = native.get_renderer() if native is not None else None
    if renderer is None:
        print("no renderer on this window", file=sys.stderr)
        return False

    texture = renderer.render_texture(node, None)
    texture.save_to_png(str(path))
    print(f"wrote {path} ({width}x{height})")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output")
    parser.add_argument("--theme", default="catppuccin:mocha:mauve",
                        help="family:variant[:accent]")
    parser.add_argument("--glass", action="store_true")
    parser.add_argument("--alpha", type=float, default=theme.GLASS_ALPHA_DEFAULT)
    parser.add_argument("--section", default="")
    parser.add_argument("--preset", default="")
    parser.add_argument("--dialog", default="", choices=["", "review", "appearance"])
    parser.add_argument("--font", default="system")
    parser.add_argument("--delay", type=int, default=900)
    args = parser.parse_args()

    parts = args.theme.split(":")
    settings = theme.Settings(
        family=parts[0],
        flavor=parts[1] if len(parts) > 1 else "mocha",
        accent=parts[2] if len(parts) > 2 else "mauve",
        palette=parts[1] if parts[0] == "ptyxis" and len(parts) > 1 else "ptyxis_nord",
        glass=args.glass,
        glass_alpha=args.alpha,
        font=args.font,
    )

    application = Adw.Application(application_id="io.github.jegly.OSS.Screenshot")
    status = {"ok": False}

    def on_activate(app: Adw.Application) -> None:
        style = StyleManager()
        style.apply(settings)

        loaded = catalogue_module.load()
        facts = probe.gather(loaded)
        staging = Staging.from_system(loaded, facts)

        window = MainWindow(app, loaded, facts, staging, style, settings)

        if args.preset:
            from ossgui import presets

            preset = presets.get(args.preset)
            if preset is not None:
                staging.set_many(
                    presets.selection_for(loaded, preset), preset_name=preset.name
                )
        if args.section:
            window._show_section(args.section)

        window.present()

        target: Gtk.Widget = window

        def shoot() -> bool:
            nonlocal target
            if args.dialog == "review":
                from ossgui.ui.review import ReviewDialog

                dialog = ReviewDialog(window, apply_callback=lambda: None)
                dialog.present()
                target = dialog
                GLib.timeout_add(args.delay, finish)
                return False
            if args.dialog == "appearance":
                from ossgui.ui.prefs import AppearanceDialog

                dialog = AppearanceDialog(window)
                dialog.present()
                target = dialog
                GLib.timeout_add(args.delay, finish)
                return False
            return finish()

        def finish() -> bool:
            status["ok"] = capture(target, Path(args.output))
            app.quit()
            return False

        GLib.timeout_add(args.delay, shoot)

    application.connect("activate", on_activate)
    application.run([])
    return 0 if status["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
