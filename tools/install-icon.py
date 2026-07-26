#!/usr/bin/python3
"""Turn a source image into the icon set the desktop expects.

    python3 tools/install-icon.py path/to/icon.png
    python3 tools/install-icon.py path/to/icon.svg

Freedesktop wants the icon named after the app id and installed per size under
hicolor. A single PNG dropped in one place works badly: the shell picks the
wrong size and scales it, so a 512px source looks soft in a 24px header bar.

Uses GdkPixbuf, which is already a dependency for the GUI, rather than pulling in
ImageMagick just to resize a square.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

import gi

gi.require_version("GdkPixbuf", "2.0")

from gi.repository import GdkPixbuf  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
APP_ID = "com.jegly.OSS"

#: The sizes a GNOME desktop actually asks for.
SIZES = (16, 24, 32, 48, 64, 128, 256, 512)

ICON_ROOT = ROOT / "data" / "icons" / "hicolor"


def load(source: Path, size: int) -> GdkPixbuf.Pixbuf:
    """Load *source* rendered at *size*, letting SVG rasterise at full quality."""
    if source.suffix.lower() == ".svg":
        # Rendering the vector at each size beats scaling one raster copy.
        return GdkPixbuf.Pixbuf.new_from_file_at_scale(str(source), size, size, True)
    pixbuf = GdkPixbuf.Pixbuf.new_from_file(str(source))
    if pixbuf.get_width() == size and pixbuf.get_height() == size:
        return pixbuf
    return pixbuf.scale_simple(size, size, GdkPixbuf.InterpType.HYPER)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="PNG, SVG or any format GdkPixbuf reads")
    parser.add_argument(
        "--keep-scalable",
        action="store_true",
        default=True,
        help="also install the SVG source as scalable/ (default when given an SVG)",
    )
    parser.add_argument(
        "--no-upscale",
        action="store_true",
        help="skip sizes larger than the source instead of upscaling to them",
    )
    args = parser.parse_args()

    source = Path(args.source).expanduser()
    if not source.is_file():
        print(f"no such file: {source}", file=sys.stderr)
        return 1

    try:
        probe = GdkPixbuf.Pixbuf.new_from_file(str(source))
    except Exception as exc:  # GdkPixbuf raises GLib.Error
        print(f"cannot read {source}: {exc}", file=sys.stderr)
        return 1

    width, height = probe.get_width(), probe.get_height()
    print(f"source: {source.name}  {width}x{height}")
    if width != height:
        print(
            f"  note: not square ({width}x{height}). It will be squashed to fit — "
            f"crop it first if that matters.",
            file=sys.stderr,
        )
    if source.suffix.lower() != ".svg" and min(width, height) < max(SIZES):
        print(
            f"  note: {min(width, height)}px source, so sizes above that are "
            f"upscaled. They are still generated: without a 512 the shell upscales "
            f"the 256 itself for HiDPI, with a cheaper filter than this uses. An "
            f"SVG or a larger source would beat both.",
            file=sys.stderr,
        )

    written = []
    for size in SIZES:
        if args.no_upscale and source.suffix.lower() != ".svg" and size > max(width, height):
            continue
        directory = ICON_ROOT / f"{size}x{size}" / "apps"
        directory.mkdir(parents=True, exist_ok=True)
        destination = directory / f"{APP_ID}.png"
        load(source, size).savev(str(destination), "png", [], [])
        written.append(f"{size}x{size}")

    if source.suffix.lower() == ".svg" and args.keep_scalable:
        directory = ICON_ROOT / "scalable" / "apps"
        directory.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, directory / f"{APP_ID}.svg")
        written.append("scalable")

    print(f"wrote: {', '.join(written)}  as {APP_ID}")
    print(f"into:  {ICON_ROOT.relative_to(ROOT)}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
