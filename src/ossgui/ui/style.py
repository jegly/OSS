"""CSS provider plumbing — applies a theme, and toggles glass mode live.

Two providers are kept for the lifetime of the process: the theme, loaded at
``PRIORITY_APPLICATION`` so widgets can still override it, and glass, loaded at
``PRIORITY_USER + 1000`` so it beats both the theme and any user CSS. Toggling
glass off just loads an empty string into the second provider, which is why the
switch is instant.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")

from gi.repository import Gdk, Gtk  # noqa: E402

from .. import theme as theme_module  # noqa: E402

#: Beats the theme and any other USER-priority css, per GLASS_MODE_INTEGRATION.md.
GLASS_PRIORITY = Gtk.STYLE_PROVIDER_PRIORITY_USER + 1000


class StyleManager:
    """Owns the app's CSS providers and re-renders them when settings change."""

    def __init__(self) -> None:
        self._theme_provider = Gtk.CssProvider()
        self._glass_provider = Gtk.CssProvider()
        self._attached = False

    def attach(self, display: Gdk.Display | None = None) -> None:
        display = display or Gdk.Display.get_default()
        if display is None or self._attached:
            return
        Gtk.StyleContext.add_provider_for_display(
            display, self._theme_provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )
        Gtk.StyleContext.add_provider_for_display(
            display, self._glass_provider, GLASS_PRIORITY
        )
        self._attached = True

    def apply(self, settings: theme_module.Settings) -> theme_module.Scheme:
        """Render *settings* into both providers. Returns the resolved scheme."""
        self.attach()
        scheme = theme_module.resolve(settings)
        self._theme_provider.load_from_string(
            theme_module.base_css(scheme, settings)
        )
        self._glass_provider.load_from_string(
            theme_module.glass_css(scheme, settings) if settings.glass else ""
        )
        return scheme


def mark_solid(window: Gtk.Window) -> None:
    """Force a secondary window opaque.

    Translucency applies to every toplevel, so without this a dialog shows the
    main window bleeding through it ("ghosting").
    """
    window.add_css_class("solid")
