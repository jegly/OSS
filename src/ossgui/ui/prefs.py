"""Appearance — theme family, accent, font, and glass mode.

Every control applies live: picking a palette re-renders the CSS providers
immediately, so the swatches are the preview.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from .. import settings as settings_module  # noqa: E402
from .. import theme as theme_module  # noqa: E402
from .style import mark_solid  # noqa: E402


class AppearanceDialog(Adw.PreferencesWindow):
    """Live theme picker."""

    __gtype_name__ = "OssAppearanceDialog"

    def __init__(self, window) -> None:
        super().__init__(transient_for=window, modal=True, title="Appearance")
        mark_solid(self)
        self.window = window
        self.settings = window.app_settings
        self._updating = False
        self.set_default_size(640, 720)

        self.add(self._theme_page())
        self.add(self._glass_page())

    # ------------------------------------------------------------------ #

    def _theme_page(self) -> Adw.PreferencesPage:
        page = Adw.PreferencesPage(title="Theme", icon_name="applications-graphics-symbolic")

        group = Adw.PreferencesGroup(
            title="Palette",
            description="114 combinations, ported from the Compose theme set: "
            "Catppuccin, Dracula, and 44 Ptyxis terminal palettes.",
        )

        self.families = theme_module.families()
        self.family_row = Adw.ComboRow(
            title="Family",
            model=Gtk.StringList.new([name for _, name in self.families]),
        )
        self.family_row.set_selected(
            next(
                (i for i, (key, _) in enumerate(self.families) if key == self.settings.family),
                0,
            )
        )
        self.family_row.connect("notify::selected", self._on_family)
        group.add(self.family_row)

        self.variant_row = Adw.ComboRow(title="Variant")
        self.variant_row.connect("notify::selected", self._on_variant)
        group.add(self.variant_row)

        self.accent_row = Adw.ComboRow(title="Accent")
        self.accent_row.connect("notify::selected", self._on_accent)
        group.add(self.accent_row)

        self.mono_row = Adw.SwitchRow(
            title="Monochrome accents",
            subtitle="Use the one accent everywhere instead of its hue-adjacent companions",
            active=self.settings.monochrome_accents,
        )
        self.mono_row.connect("notify::active", self._on_mono)
        group.add(self.mono_row)
        page.add(group)

        preview = Adw.PreferencesGroup(title="Preview")
        self.swatch_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.swatch_box.set_margin_top(4)
        self.swatch_box.set_margin_bottom(4)
        preview.add(self.swatch_box)
        page.add(preview)

        font_group = Adw.PreferencesGroup(
            title="Text",
            description="Fonts are independent of the theme — any face pairs with any palette.",
        )
        self.fonts = theme_module.available_fonts()
        self.font_row = Adw.ComboRow(
            title="Font",
            model=Gtk.StringList.new([name for _, name, _ in self.fonts]),
        )
        self.font_row.set_selected(
            next((i for i, (key, _, _) in enumerate(self.fonts) if key == self.settings.font), 0)
        )
        self.font_row.connect("notify::selected", self._on_font)
        font_group.add(self.font_row)

        self.scale_row = Adw.SpinRow.new_with_range(0.75, 1.75, 0.05)
        self.scale_row.set_title("Text size")
        self.scale_row.set_subtitle("Multiplies the system font scale")
        self.scale_row.set_value(self.settings.clamped_scale())
        self.scale_row.connect("notify::value", self._on_scale)
        font_group.add(self.scale_row)
        page.add(font_group)

        self._rebuild_variant_rows()
        return page

    def _glass_page(self) -> Adw.PreferencesPage:
        page = Adw.PreferencesPage(title="Glass", icon_name="weather-clear-symbolic")
        group = Adw.PreferencesGroup(
            title="Glass mode",
            description=(
                "Translucent surfaces with a luminous hairline on the header bar. "
                "GNOME does not blur behind application windows, so this is clean "
                "translucency rather than frost — keep the opacity at 0.5 or above "
                "so text stays readable. KDE/KWin does blur, and looks frosted."
            ),
        )

        self.glass_row = Adw.SwitchRow(title="Enable glass mode", active=self.settings.glass)
        self.glass_row.connect("notify::active", self._on_glass)
        group.add(self.glass_row)

        self.alpha_row = Adw.SpinRow.new_with_range(
            theme_module.GLASS_ALPHA_MIN, theme_module.GLASS_ALPHA_MAX, 0.02
        )
        self.alpha_row.set_title("Body opacity")
        self.alpha_row.set_subtitle(
            "Sidebars sit 0.20 clearer than this, the header bar 0.25 clearer"
        )
        self.alpha_row.set_value(self.settings.clamped_alpha())
        self.alpha_row.set_sensitive(self.settings.glass)
        self.alpha_row.connect("notify::value", self._on_alpha)
        group.add(self.alpha_row)
        page.add(group)
        return page

    # ------------------------------------------------------------------ #

    def _rebuild_variant_rows(self) -> None:
        """Repopulate variant/accent for the selected family."""
        self._updating = True
        try:
            family = self.settings.family
            if family == "catppuccin":
                self.variants = [(f["key"], f["name"]) for f in theme_module.catppuccin_flavors()]
                self.accents = [(a["key"], a["name"]) for a in theme_module.catppuccin_accents()]
                self.variant_row.set_title("Flavor")
                current_variant, current_accent = self.settings.flavor, self.settings.accent
            elif family == "dracula":
                self.variants = [(b["key"], b["name"]) for b in theme_module.dracula_bases()]
                self.accents = [(a["key"], a["name"]) for a in theme_module.dracula_accents()]
                self.variant_row.set_title("Base")
                current_variant, current_accent = self.settings.flavor, self.settings.accent
            else:
                palettes = theme_module.ptyxis_palettes()
                self.variants = [
                    (p["key"], f"{p['name']}{'' if p['set'] == 'curated' else '  ·  extended'}")
                    for p in palettes
                ]
                self.accents = []
                self.variant_row.set_title("Palette")
                current_variant, current_accent = self.settings.palette, ""

            self.variant_row.set_model(Gtk.StringList.new([n for _, n in self.variants]))
            self.variant_row.set_selected(
                next((i for i, (k, _) in enumerate(self.variants) if k == current_variant), 0)
            )

            self.accent_row.set_visible(bool(self.accents))
            self.mono_row.set_visible(bool(self.accents))
            if self.accents:
                self.accent_row.set_model(Gtk.StringList.new([n for _, n in self.accents]))
                self.accent_row.set_selected(
                    next((i for i, (k, _) in enumerate(self.accents) if k == current_accent), 0)
                )
        finally:
            self._updating = False
        self._apply()

    def _apply(self) -> None:
        scheme = self.window.style_manager.apply(self.settings)
        settings_module.save(self.settings)
        self._rebuild_swatches(scheme)

    def _rebuild_swatches(self, scheme: theme_module.Scheme) -> None:
        child = self.swatch_box.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self.swatch_box.remove(child)
            child = nxt

        for label, colour in (
            ("base", scheme.base),
            ("mantle", scheme.mantle),
            ("crust", scheme.crust),
            ("surface", scheme.surface),
            ("accent", scheme.primary),
            ("second", scheme.secondary),
            ("third", scheme.tertiary),
            ("error", scheme.error),
        ):
            swatch = Gtk.Box(width_request=54, height_request=34)
            swatch.add_css_class("swatch")
            provider = Gtk.CssProvider()
            provider.load_from_string(f"box {{ background-color: {colour}; }}")
            swatch.get_style_context().add_provider(
                provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION + 1
            )
            swatch.set_tooltip_text(f"{label}  {colour}")
            self.swatch_box.append(swatch)

    # -- handlers ------------------------------------------------------- #

    def _on_family(self, *_args) -> None:
        if self._updating:
            return
        self.settings.family = self.families[self.family_row.get_selected()][0]
        self._rebuild_variant_rows()

    def _on_variant(self, *_args) -> None:
        if self._updating:
            return
        index = self.variant_row.get_selected()
        if not (0 <= index < len(self.variants)):
            return
        key = self.variants[index][0]
        if self.settings.family == "ptyxis":
            self.settings.palette = key
        else:
            self.settings.flavor = key
        self._apply()

    def _on_accent(self, *_args) -> None:
        if self._updating or not self.accents:
            return
        index = self.accent_row.get_selected()
        if 0 <= index < len(self.accents):
            self.settings.accent = self.accents[index][0]
            self._apply()

    def _on_mono(self, *_args) -> None:
        if self._updating:
            return
        self.settings.monochrome_accents = self.mono_row.get_active()
        self._apply()

    def _on_font(self, *_args) -> None:
        if self._updating:
            return
        self.settings.font = self.fonts[self.font_row.get_selected()][0]
        self._apply()

    def _on_scale(self, *_args) -> None:
        if self._updating:
            return
        self.settings.font_scale = self.scale_row.get_value()
        self._apply()

    def _on_glass(self, *_args) -> None:
        if self._updating:
            return
        self.settings.glass = self.glass_row.get_active()
        self.alpha_row.set_sensitive(self.settings.glass)
        self._apply()

    def _on_alpha(self, *_args) -> None:
        if self._updating:
            return
        self.settings.glass_alpha = self.alpha_row.get_value()
        self._apply()
