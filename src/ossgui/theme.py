"""Themes and glass mode — palette data in, GTK4 CSS out.

Ported from the Compose theme system in "theme port for android apps": the 44
Ptyxis terminal palettes, Catppuccin's 4 flavors x 14 accents, and Dracula's
dark/light bases x 7 accents. Colour data lives in ``data/themes/*.toml``; this
module resolves a settings choice into a concrete scheme and emits the CSS.

Glass mode follows GLASS_MODE_INTEGRATION.md Part A: paint every surface with an
rgba background whose alpha < 1, then put a 1px luminous hairline and an inner
top glow on the edge surfaces. GTK4 needs no special window setup for this — the
CSS just has to load at ``STYLE_PROVIDER_PRIORITY_USER + 1000`` so it outranks
the theme's opaque blocks.

Stdlib only — no gi. The UI layer feeds the output to a ``Gtk.CssProvider``.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from . import paths

#: Default body opacity for glass mode. The guide's suggested starting point;
#: below ~0.5 text stops being readable on GNOME, which does not blur behind
#: app windows (KDE/KWin does).
GLASS_ALPHA_DEFAULT = 0.78
GLASS_ALPHA_MIN = 0.50
GLASS_ALPHA_MAX = 1.0

#: Alpha offsets per surface layer, from the guide.
GLASS_SIDE_OFFSET = 0.20  # sidebars and content panes read clearer than the body
GLASS_HEAD_OFFSET = 0.25  # headerbar is the clearest "glass edge"
GLASS_POPOVER_OFFSET = -0.10  # popovers are *more* opaque, so text stays readable

#: WCAG AA for body text. Several terminal palettes were authored for a terminal,
#: not a UI, so secondary text needs nudging to stay legible.
MIN_CONTRAST = 4.5
MIN_CONTRAST_DIM = 3.0

#: Font families bundled with the app. Any of them pairs with any theme — the
#: Compose original treats font and theme as independent.
#:
#: The oss-fonts package ships 13 families; 12 are listed here. Noto Sans
#: Egyptian Hieroglyphs is deliberately left out: it has no Latin coverage, so
#: selecting it would render every label in the app — including the picker needed
#: to change it back — as empty boxes, with no way out from inside the UI. The
#: font is still installed and usable by anything else on the system.
BUNDLED_FONTS = [
    ("system", "System default", ""),
    ("nunito", "Nunito", "Nunito"),
    ("space_grotesk", "Space Grotesk", "Space Grotesk"),
    ("quicksand", "Quicksand", "Quicksand"),
    ("ibm_plex_mono", "IBM Plex Mono", "IBM Plex Mono"),
    ("ibm_plex_serif", "IBM Plex Serif", "IBM Plex Serif"),
    ("playfair_display", "Playfair Display", "Playfair Display"),
    ("cormorant_garamond", "Cormorant Garamond", "Cormorant Garamond"),
    ("instrument_serif", "Instrument Serif", "Instrument Serif"),
    ("viaoda_libre", "Viaoda Libre", "Viaoda Libre"),
    ("turret_road", "Turret Road", "Turret Road"),
    ("dotgothic16", "DotGothic16", "DotGothic16"),
    ("press_start_2p", "Press Start 2P", "Press Start 2P"),
]

#: The monospace face used for the key line on every card.
MONO_FAMILY = "IBM Plex Mono, ui-monospace, monospace"


class ThemeError(Exception):
    """Malformed or missing theme data."""


# --------------------------------------------------------------------------- #
#  Colour maths
# --------------------------------------------------------------------------- #

RGB = tuple[int, int, int]


def parse_hex(value: str) -> RGB:
    text = value.strip().lstrip("#")
    if len(text) == 3:
        text = "".join(char * 2 for char in text)
    if len(text) != 6:
        raise ThemeError(f"not a hex colour: {value!r}")
    try:
        return int(text[0:2], 16), int(text[2:4], 16), int(text[4:6], 16)
    except ValueError as exc:
        raise ThemeError(f"not a hex colour: {value!r}") from exc


def to_hex(rgb: RGB) -> str:
    return "#{:02x}{:02x}{:02x}".format(*(max(0, min(255, int(round(c)))) for c in rgb))


def rgba(colour: str | RGB, alpha: float) -> str:
    """CSS ``rgba()`` — the whole trick behind glass mode."""
    red, green, blue = parse_hex(colour) if isinstance(colour, str) else colour
    return f"rgba({red}, {green}, {blue}, {alpha:.3f})"


def mix(first: str, second: str, amount: float) -> str:
    """Blend *first* toward *second* by *amount* (Compose's ``lerp``)."""
    one, two = parse_hex(first), parse_hex(second)
    return to_hex(tuple(a + (b - a) * amount for a, b in zip(one, two)))


def _channel_luminance(channel: int) -> float:
    ratio = channel / 255
    return ratio / 12.92 if ratio <= 0.03928 else ((ratio + 0.055) / 1.055) ** 2.4


def luminance(colour: str) -> float:
    red, green, blue = parse_hex(colour)
    return (
        0.2126 * _channel_luminance(red)
        + 0.7152 * _channel_luminance(green)
        + 0.0722 * _channel_luminance(blue)
    )


def contrast(first: str, second: str) -> float:
    one, two = luminance(first), luminance(second)
    lighter, darker = max(one, two), min(one, two)
    return (lighter + 0.05) / (darker + 0.05)


def on_colour(background: str) -> str:
    """Readable foreground for a filled surface — Compose's ``onColor``."""
    return "#ffffff" if luminance(background) < 0.5 else "#0a0a0a"


def ensure_contrast(foreground: str, background: str, target: float = MIN_CONTRAST) -> str:
    """Push *foreground* away from *background* until it is readable.

    Several of these palettes were designed for terminal text on its own
    background, not for UI chrome — C64's foreground on its own background is
    barely over 1.5:1. Rather than drop those palettes or silently ship
    unreadable text, the offending colour is walked toward white or black until
    it clears the threshold.
    """
    if contrast(foreground, background) >= target:
        return foreground
    destination = "#ffffff" if luminance(background) < 0.5 else "#000000"
    candidate = foreground
    for step in range(1, 21):
        candidate = mix(foreground, destination, step / 20)
        if contrast(candidate, background) >= target:
            return candidate
    return destination


# --------------------------------------------------------------------------- #
#  The resolved scheme
# --------------------------------------------------------------------------- #


@dataclass
class Scheme:
    """A concrete set of colours, whichever family it came from."""

    key: str
    name: str
    dark: bool
    #: The four surface layers glass mode needs, darkest last.
    base: str  # window background
    mantle: str  # sidebars
    crust: str  # headerbar — the glass edge
    surface: str  # cards and popovers
    text: str
    subtext: str
    overlay: str
    primary: str
    secondary: str
    tertiary: str
    error: str
    #: Semantic colours for the status dots (§6). These must not follow the
    #: accent: "applied" has to read as green whatever accent you picked, or the
    #: dot stops carrying information. Taken from the palette's own green/yellow/
    #: red so it still belongs to the theme.
    success: str = "#4caf50"
    warning: str = "#e8b055"
    danger: str = "#e06c6c"
    #: Full 16-slot ANSI table, when the source palette had one.
    ansi: list[str] = field(default_factory=list)

    @property
    def on_primary(self) -> str:
        return on_colour(self.primary)

    @property
    def border(self) -> str:
        return mix(self.base, self.text, 0.20)

    @property
    def border_strong(self) -> str:
        return mix(self.base, self.text, 0.40)


@dataclass
class Settings:
    """What the user picked in the appearance panel."""

    family: str = "catppuccin"  # catppuccin | dracula | ptyxis
    flavor: str = "mocha"  # catppuccin flavor / dracula base
    accent: str = "mauve"  # catppuccin or dracula accent
    palette: str = "ptyxis_nord"  # ptyxis palette key
    monochrome_accents: bool = False
    glass: bool = False
    glass_alpha: float = GLASS_ALPHA_DEFAULT
    font: str = "system"
    font_scale: float = 1.0

    def clamped_alpha(self) -> float:
        return max(GLASS_ALPHA_MIN, min(GLASS_ALPHA_MAX, self.glass_alpha))

    def clamped_scale(self) -> float:
        return max(0.75, min(1.75, self.font_scale))


# --------------------------------------------------------------------------- #
#  Loading the palette data
# --------------------------------------------------------------------------- #


def _load(name: str) -> dict:
    path = paths.data_dir() / "themes" / f"{name}.toml"
    if not path.is_file():
        raise ThemeError(f"theme data missing: {path}")
    with path.open("rb") as handle:
        return tomllib.load(handle)


@lru_cache(maxsize=1)
def catppuccin_data() -> dict:
    return _load("catppuccin")


@lru_cache(maxsize=1)
def dracula_data() -> dict:
    return _load("dracula")


@lru_cache(maxsize=1)
def ptyxis_data() -> dict:
    return _load("ptyxis")


def families() -> list[tuple[str, str]]:
    return [("catppuccin", "Catppuccin"), ("dracula", "Dracula"), ("ptyxis", "Ptyxis")]


def catppuccin_flavors() -> list[dict]:
    return catppuccin_data()["flavor"]


def catppuccin_accents() -> list[dict]:
    return catppuccin_data()["accent"]


def dracula_bases() -> list[dict]:
    return dracula_data()["base"]


def dracula_accents() -> list[dict]:
    return dracula_data()["accent"]


def ptyxis_palettes() -> list[dict]:
    return ptyxis_data()["palette"]


def _pairing(data: dict, accent: str) -> tuple[str, str]:
    for row in data.get("pairing", ()):
        if row["accent"] == accent:
            return row["secondary"], row["tertiary"]
    return accent, accent


# --------------------------------------------------------------------------- #
#  Resolving settings into a Scheme
# --------------------------------------------------------------------------- #


def _semantic(colours: dict[str, str], fallback: Scheme | None = None) -> dict[str, str]:
    """Pick green/amber/red for the status dots from the palette's own colours."""
    return {
        "success": colours.get("green", "#4caf50"),
        "warning": colours.get("yellow", colours.get("peach", "#e8b055")),
        "danger": colours.get("red", "#e06c6c"),
    }


def _resolve_catppuccin(settings: Settings) -> Scheme:
    data = catppuccin_data()
    flavors = {row["key"]: row for row in data["flavor"]}
    accents = {row["key"]: row for row in data["accent"]}
    flavor = flavors.get(settings.flavor) or flavors["mocha"]
    accent_key = settings.accent if settings.accent in accents else "mauve"

    if settings.monochrome_accents:
        secondary_key = tertiary_key = accent_key
    else:
        secondary_key, tertiary_key = _pairing(data, accent_key)

    def colour(key: str) -> str:
        return accents[key][flavor["key"]]

    return Scheme(
        key=f"catppuccin_{flavor['key']}_{accent_key}",
        name=f"Catppuccin {flavor['name']} · {accents[accent_key]['name']}",
        dark=bool(flavor["dark"]),
        base=flavor["base"],
        mantle=flavor["mantle"],
        crust=flavor["crust"],
        surface=flavor["surface0"],
        text=flavor["text"],
        subtext=flavor["subtext1"],
        overlay=flavor["overlay1"],
        primary=colour(accent_key),
        secondary=colour(secondary_key),
        tertiary=colour(tertiary_key),
        error=colour("red"),
        **_semantic({key: colour(key) for key in ("green", "yellow", "red", "peach")}),
    )


def _resolve_dracula(settings: Settings) -> Scheme:
    data = dracula_data()
    bases = {row["key"]: row for row in data["base"]}
    accents = {row["key"]: row for row in data["accent"]}
    base = bases.get(settings.flavor) or bases["dark"]
    accent_key = settings.accent if settings.accent in accents else "purple"
    variant = "dark" if base["dark"] else "light"

    if settings.monochrome_accents:
        secondary_key = tertiary_key = accent_key
    else:
        secondary_key, tertiary_key = _pairing(data, accent_key)

    return Scheme(
        key=f"dracula_{base['key']}_{accent_key}",
        name=f"{base['name']} · {accents[accent_key]['name']}",
        dark=bool(base["dark"]),
        base=base["base"],
        mantle=base["mantle"],
        crust=base["crust"],
        surface=base["surface0"],
        text=base["text"],
        subtext=base["subtext1"],
        overlay=base["overlay1"],
        primary=accents[accent_key][variant],
        secondary=accents[secondary_key][variant],
        tertiary=accents[tertiary_key][variant],
        error=accents["red"][variant],
        **_semantic({key: accents[key][variant] for key in ("green", "yellow", "red")}),
    )


def _resolve_ptyxis(settings: Settings) -> Scheme:
    palettes = {row["key"]: row for row in ptyxis_palettes()}
    palette = palettes.get(settings.palette) or palettes["ptyxis_nord"]
    background = palette["background"]
    foreground = palette["foreground"]

    # Surfaces are derived by mixing the background toward the foreground and
    # black, exactly as buildPtyxisColorScheme does, so each palette keeps its hue.
    scheme = Scheme(
        key=palette["key"],
        name=palette["name"],
        dark=bool(palette["dark"]),
        base=background,
        mantle=mix(background, "#000000", 0.20),
        crust=mix(background, "#000000", 0.40),
        surface=mix(background, foreground, 0.07),
        text=foreground,
        subtext=mix(foreground, background, 0.25),
        overlay=mix(background, foreground, 0.40),
        primary=palette["primary"],
        secondary=palette["secondary"],
        tertiary=palette["tertiary"],
        error=palette["error"],
        ansi=list(palette.get("ansi", ())),
    )
    # ANSI slot 2 is green, 3 is yellow, 1 is red — the role convention every one
    # of these palettes was authored against. Curated entries carry no table, so
    # they fall back to their own accent picks.
    ansi = scheme.ansi
    if len(ansi) >= 4:
        scheme.success, scheme.warning, scheme.danger = ansi[2], ansi[3], ansi[1]
    else:
        scheme.success, scheme.warning, scheme.danger = (
            palette["tertiary"],
            palette["secondary"],
            palette["error"],
        )
    # Terminal palettes are authored for terminal text, and a few (C64, Grass)
    # are well under AA once they are driving UI chrome.
    scheme.text = ensure_contrast(scheme.text, scheme.base)
    scheme.subtext = ensure_contrast(scheme.subtext, scheme.base, MIN_CONTRAST_DIM)
    scheme.primary = ensure_contrast(scheme.primary, scheme.base, MIN_CONTRAST_DIM)
    scheme.success = ensure_contrast(scheme.success, scheme.base, MIN_CONTRAST_DIM)
    scheme.warning = ensure_contrast(scheme.warning, scheme.base, MIN_CONTRAST_DIM)
    scheme.danger = ensure_contrast(scheme.danger, scheme.base, MIN_CONTRAST_DIM)
    return scheme


def resolve(settings: Settings) -> Scheme:
    """Turn a settings choice into the concrete colours to paint with."""
    if settings.family == "dracula":
        return _resolve_dracula(settings)
    if settings.family == "ptyxis":
        return _resolve_ptyxis(settings)
    return _resolve_catppuccin(settings)


def font_family(settings: Settings) -> str:
    for key, _, family in BUNDLED_FONTS:
        if key == settings.font and family:
            return family
    return ""


def _font_dirs() -> list[Path]:
    home = Path(os.path.expanduser("~"))
    return [
        # Where the package installs the bundled faces.
        Path("/usr/share/fonts/oss"),
        # The same faces in the source tree, so running from a checkout offers
        # the same list as an installed copy rather than silently fewer.
        paths.data_dir() / "fonts",
        Path("/usr/local/share/fonts"),
        Path("/usr/share/fonts"),
        home / ".local/share/fonts",
        home / ".fonts",
    ]


@lru_cache(maxsize=1)
def available_fonts() -> list[tuple[str, str, str]]:
    """Only offer fonts that are actually installed.

    The bundled faces ship in a separate package, because 17MB of TTFs in the
    main one would be most of its size for something optional. A picker that
    lists faces the system does not have would silently fall back to the default
    and look like a bug, so absent families are left out instead.
    """
    installed: set[str] = set()
    for directory in _font_dirs():
        if not directory.is_dir():
            continue
        try:
            for path in directory.rglob("*.tt[fc]"):
                installed.add(path.stem.lower().replace("-", "_").replace(" ", "_"))
            for path in directory.rglob("*.otf"):
                installed.add(path.stem.lower().replace("-", "_").replace(" ", "_"))
        except OSError:
            continue

    out = []
    for key, label, family in BUNDLED_FONTS:
        if not family:
            out.append((key, label, family))  # the system default, always there
            continue
        stem = family.lower().replace(" ", "_")
        if any(name.startswith(stem) or name.startswith(key) for name in installed):
            out.append((key, label, family))
    return out


# --------------------------------------------------------------------------- #
#  CSS
# --------------------------------------------------------------------------- #


def _palette_block(colours: dict[str, str]) -> str:
    """Emit each palette entry in both forms libadwaita has used.

    libadwaita 1.7 moved its stylesheet onto CSS custom properties, so on 1.9
    ``@define-color accent_bg_color`` still *resolves* but no longer drives the
    widgets — the variable does. Older versions only understand @define-color.
    Emitting both is a few hundred bytes and works either way.
    """
    defines = "\n".join(f"@define-color {name} {value};" for name, value in colours.items())
    variables = "\n".join(
        f"  --{name.replace('_', '-')}: {value};" for name, value in colours.items()
    )
    return f"{defines}\n\n:root {{\n{variables}\n}}\n"


def base_css(scheme: Scheme, settings: Settings) -> str:
    """Opaque theme: libadwaita's palette plus this app's own widgets."""
    # Semantic, not accent-derived: a green "applied" dot has to stay green
    # whatever accent is picked, or the status dot stops meaning anything.
    success = scheme.success
    warning = scheme.warning
    card = scheme.surface
    dim = ensure_contrast(scheme.subtext, card, MIN_CONTRAST_DIM)
    mono_dim = ensure_contrast(scheme.overlay, card, MIN_CONTRAST_DIM)

    family = font_family(settings)
    scale = settings.clamped_scale()
    font_rule = ""
    if family:
        font_rule += f'  font-family: "{family}", system-ui, sans-serif;\n'
    if abs(scale - 1.0) > 0.001:
        font_rule += f"  font-size: {scale:.2f}rem;\n"
    font_block = f"window {{\n{font_rule}}}\n" if font_rule else ""

    palette = {
        "window_bg_color": scheme.base,
        "window_fg_color": scheme.text,
        "view_bg_color": scheme.base,
        "view_fg_color": scheme.text,
        "headerbar_bg_color": scheme.crust,
        "headerbar_fg_color": scheme.text,
        "headerbar_border_color": scheme.border,
        "headerbar_backdrop_color": scheme.crust,
        "headerbar_shade_color": rgba(scheme.crust, 0.5),
        "sidebar_bg_color": scheme.mantle,
        "sidebar_fg_color": scheme.text,
        "sidebar_backdrop_color": scheme.mantle,
        "sidebar_border_color": scheme.border,
        "sidebar_shade_color": rgba(scheme.crust, 0.5),
        "secondary_sidebar_bg_color": scheme.mantle,
        "secondary_sidebar_fg_color": scheme.text,
        "card_bg_color": card,
        "card_fg_color": scheme.text,
        "card_shade_color": rgba(scheme.crust, 0.6),
        "dialog_bg_color": scheme.mantle,
        "dialog_fg_color": scheme.text,
        "popover_bg_color": scheme.mantle,
        "popover_fg_color": scheme.text,
        "shade_color": rgba(scheme.crust, 0.7),
        "scrollbar_outline_color": scheme.border,
        "accent_bg_color": scheme.primary,
        "accent_fg_color": scheme.on_primary,
        "accent_color": ensure_contrast(scheme.primary, scheme.base, MIN_CONTRAST_DIM),
        "success_bg_color": success,
        "success_fg_color": on_colour(success),
        "success_color": ensure_contrast(success, scheme.base, MIN_CONTRAST_DIM),
        "warning_bg_color": warning,
        "warning_fg_color": on_colour(warning),
        "warning_color": ensure_contrast(warning, scheme.base, MIN_CONTRAST_DIM),
        "error_bg_color": scheme.error,
        "error_fg_color": on_colour(scheme.error),
        "error_color": ensure_contrast(scheme.error, scheme.base, MIN_CONTRAST_DIM),
        "destructive_bg_color": scheme.error,
        "destructive_fg_color": on_colour(scheme.error),
        "destructive_color": ensure_contrast(scheme.error, scheme.base, MIN_CONTRAST_DIM),
    }

    return f"""/* {scheme.name} — generated by ossgui.theme */

{_palette_block(palette)}
{font_block}
/* ---- flag cards ------------------------------------------------------- */

.flag-card {{
  background-color: {card};
  border: 1px solid {scheme.border};
  border-radius: 8px;
  padding: 9px 10px;
}}
.flag-card:hover {{ border-color: {scheme.border_strong}; }}
.flag-card.selected {{ border-color: {rgba(scheme.primary, 0.55)}; }}
.flag-card.risk-caution {{ border-color: {mix(scheme.base, warning, 0.55)}; }}
.flag-card.risk-breaking {{ border-color: {mix(scheme.base, scheme.error, 0.45)}; }}
.flag-card.risk-one-way {{ border-color: {mix(scheme.base, scheme.error, 0.7)}; }}
.flag-card.unavailable {{ opacity: 0.45; }}

.flag-title {{ font-weight: 500; color: {scheme.text}; }}
.flag-desc {{ color: {dim}; font-size: 0.9em; }}
.flag-key {{
  font-family: {MONO_FAMILY};
  font-size: 0.82em;
  color: {mono_dim};
}}

/* ---- badges ----------------------------------------------------------- */

.risk-badge {{
  font-size: 0.75em;
  padding: 1px 6px;
  border-radius: 4px;
  font-weight: 600;
}}
.risk-badge.caution {{
  background-color: {mix(scheme.base, warning, 0.30)};
  color: {ensure_contrast(warning, mix(scheme.base, warning, 0.30), MIN_CONTRAST_DIM)};
}}
.risk-badge.breaking, .risk-badge.one-way {{
  background-color: {mix(scheme.base, scheme.error, 0.30)};
  color: {ensure_contrast(scheme.error, mix(scheme.base, scheme.error, 0.30), MIN_CONTRAST_DIM)};
}}
.hw-badge {{
  background-color: {mix(scheme.base, scheme.tertiary, 0.25)};
  color: {ensure_contrast(scheme.tertiary, mix(scheme.base, scheme.tertiary, 0.25), MIN_CONTRAST_DIM)};
}}

/* ---- status dots (§6) -------------------------------------------------- */

.status-dot {{ font-size: 0.7em; }}
.status-applied {{ color: {ensure_contrast(success, card, MIN_CONTRAST_DIM)}; }}
.status-pending-reboot {{ color: {ensure_contrast(warning, card, MIN_CONTRAST_DIM)}; }}
.status-differs {{ color: {ensure_contrast(scheme.danger, card, MIN_CONTRAST_DIM)}; }}
.status-not-set {{ color: {mono_dim}; }}
.status-invalid {{ color: {mono_dim}; }}
.status-unknown {{ color: {mono_dim}; }}

/* ---- chrome ----------------------------------------------------------- */

.group-header {{ color: {dim}; font-size: 0.92em; }}
.changed-counter {{ color: {ensure_contrast(scheme.primary, scheme.crust, MIN_CONTRAST_DIM)}; font-weight: 500; }}
.section-footer {{ color: {ensure_contrast(scheme.primary, scheme.base, MIN_CONTRAST_DIM)}; font-size: 0.9em; }}
.lock-hint {{ color: {mono_dim}; font-size: 0.9em; }}
.reboot-hint {{ color: {ensure_contrast(warning, scheme.crust, MIN_CONTRAST_DIM)}; font-size: 0.9em; }}
.diff-view {{ font-family: {MONO_FAMILY}; font-size: 0.85em; }}
.diff-add {{ color: {ensure_contrast(success, scheme.base, MIN_CONTRAST_DIM)}; }}
.diff-remove {{ color: {ensure_contrast(scheme.error, scheme.base, MIN_CONTRAST_DIM)}; }}
.diff-meta {{ color: {mono_dim}; }}
.swatch {{ border-radius: 6px; border: 1px solid {scheme.border}; }}

/* ---- dashboard meter ---------------------------------------------------- */

.meter-applied {{ background-color: {success}; }}
.meter-pending-reboot {{ background-color: {warning}; }}
.meter-differs {{ background-color: {scheme.danger}; }}
.meter-not-set {{ background-color: {mix(scheme.base, scheme.text, 0.22)}; }}
.meter-invalid {{ background-color: {mix(scheme.base, scheme.text, 0.12)}; }}
.meter-unknown {{ background-color: {mix(scheme.base, scheme.text, 0.12)}; }}
.meter-applied, .meter-pending-reboot, .meter-differs,
.meter-not-set, .meter-invalid, .meter-unknown {{
  border-radius: 3px;
  border: none;
  min-height: 10px;
}}
"""


def glass_css(scheme: Scheme, settings: Settings) -> str:
    """Translucent surfaces + hairline edge. Load at USER + 1000, last.

    Every toplevel becomes translucent, so a dialog over the main window would
    show it bleeding through. Secondary windows carry ``.solid`` and are forced
    opaque by the last rule here — that has to come *after* the glass rules to win.
    """
    alpha = settings.clamped_alpha()
    side = max(0.0, alpha - GLASS_SIDE_OFFSET)
    head = max(0.0, alpha - GLASS_HEAD_OFFSET)
    popover = min(1.0, alpha - GLASS_POPOVER_OFFSET)

    if scheme.dark:
        edge, glow = "rgba(255, 255, 255, 0.09)", "rgba(255, 255, 255, 0.05)"
    else:
        edge, glow = "rgba(0, 0, 0, 0.10)", "rgba(255, 255, 255, 0.35)"

    return f"""/* Glass mode — {scheme.name} @ {alpha:.2f}
   GNOME/Mutter does not blur behind app windows, so this is clean translucency
   rather than frost. KDE/KWin does blur. Keep alpha >= 0.5 for readable text. */

window, window.background {{
  background-color: {rgba(scheme.base, alpha)};
}}

.sidebar-pane,
.sidebar-pane > .background,
navigation-split-view > .sidebar-pane,
.navigation-sidebar {{
  background-color: {rgba(scheme.mantle, side)};
}}

.content-pane,
.content-pane > .background,
.view, scrolledwindow > viewport {{
  background-color: {rgba(scheme.base, side)};
}}

headerbar,
.toolbar headerbar,
toolbarview > headerbar {{
  background-color: {rgba(scheme.crust, head)};
  border-bottom: 1px solid {edge};
  box-shadow: inset 0 1px 0 {glow};
}}

.flag-card, .card, preferencesgroup > box.card {{
  background-color: {rgba(scheme.surface, alpha)};
  border: 1px solid {edge};
}}

popover > contents {{
  background-color: {rgba(scheme.mantle, popover)};
  border: 1px solid {edge};
}}

/* Secondary windows stay opaque, or the main window ghosts through them. */
window.solid,
window.solid.background,
.solid, .solid > .background {{
  background-color: {scheme.base};
  background-image: none;
}}
"""


def css_for(settings: Settings) -> tuple[str, str]:
    """``(base css, glass css)``. The glass string is empty when it is off."""
    scheme = resolve(settings)
    return base_css(scheme, settings), (glass_css(scheme, settings) if settings.glass else "")
