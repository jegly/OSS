"""User settings — appearance choices, persisted as TOML.

Nothing here is security-relevant: it is the theme, the font and the glass
toggle. Written with our own emitter, read with stdlib ``tomllib``.
"""

from __future__ import annotations

import tomllib
from dataclasses import asdict
from pathlib import Path

from . import paths, tomlemit
from .theme import Settings

FILENAME = "settings.toml"

HEADER = """oss appearance settings.

Safe to edit or delete — deleting it just restores the defaults.
Themes come from /usr/share/oss/themes/."""


def settings_path() -> Path:
    return paths.user_config_dir() / FILENAME


def load() -> Settings:
    """Read the saved settings, falling back to defaults on any problem."""
    path = settings_path()
    if not path.is_file():
        return Settings()
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return Settings()

    appearance = raw.get("appearance", {})
    if not isinstance(appearance, dict):
        return Settings()

    defaults = Settings()
    known = asdict(defaults)
    values: dict[str, object] = {}
    for key, fallback in known.items():
        value = appearance.get(key, fallback)
        # Keep the type the dataclass declares; a hand-edited file should not be
        # able to put a string where a float belongs.
        if isinstance(fallback, bool):
            values[key] = bool(value) if isinstance(value, bool) else fallback
        elif isinstance(fallback, float):
            values[key] = float(value) if isinstance(value, (int, float)) else fallback
        elif isinstance(fallback, str):
            values[key] = value if isinstance(value, str) else fallback
        else:
            values[key] = fallback
    return Settings(**values)  # type: ignore[arg-type]


def save(settings: Settings) -> None:
    """Write the settings, creating the config directory if needed."""
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    text = tomlemit.dumps({"appearance": asdict(settings)}, header=HEADER)
    temp = path.with_suffix(".toml.tmp")
    temp.write_text(text, encoding="utf-8")
    temp.replace(path)
