"""Presets — a saved selection over the full flag catalogue (§5).

A preset is nothing special: a TOML file mapping flag ids to values, optionally
inheriting another preset through ``base``. Applying one just pre-toggles the
grid; the user can flip anything before hitting Apply. That is what makes
click-and-go and click-and-select the same machinery at different zoom levels.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import paths, tomlemit
from .catalogue import Catalogue

#: Guard against a cycle in `base` inheritance.
MAX_INHERITANCE_DEPTH = 8


class PresetError(Exception):
    """A preset file we can't use."""


@dataclass
class Preset:
    """One named selection."""

    key: str
    name: str
    desc: str = ""
    base: str = ""
    path: Path | None = None
    shipped: bool = True
    #: flag id -> value
    values: dict[str, str] = field(default_factory=dict)
    #: Hardware-specific entries, applied only after the user confirms (§5.5).
    hardware_values: dict[str, str] = field(default_factory=dict)


def _read(path: Path) -> Preset:
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise PresetError(f"{path.name}: {exc}") from exc

    meta = raw.get("preset", {})
    if not isinstance(meta, dict) or "name" not in meta:
        raise PresetError(f"{path.name}: missing [preset] name")

    values: dict[str, str] = {}
    hardware: dict[str, str] = {}
    for entry in raw.get("set", ()):
        if not isinstance(entry, dict) or "id" not in entry or "value" not in entry:
            raise PresetError(f"{path.name}: malformed [[set]] entry")
        target = hardware if entry.get("hw") else values
        target[str(entry["id"])] = str(entry["value"])

    return Preset(
        key=path.stem,
        name=str(meta["name"]),
        desc=str(meta.get("desc", "")),
        base=str(meta.get("base", "")),
        path=path,
        values=values,
        hardware_values=hardware,
    )


def available() -> list[Preset]:
    """Shipped presets first, then the user's own."""
    out: list[Preset] = []
    for directory, shipped in (
        (paths.shipped_presets_dir(), True),
        (paths.user_presets_dir(), False),
    ):
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.toml")):
            try:
                preset = _read(path)
            except PresetError:
                continue  # a broken user preset must not stop the app starting
            preset.shipped = shipped
            out.append(preset)
    return out


def get(key: str) -> Preset | None:
    for preset in available():
        if preset.key == key:
            return preset
    return None


def resolve(preset: Preset, depth: int = 0) -> dict[str, str]:
    """Flatten ``base`` inheritance: parent values first, then this preset's."""
    if depth > MAX_INHERITANCE_DEPTH:
        raise PresetError(f"preset {preset.key!r}: inheritance is too deep or circular")
    values: dict[str, str] = {}
    if preset.base:
        parent = get(preset.base)
        if parent is None:
            raise PresetError(f"preset {preset.key!r}: unknown base {preset.base!r}")
        values.update(resolve(parent, depth + 1))
    values.update(preset.values)
    return values


def selection_for(
    catalogue: Catalogue, preset: Preset, include_hardware: bool = False
) -> dict[str, str | None]:
    """Turn a preset into a staging update covering the *whole* catalogue.

    Flags the preset does not mention are explicitly unset, so loading a preset
    means "make the machine look like this", not "add these on top of whatever
    was already staged".
    """
    wanted = resolve(preset)
    if include_hardware:
        wanted.update(preset.hardware_values)

    out: dict[str, str | None] = {}
    for flag_id, flag in catalogue.flags.items():
        section = catalogue.section(flag.section)
        if not section.implemented:
            continue
        value = wanted.get(flag_id)
        if value is not None and flag.value_is_allowed(value):
            out[flag_id] = value
        else:
            out[flag_id] = None
    return out


def build(
    catalogue: Catalogue,
    name: str,
    selection: dict[str, str],
    desc: str = "",
    base: str = "",
) -> dict:
    """The TOML structure for a preset saved from the current selection."""
    entries = []
    for flag_id in sorted(selection):
        flag = catalogue.get(flag_id)
        if flag is None:
            continue
        entry: dict[str, object] = {"id": flag_id, "value": selection[flag_id]}
        if flag.hw:
            entry["hw"] = True
        entries.append(entry)

    meta: dict[str, object] = {"name": name}
    if base:
        meta["base"] = base
    if desc:
        meta["desc"] = desc
    return {"preset": meta, "set": entries}


def save_user_preset(
    catalogue: Catalogue, name: str, selection: dict[str, str], desc: str = ""
) -> Path:
    """Write a preset into the user's own directory and return its path."""
    key = "".join(c if c.isalnum() or c in "-_" else "-" for c in name.lower()).strip("-")
    if not key:
        raise PresetError("that name has no usable characters in it")
    directory = paths.user_presets_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{key}.toml"
    header = (
        f"{name} — saved from oss.\n"
        "Carry this file to another machine and load it there."
    )
    path.write_text(
        tomlemit.dumps(build(catalogue, name, selection, desc), header=header),
        encoding="utf-8",
    )
    return path


def export_to(catalogue: Catalogue, path: Path, name: str, selection: dict[str, str]) -> None:
    path.write_text(
        tomlemit.dumps(build(catalogue, name, selection), header=f"{name} — exported"),
        encoding="utf-8",
    )


def import_from(path: Path) -> Preset:
    preset = _read(path)
    preset.shipped = False
    return preset
