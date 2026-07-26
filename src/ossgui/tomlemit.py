"""A minimal TOML writer.

``tomli-w`` is not on a stock Ubuntu system (BUILD_PLAN §1), and we only ever
write our own presets and settings, so a small emitter covering the value types
we actually use is the whole dependency story.

Supports: str, bool, int, float, list of those, dict (as table), and list of
dicts (as array of tables). Everything else raises.
"""

from __future__ import annotations

from typing import Any

_BARE_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")

_ESCAPES = {
    "\\": "\\\\",
    '"': '\\"',
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


class TomlEmitError(TypeError):
    """A value we have no TOML representation for."""


def _key(name: str) -> str:
    if name and set(name) <= _BARE_OK:
        return name
    return _string(name)


def _string(text: str) -> str:
    out = ['"']
    for char in text:
        if char in _ESCAPES:
            out.append(_ESCAPES[char])
        elif char < " " or char == "\x7f":
            out.append(f"\\u{ord(char):04X}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _scalar(value: Any) -> str:
    # bool before int — bool is a subclass of int.
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise TomlEmitError(f"cannot emit non-finite float {value!r}")
        return repr(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_scalar(item) for item in value) + "]"
    raise TomlEmitError(f"cannot emit {type(value).__name__} as a TOML value")


def _is_table_array(value: Any) -> bool:
    return (
        isinstance(value, (list, tuple))
        and bool(value)
        and all(isinstance(item, dict) for item in value)
    )


def _emit_table(data: dict, prefix: str, out: list[str]) -> None:
    scalars = {k: v for k, v in data.items() if not isinstance(v, dict) and not _is_table_array(v)}
    tables = {k: v for k, v in data.items() if isinstance(v, dict)}
    arrays = {k: v for k, v in data.items() if _is_table_array(v)}

    if prefix and (scalars or not (tables or arrays)):
        out.append(f"[{prefix}]")
    for key, value in scalars.items():
        out.append(f"{_key(key)} = {_scalar(value)}")
    if scalars:
        out.append("")

    for key, value in tables.items():
        name = f"{prefix}.{_key(key)}" if prefix else _key(key)
        _emit_table(value, name, out)

    for key, value in arrays.items():
        name = f"{prefix}.{_key(key)}" if prefix else _key(key)
        for item in value:
            out.append(f"[[{name}]]")
            for sub_key, sub_value in item.items():
                if isinstance(sub_value, dict) or _is_table_array(sub_value):
                    raise TomlEmitError(
                        f"nested tables inside [[{name}]] are not supported"
                    )
                out.append(f"{_key(sub_key)} = {_scalar(sub_value)}")
            out.append("")


def dumps(data: dict, header: str = "") -> str:
    """Serialise *data* to TOML text, optionally prefixed with a comment *header*."""
    out: list[str] = []
    if header:
        for line in header.strip().splitlines():
            out.append(f"# {line}".rstrip())
        out.append("")
    _emit_table(data, "", out)
    while out and not out[-1]:
        out.pop()
    return "\n".join(out) + "\n"
