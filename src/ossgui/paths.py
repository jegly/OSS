"""Where things live, in both dev-tree and installed layouts.

Importable by the privileged helper: stdlib only, no gi.
"""

from __future__ import annotations

import os
from pathlib import Path

APP_ID = "com.jegly.OSS"
PROG = "oss"

#: Marker file that identifies a data directory.
_MARKER = "catalogue"

_INSTALLED_DATA = Path("/usr/share") / PROG
_DEV_DATA = Path(__file__).resolve().parent.parent.parent / "data"


def data_dir() -> Path:
    """Shipped read-only data: catalogue, presets, polkit."""
    override = os.environ.get("OSS_DATA")
    if override:
        return Path(override)
    if (_DEV_DATA / _MARKER).is_dir():
        return _DEV_DATA
    return _INSTALLED_DATA


def catalogue_dir() -> Path:
    return data_dir() / "catalogue"


def shipped_presets_dir() -> Path:
    return data_dir() / "presets"


def user_config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / PROG


def user_presets_dir() -> Path:
    return user_config_dir() / "presets"


def state_dir() -> Path:
    """Root-owned state: permission rollback journal, apply log."""
    return Path("/var/lib") / PROG


def helper_path() -> str:
    dev = Path(__file__).resolve().parent.parent.parent / "helper" / f"{PROG}-helper"
    if dev.exists() and os.environ.get("OSS_DEV_HELPER"):
        return str(dev)
    return f"/usr/libexec/{PROG}-helper"
