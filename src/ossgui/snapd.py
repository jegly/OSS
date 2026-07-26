"""Snap interface permissions — connect and disconnect plugs.

A snap declares *plugs* for the things it wants (camera, home, network) and
*slots* for things it provides. A plug connected to a slot is a granted
permission; disconnecting it revokes that access. This is the closest thing snaps
have to per-app permissions, and it is otherwise only reachable from the command
line:

    snap connections firefox
    snap disconnect firefox:home
    snap connect firefox:home

Both read commands work unprivileged, so the whole view is available without a
password; only connect and disconnect need root.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field

SNAP = "/usr/bin/snap"

#: Snap and interface names: lowercase, digits, hyphens. Slot references may be
#: bare (":camera" for a system slot) or qualified ("gtk-common-themes:themes").
_NAME = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
_SNAP_NAME = re.compile(rf"^{_NAME}$")
_PLUG_REF = re.compile(rf"^{_NAME}:{_NAME}$")
_SLOT_REF = re.compile(rf"^(?:{_NAME})?:{_NAME}$")

#: Interfaces whose loss visibly breaks the snap rather than merely restricting
#: it. Disconnecting these is legitimate but should never be a surprise.
ESSENTIAL = {
    "desktop": "Basic desktop integration. Without it the app may not start.",
    "desktop-legacy": "Older desktop integration, including input methods.",
    "wayland": "The display server on this session — the window will not open.",
    "x11": "The X11 display server; needed by snaps that do not use Wayland.",
    "opengl": "Hardware rendering. Expect a black window or a refusal to start.",
    "browser-support": "Required by browser sandboxes; Firefox and Chromium need it.",
    "gpu-2404": "The graphics driver stack, supplied through a content interface.",
    "gnome-46-2404": "The GNOME platform runtime this snap is built against.",
    "network": "All network access.",
    "home": "Read and write access to your home directory — no opening or saving files.",
}

#: Interfaces worth reviewing: real capability, and usually safe to remove.
SENSITIVE = {
    "camera": "The webcam.",
    "audio-record": "The microphone.",
    "removable-media": "Anything mounted under /media and /mnt.",
    "cups-control": "Full control of the print system, not just printing.",
    "network-control": "Reconfiguring the network — interfaces, routes, firewall.",
    "network-observe": "Reading network configuration and traffic counters.",
    "system-observe": "Reading process and system state, including other processes.",
    "hardware-observe": "Reading detailed hardware information.",
    "mount-observe": "Reading mount points and disk layout.",
    "log-observe": "Reading the system log.",
    "raw-usb": "Direct access to USB devices.",
    "bluetooth-control": "Full control of Bluetooth.",
    "firewall-control": "Changing firewall rules.",
    "kernel-module-control": "Loading kernel modules. Very rarely legitimate.",
    "docker-support": "Container privileges close to root.",
    "personal-files": "Named files and directories in your home.",
    "system-files": "Named files elsewhere on the system.",
    "password-manager-service": "Reading your stored passwords.",
    "screen-inhibit-control": "Preventing the screen from locking.",
    "shutdown": "Rebooting or powering off the machine.",
    "ssh-keys": "Reading your SSH private keys.",
    "gpg-keys": "Reading your GPG keyring.",
}


class SnapError(ValueError):
    """A snap, plug or slot reference we refuse to act on."""


@dataclass(frozen=True)
class Connection:
    """One row of `snap connections` — an interface and its wiring."""

    interface: str
    plug: str  # "snap:plug", or "" when this snap only provides a slot
    slot: str  # "", ":name" for a system slot, or "othersnap:name"
    notes: str = ""

    @property
    def connected(self) -> bool:
        return bool(self.slot)

    @property
    def snap(self) -> str:
        return self.plug.partition(":")[0] if self.plug else ""

    @property
    def plug_name(self) -> str:
        return self.plug.partition(":")[2] if self.plug else ""

    @property
    def base_interface(self) -> str:
        """`content[gnome-46-2404]` -> `content`."""
        return self.interface.partition("[")[0]

    @property
    def essential(self) -> str:
        return ESSENTIAL.get(self.base_interface, "") or ESSENTIAL.get(self.plug_name, "")

    @property
    def sensitive(self) -> str:
        return SENSITIVE.get(self.base_interface, "")

    @property
    def describe(self) -> str:
        return self.essential or self.sensitive or ""


@dataclass
class Snap:
    """An installed snap and its connections."""

    name: str
    version: str = ""
    publisher: str = ""
    notes: str = ""
    connections: list[Connection] = field(default_factory=list)

    @property
    def is_base(self) -> bool:
        """Bases and runtimes have no user-facing permissions worth showing."""
        return "base" in self.notes or self.name.startswith(("core", "bare"))

    @property
    def plugs(self) -> list[Connection]:
        """Only rows where *this* snap is the consumer."""
        return [c for c in self.connections if c.snap == self.name]

    @property
    def connected_count(self) -> int:
        return sum(1 for c in self.plugs if c.connected)


def available() -> bool:
    return shutil.which("snap") is not None or _exists(SNAP)


def _exists(path: str) -> bool:
    from pathlib import Path

    return Path(path).exists()


def _run(argv: list[str], timeout: int = 30) -> str | None:
    if not available():
        return None
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def parse_list(output: str) -> list[Snap]:
    """Parse `snap list`."""
    out: list[Snap] = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6 or not _SNAP_NAME.match(parts[0]):
            continue
        out.append(
            Snap(
                name=parts[0],
                version=parts[1],
                publisher=parts[4],
                notes=parts[5] if len(parts) > 5 else "",
            )
        )
    return out


def parse_connections(output: str) -> list[Connection]:
    """Parse `snap connections`. A '-' means absent, not a name."""
    out: list[Connection] = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 3:
            continue
        interface, plug, slot = parts[0], parts[1], parts[2]
        notes = parts[3] if len(parts) > 3 else ""
        out.append(
            Connection(
                interface=interface,
                plug="" if plug == "-" else plug,
                slot="" if slot == "-" else slot,
                notes="" if notes == "-" else notes,
            )
        )
    return out


def read_all() -> list[Snap]:
    """Every installed snap with its connections. Unprivileged."""
    listing = _run([SNAP, "list"])
    if listing is None:
        return []
    snaps = parse_list(listing)

    connections_output = _run([SNAP, "connections", "--all"], timeout=60)
    connections = parse_connections(connections_output or "")

    by_name = {snap.name: snap for snap in snaps}
    for connection in connections:
        owner = by_name.get(connection.snap)
        if owner is not None:
            owner.connections.append(connection)
    return snaps


# --------------------------------------------------------------------------- #
#  Changes
# --------------------------------------------------------------------------- #


def validate(plug: str, action: str) -> None:
    """Both halves are interpolated into an argv, so both are checked."""
    if action not in ("connect", "disconnect"):
        raise SnapError(f"unknown action {action!r}")
    if not _PLUG_REF.match(plug):
        raise SnapError(f"not a valid snap:plug reference: {plug!r}")


def to_argv(plug: str, action: str, slot: str = "") -> list[str]:
    validate(plug, action)
    argv = [SNAP, action, plug]
    if slot:
        if not _SLOT_REF.match(slot):
            raise SnapError(f"not a valid slot reference: {slot!r}")
        argv.append(slot)
    return argv


def plan_commands(changes: dict[str, str]) -> list[tuple[list[str], str]]:
    """``(argv, why)`` for each staged plug change."""
    out = []
    for plug in sorted(changes):
        action = changes[plug]
        verb = "revoke" if action == "disconnect" else "grant"
        out.append((to_argv(plug, action), f"{verb} {plug}"))
    return out


def from_payload(data: dict) -> dict[str, str]:
    """Validate a snap payload from the GUI."""
    if not isinstance(data, dict):
        raise SnapError("snap payload is not an object")
    out: dict[str, str] = {}
    for plug, action in data.items():
        if not isinstance(plug, str) or not isinstance(action, str):
            raise SnapError("plug references and actions must both be strings")
        validate(plug, action)
        out[plug] = action
    return out
