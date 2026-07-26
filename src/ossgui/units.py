"""Arbitrary systemd units — mask, disable, enable — BUILD_PLAN §4.13.

The catalogue carries a curated set of units worth turning off, which is what
presets use. This module is the other half: letting you act on *any* unit on the
system, which cannot go through the flag catalogue because the unit names are
not known ahead of time.

Safety comes from three places: the unit name must match a strict pattern, the
action must be one of four words, and a short list of units may never be masked
because masking them leaves the machine unusable or unbootable.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass

SYSTEMCTL = "/usr/bin/systemctl"

ACTIONS = ("mask", "unmask", "disable", "enable")

#: A unit name, per systemd.unit(5) — the templating '@' and escaped names included.
_UNIT_NAME = re.compile(
    r"^[A-Za-z0-9:_.\\@-]{1,200}"
    r"\.(service|socket|timer|target|path|mount|automount|slice|swap)$"
)

#: Masking any of these leaves you with a machine you cannot log into or fix.
#: They are refused outright rather than warned about.
NEVER_MASK = frozenset({
    "dbus.service",
    "dbus.socket",
    "dbus-broker.service",
    "systemd-journald.service",
    "systemd-journald.socket",
    "systemd-logind.service",
    "systemd-udevd.service",
    "systemd-udevd-control.socket",
    "systemd-udevd-kernel.socket",
    "polkit.service",
    "user@.service",
    "basic.target",
    "sysinit.target",
    "multi-user.target",
    "graphical.target",
    "local-fs.target",
    "dbus.target",
    "systemd-tmpfiles-setup.service",
    "systemd-remount-fs.service",
})

#: Turning these off is legitimate but takes away something large and obvious.
#: The UI warns and names the consequence rather than blocking.
HEAVY_CONSEQUENCE = {
    "gdm.service": "The graphical login screen. Masking it boots you to a text console.",
    "gdm3.service": "The graphical login screen. Masking it boots you to a text console.",
    "NetworkManager.service": "All managed networking. Wi-Fi and wired connections stop coming up.",
    "systemd-networkd.service": "Networking on systems that use networkd instead of NetworkManager.",
    "systemd-resolved.service": "DNS resolution for the whole system.",
    "ssh.service": "Remote login. If you are connected over SSH you will not get back in.",
    "sshd.service": "Remote login. If you are connected over SSH you will not get back in.",
    "snapd.service": "Every snap, which on stock Ubuntu includes Firefox.",
    "systemd-timesyncd.service": "Clock synchronisation. The clock will drift.",
    "cups.service": "All printing.",
    "bluetooth.service": "All Bluetooth devices.",
    "wpa_supplicant.service": "All Wi-Fi.",
}

#: Well-known ports, so a listening socket can be named even when the owning
#: process is root-owned and therefore invisible to an unprivileged `ss`.
PORT_NAMES = {
    22: "SSH", 25: "SMTP", 53: "DNS", 67: "DHCP server", 68: "DHCP client",
    80: "HTTP", 111: "RPC portmapper", 123: "NTP", 137: "NetBIOS name",
    138: "NetBIOS datagram", 139: "NetBIOS session", 143: "IMAP", 161: "SNMP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP submission",
    631: "CUPS printing", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1900: "SSDP/UPnP", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
    3702: "WS-Discovery", 5353: "mDNS", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP alt", 27017: "MongoDB", 51820: "WireGuard",
}


class UnitError(ValueError):
    """A unit name or action we refuse to act on."""


@dataclass(frozen=True)
class Socket:
    """One listening socket from `ss -ltnup`."""

    proto: str
    address: str
    port: int
    process: str = ""

    @property
    def name(self) -> str:
        return self.process or PORT_NAMES.get(self.port, "")

    @property
    def public(self) -> bool:
        """Listening on something other than loopback — reachable from outside."""
        return not (
            self.address.startswith("127.")
            or self.address in ("::1", "[::1]")
            or self.address.startswith("127.0.0.53")
        )


@dataclass(frozen=True)
class Unit:
    """One systemd unit and its enablement state."""

    name: str
    state: str  # enabled | disabled | masked | static | generated | …
    sockets: tuple[Socket, ...] = ()

    @property
    def can_mask(self) -> bool:
        return self.name not in NEVER_MASK

    @property
    def warning(self) -> str:
        return HEAVY_CONSEQUENCE.get(self.name, "")

    @property
    def ports(self) -> str:
        if not self.sockets:
            return ""
        parts = []
        for socket in sorted(self.sockets, key=lambda s: s.port):
            label = f"{socket.port}/{socket.proto}"
            if socket.name:
                label += f" ({socket.name})"
            parts.append(label)
        return ", ".join(parts)


def validate(name: str, action: str) -> None:
    """Reject anything we would not build a systemctl command from."""
    if action not in ACTIONS:
        raise UnitError(f"unknown action {action!r}")
    if not _UNIT_NAME.match(name):
        raise UnitError(f"not a valid unit name: {name!r}")
    if action == "mask" and name in NEVER_MASK:
        raise UnitError(
            f"{name} is required for the system to be usable and will not be masked"
        )


def to_argv(name: str, action: str) -> list[str]:
    validate(name, action)
    if action in ("mask", "disable"):
        # --now also stops it, so the effect is immediate rather than next boot.
        return [SYSTEMCTL, action, "--now", name]
    return [SYSTEMCTL, action, name]


_SS_ROW = re.compile(
    r"^(?P<proto>tcp|udp)\s+\S+\s+\d+\s+\d+\s+"
    r"(?P<local>\S+)\s+\S+\s*(?P<rest>.*)$"
)
_SS_PROCESS = re.compile(r'users:\(\("(?P<name>[^"]+)"')


def read_sockets() -> list[Socket]:
    """Listening TCP/UDP sockets. Works unprivileged, minus root-owned process names."""
    if shutil.which("ss") is None:
        return []
    try:
        result = subprocess.run(
            ["ss", "-ltnup"], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return []

    out: list[Socket] = []
    for line in result.stdout.splitlines()[1:]:
        match = _SS_ROW.match(line.strip())
        if match is None:
            continue
        local = match.group("local")
        address, _, port_text = local.rpartition(":")
        try:
            port = int(port_text)
        except ValueError:
            continue
        process = ""
        found = _SS_PROCESS.search(match.group("rest"))
        if found:
            process = found.group("name")
        out.append(Socket(match.group("proto"), address.strip("[]"), port, process))
    return out


def sockets_for(unit_name: str, sockets: list[Socket]) -> tuple[Socket, ...]:
    """Best-effort match of listening sockets to a unit, by process name.

    An unprivileged `ss` cannot see the process behind a root-owned socket, so
    this is a hint rather than an authority — which is why the UI presents it as
    "listening on", not "this unit owns".
    """
    stem = unit_name.rsplit(".", 1)[0].lower()
    matched = []
    for socket in sockets:
        process = socket.process.lower()
        if not process:
            continue
        if process == stem or process.startswith(stem[:12]) or stem.startswith(process[:12]):
            matched.append(socket)
    return tuple(matched)


def plan_commands(changes: dict[str, str]) -> list[tuple[list[str], str]]:
    """``(argv, why)`` for each staged unit change."""
    out = []
    for name in sorted(changes):
        action = changes[name]
        out.append((to_argv(name, action), f"{action} {name}"))
    return out


def from_payload(data: dict) -> dict[str, str]:
    """Validate a units payload from the GUI."""
    if not isinstance(data, dict):
        raise UnitError("units payload is not an object")
    out: dict[str, str] = {}
    for name, action in data.items():
        if not isinstance(name, str) or not isinstance(action, str):
            raise UnitError("unit names and actions must both be strings")
        validate(name, action)
        out[name] = action
    return out
