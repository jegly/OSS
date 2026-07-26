"""systemd service sandboxing — BUILD_PLAN §4.12.

Applied per-unit as ``/etc/systemd/system/<unit>.d/99-oss.conf``.
``systemd-analyze security <unit>`` gives an exposure score before and after,
which is the built-in feedback loop for this section: you can see a change do
something rather than taking it on faith.

Directive names and values come from a fixed table, so the drop-in is assembled
from known-good strings and nothing the user types reaches the file.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import branding
from .units import _UNIT_NAME  # the same strict unit-name grammar

ANALYZE = "/usr/bin/systemd-analyze"
DROPIN_NAME = "99-oss.conf"

BANNER = branding.with_footer(
    "Delete this file and run systemctl daemon-reload to revert this unit."
) + "[Service]\n"


class SandboxError(ValueError):
    """A unit or directive we refuse to write."""


@dataclass(frozen=True)
class Directive:
    """One sandboxing directive, with what it costs."""

    key: str
    value: str
    title: str
    desc: str
    why: str
    risk: str = "safe"
    breaks: str = ""

    @property
    def line(self) -> str:
        return f"{self.key}={self.value}\n"


#: The §4.12 directive set. Ordered roughly cheapest-to-riskiest.
DIRECTIVES: tuple[Directive, ...] = (
    Directive("NoNewPrivileges", "yes", "No new privileges",
              "Blocks gaining privileges via setuid",
              "Stops a compromised service escalating through any setuid binary"),
    Directive("PrivateTmp", "yes", "Private /tmp",
              "Its own /tmp, invisible to others",
              "Removes the shared-/tmp attack surface between services"),
    Directive("PrivateDevices", "yes", "Private /dev",
              "Only the pseudo-devices it needs",
              "No raw disk or input-device access from the service",
              breaks="Anything needing real hardware access"),
    Directive("ProtectSystem", "strict", "Read-only system",
              "The whole filesystem is read-only",
              "A service that cannot write cannot persist",
              risk="caution",
              breaks="Services that write outside their state directory"),
    Directive("ProtectHome", "yes", "No access to /home",
              "Home directories are hidden",
              "Most daemons have no business reading your files",
              breaks="Services that legitimately serve user data"),
    Directive("ProtectKernelTunables", "yes", "Read-only kernel tunables",
              "No writes to /proc/sys",
              "Stops a service disabling the hardening you just applied"),
    Directive("ProtectKernelModules", "yes", "No module loading",
              "Cannot load kernel modules",
              "Loading a module is the cleanest route from service to kernel"),
    Directive("ProtectKernelLogs", "yes", "No kernel log access",
              "Cannot read dmesg",
              "Kernel logs leak addresses useful for exploitation"),
    Directive("ProtectControlGroups", "yes", "Read-only cgroups",
              "Cannot alter its own limits",
              "Prevents escaping resource limits and some container escapes"),
    Directive("ProtectClock", "yes", "Cannot change the clock",
              "No writes to the system time",
              "Moving the clock is how you make logs lie"),
    Directive("ProtectHostname", "yes", "Cannot change the hostname",
              "Hostname is read-only",
              "Small surface, no legitimate need for most services"),
    Directive("ProtectProc", "invisible", "Cannot see other processes",
              "Only its own processes in /proc",
              "Removes process enumeration, a standard first step after a foothold"),
    Directive("RestrictNamespaces", "yes", "No namespaces",
              "Cannot create new namespaces",
              "User namespaces are the entry point for most container escapes",
              breaks="Container runtimes and anything using bwrap"),
    Directive("RestrictRealtime", "yes", "No realtime scheduling",
              "Cannot request realtime priority",
              "Realtime priority is a local denial-of-service primitive"),
    Directive("RestrictSUIDSGID", "yes", "Cannot create setuid files",
              "No setuid or setgid bits",
              "Closes the most direct route to a persistent backdoor"),
    Directive("LockPersonality", "yes", "Locked personality",
              "Cannot switch execution domain",
              "Blocks a niche route to defeating ASLR"),
    Directive("MemoryDenyWriteExecute", "yes", "No W^X memory",
              "Memory is never writable and executable",
              "Blocks the classic inject-then-run shellcode pattern",
              risk="caution",
              breaks="Anything with a JIT — browsers, Java, Node, Python with some extensions"),
    Directive("SystemCallArchitectures", "native", "Native syscalls only",
              "No 32-bit syscall entry on 64-bit",
              "The compat syscall table is a well-known source of kernel bugs"),
    Directive("SystemCallFilter", "@system-service", "Syscall allowlist",
              "Only the usual service syscalls",
              "Blocks the syscalls no daemon needs but every exploit wants",
              risk="caution",
              breaks="Services using unusual syscalls"),
    Directive("RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6", "Limited socket types",
              "No exotic protocol families",
              "Rare address families are unaudited kernel code",
              risk="caution",
              breaks="Anything using netlink, packet or bluetooth sockets"),
    Directive("CapabilityBoundingSet", "", "Drop all capabilities",
              "No capabilities at all",
              "The strongest single restriction, if the service can live without them",
              risk="caution",
              breaks="Services binding low ports or needing any privileged operation"),
    Directive("PrivateUsers", "yes", "Private user namespace",
              "Its root is not the real root",
              "Even a full compromise lands in a namespace with no real privilege",
              risk="caution",
              breaks="Services needing real uids, or that bind low ports"),
    Directive("IPAddressDeny", "any", "No network at all",
              "All IP traffic denied",
              "The only complete answer for a service that should never talk out",
              risk="breaking",
              breaks="All networking for this unit"),
)

BY_KEY = {directive.key: directive for directive in DIRECTIVES}

_SCORE = re.compile(r"Overall exposure level for .*?:\s*(?P<score>[\d.]+)\s+(?P<verdict>\w+)")


def validate(unit: str, keys: list[str]) -> None:
    if not _UNIT_NAME.match(unit):
        raise SandboxError(f"not a valid unit name: {unit!r}")
    if not unit.endswith(".service"):
        raise SandboxError("only .service units can be sandboxed this way")
    for key in keys:
        if key not in BY_KEY:
            raise SandboxError(f"unknown directive {key!r}")


def dropin_path(unit: str) -> str:
    return f"/etc/systemd/system/{unit}.d/{DROPIN_NAME}"


def render(unit: str, keys: list[str]) -> str:
    """The drop-in content for a unit, built only from the fixed table."""
    validate(unit, keys)
    ordered = [d for d in DIRECTIVES if d.key in set(keys)]
    return BANNER + "".join(d.line for d in ordered)


def read_current(unit: str) -> list[str]:
    """Which of our directives are already in this unit's drop-in."""
    try:
        text = Path(dropin_path(unit)).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out = []
    for line in text.splitlines():
        key, _, _value = line.partition("=")
        key = key.strip()
        if key in BY_KEY:
            out.append(key)
    return out


def score(unit: str) -> tuple[float | None, str]:
    """``systemd-analyze security`` exposure for one unit.

    Lower is better: 0 is fully sandboxed, 10 is a service with no restrictions
    at all. This is what makes the section's effect visible rather than notional.
    """
    if shutil.which("systemd-analyze") is None and not Path(ANALYZE).exists():
        return None, "systemd-analyze is not available"
    try:
        result = subprocess.run(
            [ANALYZE, "security", unit],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, str(exc)

    output = result.stdout + result.stderr
    if "is masked" in output:
        return None, "masked — nothing to analyse"
    if "Unit" in output and "not found" in output:
        return None, "no such unit"
    match = _SCORE.search(output)
    if match is None:
        return None, "no score reported"
    return float(match.group("score")), match.group("verdict")


def overview() -> list[tuple[str, float, str]]:
    """``(unit, score, verdict)`` for every analysable service, worst first."""
    if shutil.which("systemd-analyze") is None and not Path(ANALYZE).exists():
        return []
    try:
        result = subprocess.run(
            [ANALYZE, "security", "--no-pager"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    out: list[tuple[str, float, str]] = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3 or not parts[0].endswith(".service"):
            continue
        try:
            out.append((parts[0], float(parts[1]), parts[2]))
        except ValueError:
            continue
    out.sort(key=lambda row: -row[1])
    return out


def from_payload(data: dict) -> dict[str, list[str]]:
    """Validate a sandbox payload: unit -> list of directive keys."""
    if not isinstance(data, dict):
        raise SandboxError("sandbox payload is not an object")
    out: dict[str, list[str]] = {}
    for unit, keys in data.items():
        if not isinstance(unit, str) or not isinstance(keys, list):
            raise SandboxError("each entry must map a unit name to a list of directives")
        keys = [str(k) for k in keys]
        validate(unit, keys)
        out[unit] = keys
    return out


@dataclass
class Change:
    """One unit's staged drop-in."""

    unit: str
    keys: list[str] = field(default_factory=list)

    @property
    def path(self) -> str:
        return dropin_path(self.unit)

    @property
    def content(self) -> str:
        return render(self.unit, self.keys)

    @property
    def removing(self) -> bool:
        return not self.keys


def plan_changes(changes: dict[str, list[str]]) -> list[Change]:
    return [Change(unit=unit, keys=changes[unit]) for unit in sorted(changes)]
