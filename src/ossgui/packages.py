"""Installed packages, and removing them — the cascade shown first.

Removal only. There is no install path here on purpose: installing is what apt and
the software centre are for, and a hardening tool that installs things is a
hardening tool with a supply chain.

The whole risk in removing a package is what comes with it. `libgtk-3-0t64` looks
like one library and takes 64 packages with it on a desktop. So nothing is
described to the user as "remove one package": every selection is put through
apt's own resolver first, with `apt-get --simulate`, and what comes back is the
actual list. That is the same resolution Synaptic gets from libapt-pkg, obtained
without depending on python3-apt.

Everything here reads unprivileged, including the simulation.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field

APT_GET = "/usr/bin/apt-get"
DPKG_QUERY = "/usr/bin/dpkg-query"
APT_MARK = "/usr/bin/apt-mark"

#: Debian policy: package names are lowercase alphanumerics plus + - . and may
#: carry an architecture qualifier.
_NAME = re.compile(r"^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?$")

#: Removing one of these does not break a feature, it breaks the system — you
#: lose dpkg, or apt, or the shell. Never offered, whatever the user asks.
NEVER_REMOVE_PRIORITIES = ("required",)

#: Removing these is possible and occasionally right, but it takes a large,
#: obvious thing with it.
HEAVY = {
    "ubuntu-desktop": "The entire desktop metapackage.",
    "ubuntu-desktop-minimal": "The desktop metapackage.",
    "gnome-shell": "The desktop shell — you would boot to a console.",
    "gdm3": "The graphical login screen.",
    "systemd": "Init. The machine will not boot.",
    "network-manager": "All managed networking.",
    "snapd": "Every snap, including Firefox on a stock install.",
    "xorg": "The X server.",
    "linux-generic": "The kernel metapackage — no future kernel updates.",
    "grub-efi-amd64": "The bootloader. The machine will not boot.",
    "grub-common": "The bootloader.",
    "policykit-1": "Privilege escalation for desktop apps, including this one.",
    "polkitd": "Privilege escalation for desktop apps, including this one.",
    "sudo": "Privilege escalation.",
    "sudo-rs": "Privilege escalation.",
}


class PackageError(ValueError):
    """A package name or removal we refuse to act on."""


@dataclass(frozen=True)
class Package:
    """One installed package."""

    name: str
    version: str
    summary: str = ""
    priority: str = "optional"
    essential: bool = False
    size_kb: int = 0
    #: True when the user asked for this, rather than it arriving as a dependency.
    manual: bool = False
    section: str = ""

    @property
    def removable(self) -> bool:
        return not self.essential and self.priority not in NEVER_REMOVE_PRIORITIES

    @property
    def refusal(self) -> str:
        if self.essential:
            return (
                "Marked Essential by the distribution. Removing it breaks the "
                "system outright, so it is not offered."
            )
        if self.priority in NEVER_REMOVE_PRIORITIES:
            return (
                f"Priority '{self.priority}' — part of the base system. Not offered."
            )
        return ""

    @property
    def warning(self) -> str:
        return HEAVY.get(self.name, "")

    @property
    def size(self) -> str:
        if self.size_kb >= 1024:
            return f"{self.size_kb / 1024:.1f} MB"
        return f"{self.size_kb} kB"


@dataclass
class Cascade:
    """What apt says would actually happen."""

    requested: list[str] = field(default_factory=list)
    #: Everything apt would remove, requested packages included.
    removing: list[str] = field(default_factory=list)
    #: Packages left behind that nothing needs any more.
    autoremovable: list[str] = field(default_factory=list)
    freed_kb: int = 0
    error: str = ""

    @property
    def collateral(self) -> list[str]:
        """Removals the user did not ask for — the part worth reading."""
        return [p for p in self.removing if p not in self.requested]

    @property
    def ok(self) -> bool:
        return not self.error

    def blocked_by(self, packages: dict[str, Package]) -> list[str]:
        """Anything in the cascade that must never be removed."""
        out = []
        for name in self.removing:
            package = packages.get(name)
            if package is not None and not package.removable:
                out.append(name)
        return out


def available() -> bool:
    return shutil.which("dpkg-query") is not None


def _run(argv: list[str], timeout: int = 120) -> str | None:
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    # apt-get --simulate exits non-zero when it refuses; the output still explains.
    return result.stdout + result.stderr


def read_installed() -> dict[str, Package]:
    """Every installed package with its short description. Unprivileged."""
    if not available():
        return {}

    fmt = (
        "${Package}\\t${Version}\\t${Installed-Size}\\t${Priority}\\t"
        "${Essential}\\t${Section}\\t${binary:Summary}\\n"
    )
    output = _run([DPKG_QUERY, "-W", "-f=" + fmt]) or ""

    manual: set[str] = set()
    marked = _run([APT_MARK, "showmanual"])
    if marked:
        manual = {line.strip() for line in marked.splitlines() if line.strip()}

    out: dict[str, Package] = {}
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 7 or not _NAME.match(parts[0]):
            continue
        try:
            size = int(parts[2]) if parts[2].strip() else 0
        except ValueError:
            size = 0
        out[parts[0]] = Package(
            name=parts[0],
            version=parts[1],
            size_kb=size,
            priority=parts[3] or "optional",
            essential=parts[4].strip() == "yes",
            section=parts[5],
            summary=parts[6],
            manual=parts[0] in manual,
        )
    return out


_REMV = re.compile(r"^Remv\s+(?P<name>\S+)")
_FREED = re.compile(r"After this operation, ([\d.]+) ([kMG])B disk space will be freed")


def simulate_removal(names: list[str], purge: bool = False) -> Cascade:
    """Ask apt what removing these would actually do. Needs no root.

    This is the whole safety mechanism: the answer comes from apt's own
    dependency resolution, not from anything this app works out for itself.
    """
    cascade = Cascade(requested=sorted(names))
    if not names:
        return cascade
    for name in names:
        validate(name)

    argv = [APT_GET, "--simulate", "purge" if purge else "remove", *sorted(names)]
    output = _run(argv)
    if output is None:
        cascade.error = "apt-get could not be run"
        return cascade

    # An apt error is a line *starting* with "E:". Matching "E:" anywhere in the
    # output is not the same thing: apt's own notes contain it, so a substring
    # check bailed out early and returned an empty cascade — making a 64-package
    # removal look like it would touch nothing at all.
    errors = [l for l in output.splitlines() if l.startswith("E:")]
    if errors:
        cascade.error = errors[0]
        return cascade
    if "Unable to locate package" in output:
        cascade.error = "apt does not know that package"
        return cascade

    for line in output.splitlines():
        match = _REMV.match(line.strip())
        if match:
            cascade.removing.append(match.group("name"))

    # apt prints no "disk space will be freed" line under --simulate, so the size
    # is summed from the installed sizes dpkg already told us. Reporting 0 would
    # read as "this frees nothing", which is worse than not showing a figure.
    freed = _FREED.search(output)
    if freed:
        value, unit = float(freed.group(1)), freed.group(2)
        cascade.freed_kb = int(value * {"k": 1, "M": 1024, "G": 1024 * 1024}[unit])
    else:
        installed = read_installed()
        cascade.freed_kb = sum(
            installed[name].size_kb for name in cascade.removing if name in installed
        )

    # apt lists no-longer-needed packages in a paragraph of its own.
    if "no longer required" in output:
        collecting = False
        for line in output.splitlines():
            if "no longer required" in line:
                collecting = True
                continue
            if collecting:
                if not line.startswith(" "):
                    break
                cascade.autoremovable.extend(line.split())
    return cascade


def validate(name: str) -> None:
    if not _NAME.match(name):
        raise PackageError(f"not a valid package name: {name!r}")


def to_argv(names: list[str], purge: bool = False) -> list[str]:
    """The removal command. Non-interactive, and never with --force anything.

    Deliberately *without* ``--no-remove``. That flag reads like "do not let
    this cascade", but what it actually means is "abort if anything at all
    would be removed" — which is every removal, including the one being asked
    for. With it present apt answered `E: Packages need to be removed but
    remove is disabled.` for every selection, exit 100, so the section could
    never remove a single package and took the whole transaction down with it.

    The guard it was standing in for is in :func:`from_payload`, which re-runs
    apt's resolution as root and refuses if the cascade has swept up anything
    protected. Essential packages need ``--allow-remove-essential``, which is
    never passed, so apt refuses those on its own.
    """
    if not names:
        raise PackageError("nothing to remove")
    for name in names:
        validate(name)
    return [
        APT_GET,
        "--yes",
        "purge" if purge else "remove",
        *sorted(names),
    ]


def plan_commands(names: list[str], purge: bool = False) -> list[tuple[list[str], str]]:
    if not names:
        return []
    verb = "purge" if purge else "remove"
    return [(to_argv(names, purge), f"{verb} {len(names)} package(s)")]


def from_payload(data: dict) -> tuple[list[str], bool]:
    """Validate a packages payload from the GUI."""
    if not isinstance(data, dict):
        raise PackageError("packages payload is not an object")
    names = data.get("remove", [])
    if not isinstance(names, list) or not names:
        raise PackageError("no packages listed for removal")

    installed = read_installed()
    out = []
    for name in names:
        if not isinstance(name, str):
            raise PackageError("package names must be strings")
        validate(name)
        package = installed.get(name)
        if package is None:
            raise PackageError(f"{name} is not installed")
        if not package.removable:
            raise PackageError(f"{name}: {package.refusal}")
        out.append(name)

    # Re-run the resolution as root and refuse if it now sweeps up something
    # protected — the set can differ from what the GUI simulated.
    cascade = simulate_removal(out, purge=bool(data.get("purge")))
    if not cascade.ok:
        raise PackageError(f"apt refused the removal: {cascade.error}")
    blocked = cascade.blocked_by(installed)
    if blocked:
        raise PackageError(
            "this removal would also take protected packages with it: "
            + ", ".join(sorted(blocked)[:6])
        )
    return sorted(out), bool(data.get("purge"))
