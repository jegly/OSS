"""Kernel module inventory — the debloat browser.

A stock Ubuntu kernel ships around 6,900 loadable modules and boots using about
130 of them. Every one of the rest is code the kernel will autoload if something
asks for it: plug in a device, mount an image, receive a packet for a protocol
nobody uses. That autoload path is the attack surface this section is about.

The curated modprobe section covers the families worth blacklisting on any
machine. This is the browser for everything else, the way the services page is
the browser behind the curated service flags.

Two things this module is careful about:

*Not loaded* is not the same as *not needed*. A module that has never loaded on
this boot may still be the driver for a device you plug in next week, or the
filesystem on a disk you have not mounted yet. So a module is offered as a
candidate, never asserted to be safe, and anything the running system depends on
is refused outright.

*Blacklisting is not deleting.* See DELETION_ANSWER — removing the .ko files
buys nothing over `install <mod> /bin/false` and costs you the ability to undo.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

#: Where the staged blacklist goes. Deliberately a different file from the
#: curated section's 99-oss.conf: this one is generated from a browser and can
#: get long, and keeping them apart means reverting one does not touch the other.
TARGET = "/etc/modprobe.d/98-oss-debloat.conf"

MODULE_ROOT = "/lib/modules"

#: A kernel module file, compressed or not.
_KO = re.compile(r"^(?P<name>[\w-]+)\.ko(\.(xz|gz|zst))?$")

#: modprobe matches on underscores; a hyphenated name in the file is silently
#: ignored, which is the failure this normalisation exists to prevent.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_]{1,64}$")


class ModuleError(ValueError):
    """A module name we refuse to write a blacklist line for."""


#: Subsystems where a module not being loaded right now says nothing about
#: whether you will need it. Blacklisting one of these can leave a machine with
#: no keyboard, no disk, or no way to mount its own root filesystem — and the
#: symptom appears at the next boot, not now.
CRITICAL = {
    "arch": "CPU and platform support",
    "block": "block layer",
    "crypto": "ciphers, including the one your encrypted disk uses",
    "io_uring": "core kernel I/O",
    "kernel": "core kernel",
    "lib": "kernel library code",
    "mm": "memory management",
    "virt": "virtualisation host support",
    "drivers/acpi": "power and firmware interfaces",
    "drivers/ata": "SATA and PATA storage",
    "drivers/base": "the driver model itself",
    "drivers/block": "block devices",
    "drivers/char": "core character devices",
    "drivers/gpu": "graphics — blacklisting the wrong one gives you no display",
    "drivers/hid": "keyboards and mice",
    "drivers/input": "keyboards and mice",
    "drivers/md": "software RAID and LVM",
    "drivers/nvme": "NVMe storage",
    "drivers/pci": "the PCI bus",
    "drivers/scsi": "SCSI and USB storage",
    "drivers/usb": "USB, including USB keyboards",
    "drivers/virtio": "virtual machine devices",
    "fs": "filesystems — including ones you have not mounted yet",
}

#: Subsystems that are usually dead weight on a desktop or server. Not a promise:
#: it changes the wording from "unknown" to "commonly removed", nothing more.
BLOAT = {
    "drivers/comedi": "data-acquisition cards for laboratory hardware",
    "drivers/iio": "industrial and embedded sensors",
    "drivers/media": "TV tuners, capture cards and webcams",
    "drivers/isdn": "ISDN telephony hardware",
    "drivers/staging": "unfinished drivers, explicitly not production quality",
    "drivers/infiniband": "InfiniBand fabric hardware",
    "drivers/net/wireless": "wireless chipsets other than yours",
    "drivers/bluetooth": "Bluetooth radios",
    "net/appletalk": "AppleTalk, obsolete since the 1990s",
    "net/ax25": "amateur radio packet networking",
    "net/decnet": "DECnet, obsolete",
    "net/ipx": "Novell IPX, obsolete",
    "net/rds": "RDS, a cluster interconnect protocol",
    "net/sctp": "SCTP, used almost exclusively by telecoms signalling",
    "net/tipc": "TIPC cluster messaging",
    "sound": "audio drivers for hardware you do not have",
}


@dataclass
class Module:
    """One loadable module on this kernel."""

    name: str
    path: str
    #: Path under kernel/, e.g. "drivers/media/usb".
    category: str
    size_kb: int = 0
    loaded: bool = False
    #: Modules that currently have this one open, from lsmod's "Used by".
    used_by: tuple[str, ...] = ()
    #: Filled lazily from modinfo — see describe().
    description: str = ""

    @property
    def subsystem(self) -> str:
        """The two-level category used for the risk tables."""
        parts = self.category.split("/")
        for depth in (3, 2, 1):
            key = "/".join(parts[:depth])
            if key in CRITICAL or key in BLOAT:
                return key
        return parts[0] if parts else ""

    def verdict(
        self, mounted_fstypes: frozenset[str], blacklisted_by: str | None = None
    ) -> tuple[str, str]:
        """``(level, why)`` — refused | blocked | caution | candidate.

        Order matters: the running system's own needs outrank any table, and they
        outrank the blacklist too. A module that is loaded *is* in the kernel
        whatever modprobe.d says about it — the blacklist only decides what
        happens at the next boot.

        *blacklisted_by* is the file that already stops this module loading, from
        ``probe.read_blacklists()``. Without it this browser offered modules it had
        no way of knowing were already blocked: 107 of them on a stock install,
        including everything the curated section had applied and everything the
        distro blacklists itself.
        """
        if self.loaded and self.used_by:
            return (
                "refused",
                f"Loaded and in use by {', '.join(self.used_by)}. Blacklisting it "
                f"would break them at the next boot.",
            )
        if self.loaded:
            if blacklisted_by:
                return (
                    "refused",
                    f"Already blacklisted in {blacklisted_by}, but loaded on this "
                    f"boot, so it is still in the kernel. A reboot is what applies "
                    f"it — there is nothing to stage here.",
                )
            return (
                "refused",
                "Loaded right now. Something asked for it on this boot, so it is "
                "not spare capacity.",
            )
        if self.category.startswith("fs/") and self.name in mounted_fstypes:
            return (
                "refused",
                f"{self.name} is a filesystem currently mounted on this machine.",
            )
        if blacklisted_by:
            return (
                "blocked",
                f"Already blacklisted in {blacklisted_by}, and not loaded. This one "
                f"is done — staging it again would write a second line saying the "
                f"same thing.",
            )

        subsystem = self.subsystem
        if subsystem in CRITICAL:
            return (
                "caution",
                f"Not loaded, but this is {CRITICAL[subsystem]}. Not being loaded "
                f"now does not mean it will not be needed at the next boot or the "
                f"next time hardware changes.",
            )
        if subsystem in BLOAT:
            return (
                "candidate",
                f"Not loaded. {BLOAT[subsystem].capitalize()} — commonly removed, "
                f"but check it is not your hardware first.",
            )
        return (
            "candidate",
            "Not loaded on this boot. Nothing has asked for it, which makes it a "
            "candidate — not a guarantee it is unused.",
        )


@dataclass
class Inventory:
    """Every module on this kernel, plus what the running system is using."""

    release: str = ""
    modules: dict[str, Module] = field(default_factory=dict)
    mounted_fstypes: frozenset[str] = frozenset()
    builtin: frozenset[str] = frozenset()
    #: Module -> the modprobe.d file that already blacklists it. Empty means the
    #: caller did not ask for it; read_inventory() always fills it in.
    blacklisted: dict[str, str] = field(default_factory=dict)

    @property
    def loaded_count(self) -> int:
        return sum(1 for m in self.modules.values() if m.loaded)

    def verdict_for(self, module: Module) -> tuple[str, str]:
        """This module's verdict, with the blacklist this inventory knows about."""
        return module.verdict(self.mounted_fstypes, self.blacklisted.get(module.name))

    def counts(self) -> dict[str, int]:
        out = {"refused": 0, "blocked": 0, "caution": 0, "candidate": 0}
        for module in self.modules.values():
            level, _why = self.verdict_for(module)
            out[level] = out.get(level, 0) + 1
        return out


def read_lsmod() -> dict[str, tuple[str, ...]]:
    """``{module: dependents}`` from /proc/modules.

    /proc/modules rather than the lsmod binary: same data, no subprocess, and it
    is readable without root.
    """
    out: dict[str, tuple[str, ...]] = {}
    try:
        text = Path("/proc/modules").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        # name size refcount deps...
        deps = parts[3]
        dependents = () if deps == "-" else tuple(
            d for d in deps.rstrip(",").split(",") if d
        )
        out[parts[0]] = dependents
    return out


def read_mounted_fstypes() -> frozenset[str]:
    try:
        text = Path("/proc/mounts").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return frozenset()
    return frozenset(
        parts[2] for line in text.splitlines() if len(parts := line.split()) >= 3
    )


def read_builtin(release: str) -> frozenset[str]:
    """Modules compiled into the kernel. These cannot be blacklisted at all."""
    path = Path(MODULE_ROOT) / release / "modules.builtin"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return frozenset()
    names = set()
    for line in text.splitlines():
        match = _KO.match(Path(line.strip()).name)
        if match:
            names.add(match.group("name").replace("-", "_"))
    return frozenset(names)


def read_inventory(release: str | None = None) -> Inventory:
    """Walk /lib/modules and combine it with what is loaded right now.

    Unprivileged and fast: this is a directory walk plus two /proc reads. It
    deliberately does not shell out to modinfo, which costs about 6ms per module
    and would take most of a minute across the whole tree — descriptions are
    fetched by describe() for the rows actually on screen.
    """
    # Imported here rather than at module scope, matching how branding is pulled
    # in below: this module is shared with the privileged helper, and the import
    # graph stays a tree.
    from . import probe

    release = release or os.uname().release
    inventory = Inventory(
        release=release,
        mounted_fstypes=read_mounted_fstypes(),
        builtin=read_builtin(release),
        blacklisted=probe.read_blacklists(),
    )
    loaded = read_lsmod()
    root = Path(MODULE_ROOT) / release / "kernel"
    if not root.is_dir():
        return inventory

    for dirpath, _dirnames, filenames in os.walk(root):
        category = os.path.relpath(dirpath, root)
        if category == ".":
            category = ""
        for filename in filenames:
            match = _KO.match(filename)
            if match is None:
                continue
            name = match.group("name").replace("-", "_")
            full = os.path.join(dirpath, filename)
            try:
                size_kb = os.path.getsize(full) // 1024
            except OSError:
                size_kb = 0
            inventory.modules[name] = Module(
                name=name,
                path=full,
                category=category,
                size_kb=size_kb,
                loaded=name in loaded,
                used_by=loaded.get(name, ()),
            )
    return inventory


# --------------------------------------------------------------------------- #
#  The row model behind the modprobe page
# --------------------------------------------------------------------------- #

#: A subsystem with at least this many modules gets its own group; anything
#: smaller folds into its parent. Two-level paths alone gave 244 groups, which is
#: not a list anyone scrolls; one-level gave 12, with 4,500 modules under
#: "drivers". This lands on about 50.
GROUP_THRESHOLD = 40


@dataclass
class Row:
    """One module on the page: at most one row per module name.

    *flag* is the curated catalogue entry when there is one. That is what decides
    where a toggle writes — a curated module goes to the section's own drop-in and
    can travel in a preset, everything else goes to the debloat drop-in. Before
    this existed the two lists were rendered separately and 170 modules appeared
    twice on the same page, with two controls writing to two different files.
    """

    name: str
    module: Module | None = None
    flag: object | None = None

    @property
    def curated(self) -> bool:
        return self.flag is not None

    @property
    def size_kb(self) -> int:
        return self.module.size_kb if self.module is not None else 0

    @property
    def category(self) -> str:
        if self.module is not None:
            return self.module.category
        return getattr(self.flag, "group", "") or ""


def _cut(category: str, depth: int) -> str:
    parts = [p for p in category.split("/") if p]
    return "/".join(parts[:depth]) or "kernel"


def group_key(category: str, big: set[str]) -> str:
    """Which group a kernel-tree category belongs to."""
    two = _cut(category, 2)
    return two if two in big else _cut(category, 1) + "/*"


def big_groups(categories: list[str], threshold: int = GROUP_THRESHOLD) -> set[str]:
    """Two-level subsystems large enough to stand on their own."""
    counts: dict[str, int] = {}
    for category in categories:
        key = _cut(category, 2)
        counts[key] = counts.get(key, 0) + 1
    return {key for key, count in counts.items() if count >= threshold}


def build_rows(inventory: Inventory, flags: list) -> list[Row]:
    """One row per module: curated entries in catalogue order, then the rest.

    A curated flag whose module is not on this kernel still gets a row. Writing a
    blacklist line for a name the kernel does not have is inert, but the flag is
    carried by presets and does apply on a machine that has it, so hiding it here
    would silently drop it from the section.
    """
    rows: list[Row] = []
    claimed: set[str] = set()
    for flag in flags:
        key = getattr(flag, "key", "")
        if not key or key in claimed:
            continue
        claimed.add(key)
        rows.append(Row(name=key, module=inventory.modules.get(key), flag=flag))
    for name, module in inventory.modules.items():
        if name not in claimed:
            rows.append(Row(name=name, module=module))
    return rows


def grouped(rows: list[Row]) -> list[tuple[str, list[Row]]]:
    """``[(group, rows)]`` — curated groups first, then subsystems by size.

    Curated groups keep their catalogue names and their catalogue order: they are
    the families someone came to this page looking for, and they stay at the top
    where the section used to be.
    """
    curated: dict[str, list[Row]] = {}
    others: list[Row] = []
    for row in rows:
        if row.curated:
            curated.setdefault(getattr(row.flag, "group", "") or "modules", []).append(row)
        else:
            others.append(row)

    big = big_groups([row.category for row in others])
    buckets: dict[str, list[Row]] = {}
    for row in others:
        buckets.setdefault(group_key(row.category, big), []).append(row)
    for bucket in buckets.values():
        bucket.sort(key=lambda r: (-r.size_kb, r.name))

    ordered = list(curated.items())
    ordered += sorted(buckets.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    return ordered


def describe(module: Module, timeout: int = 5) -> str:
    """One-line description from modinfo, for a module about to be shown.

    Called per visible row rather than for the whole tree. Failure is not an
    error: plenty of modules carry no description field at all.
    """
    if module.description:
        return module.description
    try:
        result = subprocess.run(
            ["/usr/sbin/modinfo", "-F", "description", module.path],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    module.description = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    return module.description


# --------------------------------------------------------------------------- #
#  Staging
# --------------------------------------------------------------------------- #


def validate(name: str) -> None:
    if not _SAFE_NAME.match(name):
        raise ModuleError(f"not a usable module name: {name!r}")


def render_blacklist(names: list[str]) -> str:
    """The drop-in for a staged selection.

    Same shape as the curated section: `blacklist` stops autoloading, and
    `install <mod> /bin/false` stops an explicit modprobe as well. /bin/false
    rather than /bin/true so a blocked load fails loudly instead of appearing to
    have worked.
    """
    from . import branding

    lines = [branding.DROPIN]
    for name in sorted(set(names)):
        validate(name)
        lines.append(f"blacklist {name}\n")
        lines.append(f"install {name} /bin/false\n")
    return "".join(lines)


def from_payload(data: object) -> list[str]:
    """Validate a debloat payload from the GUI."""
    if not isinstance(data, list):
        raise ModuleError("debloat payload is not a list")
    out = []
    for entry in data:
        if not isinstance(entry, str):
            raise ModuleError("every debloat entry must be a module name")
        validate(entry)
        out.append(entry)
    return out


#: The answer to "can I just delete them?", shown in the UI rather than buried.
DELETION_ANSWER = (
    "You can, and this app will not do it.\n\n"
    "Deleting the .ko files buys nothing that `install <mod> /bin/false` does "
    "not already buy: a blacklisted module cannot be autoloaded by a device, a "
    "filesystem, a socket family or an explicit modprobe, so it is never mapped "
    "into the kernel either way. What deletion adds is cost — the files belong "
    "to the linux-modules package, so dpkg reports the system as modified, "
    "every kernel update puts them all back, and an initramfs rebuild can fail "
    "on a module it expected to find.\n\n"
    "It is also not reversible from here. A blacklist is one file you delete to "
    "undo; a deleted driver needs the package reinstalled, which on a machine "
    "that no longer has its network driver is a rescue-media job."
)
