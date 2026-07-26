"""Filesystem mount options — BUILD_PLAN §4.10.

The highest brick risk in the app: a bad line in /etc/fstab drops you to an
emergency shell at boot, with no GUI to fix it from.

The mitigation is that nothing is written until the exact option set has been
proved to work on the running system. The helper runs
``mount -o remount,<opts> <mount>`` first and refuses to write any entry whose
live remount fails — so an option combination the kernel or the filesystem
rejects never reaches fstab.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

FSTAB = "/etc/fstab"
MOUNT = "/usr/bin/mount"

#: The options this section offers. Anything else in an existing line is left
#: exactly as it is — we add and remove only from this set.
HARDENING_OPTIONS = ("nodev", "nosuid", "noexec", "ro")

OPTION_HELP = {
    "nodev": ("No device files", "Stops a device node on this filesystem being used to reach raw hardware"),
    "nosuid": ("Ignore setuid bits", "A setuid binary placed here cannot gain privileges"),
    "noexec": ("Nothing executes", "Code dropped here cannot be run directly"),
    "ro": ("Read-only", "Nothing on this filesystem can be modified at all"),
}

#: Per-mount recommendations from §4.10, with what each one is likely to break.
RECOMMENDED = {
    "/tmp": (("nodev", "nosuid", "noexec"), "noexec on /tmp breaks some installers, DKMS builds and Steam"),
    "/var/tmp": (("nodev", "nosuid", "noexec"), "Same class of breakage as /tmp, less often hit"),
    "/dev/shm": (("nodev", "nosuid", "noexec"), "noexec here breaks some JIT and sandbox implementations"),
    "/home": (("nodev", "nosuid"), "noexec on /home would stop you running anything you built or downloaded"),
    "/var": (("nodev", "nosuid"), ""),
    "/var/log": (("nodev", "nosuid", "noexec"), ""),
    "/var/log/audit": (("nodev", "nosuid", "noexec"), ""),
    "/boot": (("nodev", "nosuid", "noexec"), ""),
    "/boot/efi": (("nodev", "nosuid", "noexec"), ""),
}

#: Mounts we will not touch — remounting these read-only or noexec mid-session
#: takes the machine down with it.
NEVER_TOUCH = ("/", "/proc", "/sys", "/dev", "/run", "/usr")

_FIELD_OK = re.compile(r"^[^\s#]+$")
_OPTION_OK = re.compile(r"^[A-Za-z0-9_.,=:+/@-]{1,256}$")


class FstabError(ValueError):
    """An entry we refuse to write."""


@dataclass
class Entry:
    """One line of /etc/fstab."""

    device: str
    mount: str
    fstype: str
    options: str
    dump: str = "0"
    passno: str = "0"
    line_number: int = 0
    raw: str = ""

    @property
    def option_list(self) -> list[str]:
        return [o for o in self.options.split(",") if o]

    def has(self, option: str) -> bool:
        return option in self.option_list

    @property
    def recommended(self) -> tuple[str, ...]:
        return RECOMMENDED.get(self.mount, ((), ""))[0]

    @property
    def caveat(self) -> str:
        return RECOMMENDED.get(self.mount, ((), ""))[1]

    @property
    def touchable(self) -> bool:
        return self.mount not in NEVER_TOUCH and self.fstype not in ("swap", "proc", "sysfs")

    @property
    def missing_recommended(self) -> list[str]:
        return [o for o in self.recommended if not self.has(o)]

    def with_options(self, wanted: set[str]) -> str:
        """This entry's option string with the hardening set replaced by *wanted*."""
        kept = [o for o in self.option_list if o not in HARDENING_OPTIONS]
        merged = kept + [o for o in HARDENING_OPTIONS if o in wanted]
        return ",".join(merged) or "defaults"

    def rendered(self, wanted: set[str]) -> str:
        return "\t".join(
            [self.device, self.mount, self.fstype, self.with_options(wanted),
             self.dump, self.passno]
        )


def parse(text: str) -> list[Entry]:
    """Parse fstab, keeping line numbers so the diff can point at them."""
    entries: list[Entry] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        entries.append(
            Entry(
                device=parts[0],
                mount=parts[1],
                fstype=parts[2],
                options=parts[3],
                dump=parts[4] if len(parts) > 4 else "0",
                passno=parts[5] if len(parts) > 5 else "0",
                line_number=number,
                raw=raw,
            )
        )
    return entries


def read() -> list[Entry]:
    try:
        return parse(Path(FSTAB).read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return []


def validate_options(options: set[str]) -> None:
    for option in options:
        if option not in HARDENING_OPTIONS:
            raise FstabError(f"{option!r} is not one of the options this section manages")


def render_fstab(current: str, changes: dict[str, set[str]]) -> str:
    """Rewrite fstab with the staged option sets, leaving everything else alone."""
    entries = {e.mount: e for e in parse(current)}
    for mount, options in changes.items():
        if mount not in entries:
            raise FstabError(f"no fstab entry for {mount}")
        if not entries[mount].touchable:
            raise FstabError(f"{mount} is not a mount this app will change")
        validate_options(options)

    out: list[str] = []
    for raw in current.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            out.append(raw)
            continue
        parts = line.split()
        if len(parts) < 4 or parts[1] not in changes:
            out.append(raw)
            continue
        entry = entries[parts[1]]
        rendered = entry.rendered(changes[parts[1]])
        if not _OPTION_OK.match(rendered.split("\t")[3]):
            raise FstabError(f"refusing to write malformed options for {parts[1]}")
        out.append(rendered)
    return "\n".join(out) + "\n"


def remount_argv(mount: str, options: set[str], entry: Entry) -> list[str]:
    """The live remount that must succeed before fstab is written."""
    if not _FIELD_OK.match(mount):
        raise FstabError(f"not a usable mount point: {mount!r}")
    validate_options(options)
    return [MOUNT, "-o", f"remount,{entry.with_options(options)}", mount]


def from_payload(data: dict) -> dict[str, set[str]]:
    """Validate an fstab payload from the GUI."""
    if not isinstance(data, dict):
        raise FstabError("fstab payload is not an object")
    out: dict[str, set[str]] = {}
    for mount, options in data.items():
        if not isinstance(mount, str) or not isinstance(options, list):
            raise FstabError("each entry maps a mount point to a list of options")
        if mount in NEVER_TOUCH:
            raise FstabError(f"{mount} is not a mount this app will change")
        chosen = {str(o) for o in options}
        validate_options(chosen)
        out[mount] = chosen
    return out
