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

#: What is mounted right now, with the options the kernel is actually enforcing.
#: fstab is a request made at boot; this is the answer. They drift — someone
#: remounts by hand, a unit mounts something fstab never mentions, or an entry
#: was edited and never remounted — and until you can see both, a hardened line
#: in fstab looks like a hardened filesystem when it may be neither.
PROC_MOUNTS = "/proc/mounts"

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


# --------------------------------------------------------------------------- #
#  Live state
# --------------------------------------------------------------------------- #


@dataclass
class LiveMount:
    """One line of /proc/mounts — a filesystem as the kernel has it now."""

    device: str
    mount: str
    fstype: str
    options: str

    @property
    def option_list(self) -> list[str]:
        return [o for o in self.options.split(",") if o]

    def has(self, option: str) -> bool:
        return option in self.option_list

    @property
    def hardening(self) -> set[str]:
        """Just the options this section manages."""
        return set(self.option_list) & set(HARDENING_OPTIONS)


def _unescape(field: str) -> str:
    """Undo the octal escaping /proc/mounts uses for space, tab, newline and \\."""
    out: list[str] = []
    index = 0
    while index < len(field):
        char = field[index]
        if char == "\\" and index + 3 < len(field) and field[index + 1:index + 4].isdigit():
            try:
                out.append(chr(int(field[index + 1:index + 4], 8)))
                index += 4
                continue
            except ValueError:
                pass
        out.append(char)
        index += 1
    return "".join(out)


def parse_mounts(text: str) -> dict[str, LiveMount]:
    """Parse /proc/mounts, keyed by mount point.

    A mount point can appear more than once when something is mounted over the
    top of it. The last line wins, because that is the filesystem you reach when
    you open a path there.
    """
    live: dict[str, LiveMount] = {}
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) < 4:
            continue
        mount = _unescape(parts[1])
        live[mount] = LiveMount(
            device=_unescape(parts[0]),
            mount=mount,
            fstype=parts[2],
            options=parts[3],
        )
    return live


def read_live() -> dict[str, LiveMount]:
    """What is mounted right now. Unprivileged — /proc/mounts is world-readable."""
    try:
        return parse_mounts(Path(PROC_MOUNTS).read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return {}


def drift(entries: list[Entry], live: dict[str, LiveMount]) -> dict[str, tuple[set[str], set[str]]]:
    """``{mount: (in fstab, live)}`` for entries where the two disagree.

    Only the options this section manages are compared: fstab saying ``defaults``
    while the kernel reports ``rw,relatime`` is not drift, it is the same thing
    spelled differently.
    """
    out: dict[str, tuple[set[str], set[str]]] = {}
    for entry in entries:
        if not entry.touchable:
            continue
        mounted = live.get(entry.mount)
        if mounted is None:
            continue  # not mounted at all; reported separately
        wanted = set(entry.option_list) & set(HARDENING_OPTIONS)
        if wanted != mounted.hardening:
            out[entry.mount] = (wanted, mounted.hardening)
    return out


def unmounted(entries: list[Entry], live: dict[str, LiveMount]) -> list[str]:
    """fstab entries that are not mounted right now."""
    return [e.mount for e in entries if e.touchable and e.mount not in live]


def unlisted(entries: list[Entry], live: dict[str, LiveMount]) -> list[LiveMount]:
    """Mounted filesystems with no fstab entry, where hardening is recommended.

    /dev/shm and /run are the ones that matter: systemd mounts them and most
    machines have no fstab line for either, so a page built only from fstab
    silently omits two of the filesystems §4.10 most wants hardened.
    """
    known = {e.mount for e in entries}
    return [
        mount
        for name, mount in sorted(live.items())
        if name not in known and name in RECOMMENDED and name not in NEVER_TOUCH
    ]


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
