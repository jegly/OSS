"""Change the mode of an arbitrary path — the general half of §4.11.

The recommended table in `permissions` covers paths worth fixing on any machine.
This covers the other case: "I want *this* file locked down", which is what makes
the section general rather than a fixed checklist.

Two ways to do it, and the difference matters:

**chmod** changes the file now. On a path that belongs to a package, dpkg restores
the shipped mode the next time that package is upgraded, so the change quietly
comes undone weeks later.

**dpkg-statoverride** records the mode you want and dpkg honours it on every
future unpack. It is the durable answer for anything packaged, and its own man
page names this use case: forcing a program to be installed without its setuid
bit, or executable only by a certain group.

So for a packaged path this defaults to a statoverride and says why. For anything
dpkg does not manage, chmod is the only option and nothing will revert it.
"""

from __future__ import annotations

import grp
import pwd
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

DPKG_STATOVERRIDE = "/usr/bin/dpkg-statoverride"
DPKG_QUERY = "/usr/bin/dpkg-query"
CHATTR = "/usr/bin/chattr"

_PATH_OK = re.compile(r"^/[^\0\n]{1,4095}$")
_NAME_OK = re.compile(r"^[a-z_][a-z0-9_-]{0,31}\$?$")

#: dpkg-statoverride takes an id in place of a name when it is written with a
#: leading '#' (see its man page). That is the only way to preserve ownership
#: of a file whose uid has no passwd entry.
_NUMERIC_ID_OK = re.compile(r"^#\d{1,10}$")

#: Making any of these unreadable or non-executable takes the system with it.
#: The list is about *consequence*, not about who owns the file.
PROTECTED = {
    "/usr/bin/dpkg": "Package management. Nothing could be installed or repaired.",
    "/usr/bin/apt": "Package management.",
    "/usr/bin/apt-get": "Package management.",
    "/bin/sh": "The shell every maintainer script uses. Nothing would install.",
    "/usr/bin/sh": "The shell every maintainer script uses.",
    "/bin/bash": "The default shell.",
    "/usr/bin/bash": "The default shell.",
    "/usr/bin/sudo": "Privilege escalation — you could not undo this.",
    "/usr/bin/sudo-rs": "Privilege escalation — you could not undo this.",
    "/usr/bin/pkexec": "This app needs it to apply anything, including a repair.",
    "/usr/bin/systemctl": "Service control.",
    "/usr/lib/systemd/systemd": "Init itself. The machine would not boot.",
    "/usr/bin/chmod": "You would have no way to reverse a mode change.",
    "/usr/bin/env": "Used by the shebang of countless scripts.",
    "/usr/bin/python3": "Used by this app, and by much of the system.",
    "/usr/bin/coreutils": "The core utilities.",
    "/usr/bin/ls": "Basic inspection.",
    "/usr/bin/cat": "Basic inspection.",
}

#: Ready-made modes for the common intents, so nobody has to reason in octal.
PRESETS = [
    ("Not executable", 0o644, "Readable, but cannot be run directly."),
    ("Root only", 0o700, "Only root can read or run it."),
    ("Root executes, nobody reads", 0o700, "Same as above."),
    ("No access at all", 0o000, "Not even root can read it without changing this back."),
    ("Read-only for everyone", 0o444, "Nobody can modify it."),
    ("Drop setuid, keep working", 0o755, "Removes the setuid bit, leaves it runnable."),
]


class ModeError(ValueError):
    """A path or mode we refuse to change."""


@dataclass
class Target:
    """A path the user wants to change, and what is true about it now."""

    path: str
    exists: bool = False
    mode: int = 0
    owner: str = ""
    group: str = ""
    is_dir: bool = False
    package: str = ""
    #: An existing statoverride, if one is already recorded.
    override: str = ""
    #: Set when the owning uid/gid has no passwd or group entry, so there is
    #: no name to show or to hand to dpkg-statoverride.
    orphan_uid: int | None = None
    orphan_gid: int | None = None

    @property
    def owner_label(self) -> str:
        """What to show for the owner, naming an orphan uid as the number it is."""
        if self.owner:
            return self.owner
        if self.orphan_uid is not None:
            return f"uid {self.orphan_uid} (no such user)"
        return ""

    @property
    def group_label(self) -> str:
        if self.group:
            return self.group
        if self.orphan_gid is not None:
            return f"gid {self.orphan_gid} (no such group)"
        return ""

    @property
    def owner_spec(self) -> str:
        """What to hand dpkg-statoverride so ownership is *preserved*.

        Defaulting an orphan-owned file to root would quietly change who owns
        it while the user was only adjusting its mode, which is not what the
        dialog said it would do.
        """
        if self.owner:
            return self.owner
        if self.orphan_uid is not None:
            return f"#{self.orphan_uid}"
        return "root"

    @property
    def group_spec(self) -> str:
        if self.group:
            return self.group
        if self.orphan_gid is not None:
            return f"#{self.orphan_gid}"
        return "root"

    @property
    def packaged(self) -> bool:
        return bool(self.package)

    @property
    def protected(self) -> str:
        return PROTECTED.get(self.path, "")

    @property
    def mode_octal(self) -> str:
        return f"{self.mode:04o}"

    @property
    def mode_symbolic(self) -> str:
        return mode_string(self.mode)

    @property
    def durability_note(self) -> str:
        if self.packaged:
            return (
                f"Owned by {self.package}. A plain chmod here is undone the next "
                f"time that package is upgraded — use a statoverride so dpkg "
                f"keeps the mode you chose."
            )
        return "No package owns this, so a chmod will not be reverted by an upgrade."


def inspect(path: str) -> Target:
    """Everything readable about a path, without root."""
    validate_path(path)
    target = Target(path=path)

    location = Path(path)
    try:
        stat = location.lstat()
    except OSError:
        return target

    target.exists = True
    target.mode = stat.st_mode & 0o7777
    target.is_dir = location.is_dir()
    # An orphan uid — a file left behind by a deleted account, or one from
    # another machine's numbering — has no name to carry forward. The bare
    # number used to be stored here as if it were one, and dpkg-statoverride
    # takes names: the payload validator then rejected it and aborted the
    # *whole* apply over one file. Recorded separately instead, so the mode
    # change still goes through and ownership is simply left as it is.
    try:
        target.owner = pwd.getpwuid(stat.st_uid).pw_name
    except KeyError:
        target.owner = ""
        target.orphan_uid = stat.st_uid
    try:
        target.group = grp.getgrgid(stat.st_gid).gr_name
    except KeyError:
        target.group = ""
        target.orphan_gid = stat.st_gid

    target.package = _package_for(path)
    target.override = _existing_override(path)
    return target


def _package_for(path: str) -> str:
    if shutil.which("dpkg-query") is None:
        return ""
    try:
        result = subprocess.run(
            [DPKG_QUERY, "-S", path], capture_output=True, text=True, timeout=20, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    first = result.stdout.splitlines()[0] if result.stdout.splitlines() else ""
    return first.partition(":")[0].strip()


def _existing_override(path: str) -> str:
    if not Path(DPKG_STATOVERRIDE).exists():
        return ""
    try:
        result = subprocess.run(
            [DPKG_STATOVERRIDE, "--list", path],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


# --------------------------------------------------------------------------- #
#  Validation
# --------------------------------------------------------------------------- #


def validate_path(path: str) -> None:
    if not _PATH_OK.match(path):
        raise ModeError(f"not an absolute path: {path!r}")
    if ".." in Path(path).parts:
        raise ModeError("paths must not contain ..")


def validate_mode(mode: int) -> None:
    if not 0 <= mode <= 0o7777:
        raise ModeError(f"not a valid mode: {mode}")


def validate_owner(name: str) -> None:
    if name and not (_NAME_OK.match(name) or _NUMERIC_ID_OK.match(name)):
        raise ModeError(f"not a usable user or group name: {name!r}")


def check_allowed(path: str, mode: int) -> None:
    """Refuse the changes that would leave the machine unrepairable."""
    validate_path(path)
    validate_mode(mode)

    reason = PROTECTED.get(path)
    if reason:
        raise ModeError(f"{path} will not be changed: {reason}")

    # A directory that loses its execute bit cannot be traversed, which takes
    # everything underneath it with it — a far bigger change than it looks.
    from .permissions import NEVER_RECURSE

    if path in NEVER_RECURSE:
        raise ModeError(
            f"{path} is a system directory this app will not change. Changing its "
            f"mode affects every path underneath it."
        )


# --------------------------------------------------------------------------- #
#  Commands
# --------------------------------------------------------------------------- #


def statoverride_argv(
    path: str, mode: int, owner: str = "root", group: str = "root"
) -> list[str]:
    """Record the mode with dpkg so upgrades honour it, and apply it now."""
    check_allowed(path, mode)
    validate_owner(owner)
    validate_owner(group)
    return [
        DPKG_STATOVERRIDE,
        "--force-statoverride-add",
        # --update also chmods the file now, rather than only at next unpack.
        "--update",
        "--add",
        owner or "root",
        group or "root",
        f"{mode:04o}",
        path,
    ]


def statoverride_remove_argv(path: str) -> list[str]:
    validate_path(path)
    return [DPKG_STATOVERRIDE, "--remove", path]


def immutable_argv(path: str, on: bool) -> list[str]:
    """chattr +i. Blocks even root from modifying the file until it is cleared."""
    validate_path(path)
    return [CHATTR, "+i" if on else "-i", path]


@dataclass
class Change:
    """One staged mode change."""

    path: str
    mode: int
    owner: str = "root"
    group: str = "root"
    #: Record it with dpkg so a package upgrade does not undo it.
    durable: bool = True
    #: Set the immutable attribute as well.
    immutable: bool = False
    before_mode: int | None = None

    @property
    def summary(self) -> str:
        before = f"{self.before_mode:04o}" if self.before_mode is not None else "?"
        how = "statoverride" if self.durable else "chmod"
        return f"{self.path}: {before} → {self.mode:04o} ({how})"


def plan_commands(changes: list[Change]) -> list[tuple[list[str], str]]:
    """``(argv, why)`` for each staged change.

    A plain chmod is not a command — the helper does it with os.chmod so it can
    record the before-state in the rollback journal first. Only the durable form
    and the immutable flag need a program.
    """
    out: list[tuple[list[str], str]] = []
    for change in changes:
        if change.durable:
            out.append((
                statoverride_argv(change.path, change.mode, change.owner, change.group),
                f"record {change.path} as {change.mode:04o} so upgrades keep it",
            ))
        if change.immutable:
            out.append((
                immutable_argv(change.path, True),
                f"make {change.path} immutable — even root cannot modify it",
            ))
    return out


def from_payload(data: dict) -> list[Change]:
    """Validate a filemode payload from the GUI."""
    if not isinstance(data, dict):
        raise ModeError("filemode payload is not an object")
    out = []
    for path, spec in data.items():
        if not isinstance(path, str) or not isinstance(spec, dict):
            raise ModeError("each entry maps a path to a mode object")
        try:
            mode = int(spec.get("mode"))
        except (TypeError, ValueError) as exc:
            raise ModeError(f"bad mode for {path}") from exc
        check_allowed(path, mode)
        owner = str(spec.get("owner", "root"))
        group = str(spec.get("group", "root"))
        validate_owner(owner)
        validate_owner(group)
        out.append(
            Change(
                path=path,
                mode=mode,
                owner=owner,
                group=group,
                durable=bool(spec.get("durable", True)),
                immutable=bool(spec.get("immutable", False)),
            )
        )
    return out


def mode_string(mode: int) -> str:
    """``0640`` → ``-rw-r-----``, for the picker's readout."""
    from .permissions import mode_string as shared

    return shared(mode)

# --------------------------------------------------------------------------- #
#  Explaining a mode in words
# --------------------------------------------------------------------------- #

#: What each bit means, and how that differs between a file and a directory.
#: The directory meanings are the ones people get wrong: execute is traversal,
#: not "run", and read without execute lets you list names and nothing else.
BIT_HELP = {
    "r": (
        "Read the contents of the file.",
        "List the names inside the directory. Without execute as well, that is all "
        "you can do — you cannot look at anything in it.",
    ),
    "w": (
        "Change or overwrite the file.",
        "Create, rename and delete entries in the directory. This is what lets "
        "someone delete a file they cannot write to.",
    ),
    "x": (
        "Run the file as a program.",
        "Enter the directory and reach things inside it by name. A directory "
        "without this is unusable even if it is readable.",
    ),
}

SPECIAL_HELP = {
    "setuid": (
        "Run as the file's owner rather than as whoever started it. This is how "
        "an ordinary user runs something as root, and it is why setuid binaries "
        "are the first thing an attacker looks for. Meaningless on a directory."
    ),
    "setgid": (
        "On a file, run with the file's group. On a directory, new files inside "
        "inherit the directory's group rather than the creator's — which is how "
        "shared directories are usually set up."
    ),
    "sticky": (
        "On a directory, only the owner of a file may delete it, even if others "
        "can write to the directory. This is what makes /tmp safe to share, and "
        "why /tmp is 1777 rather than 777."
    ),
}

WHO = (("owner", 0o700, 6), ("group", 0o070, 3), ("others", 0o007, 0))


def describe_mode(mode: int, is_dir: bool = False) -> str:
    """A mode in plain words, for the picker's live readout."""
    kind = 1 if is_dir else 0
    verbs = {
        "r": ("read it", "list it")[kind],
        "w": ("change it", "add and delete things in it")[kind],
        "x": ("run it", "enter it")[kind],
    }

    lines = []
    for label, mask, shift in WHO:
        bits = (mode & mask) >> shift
        allowed = [verbs[c] for c, bit in (("r", 4), ("w", 2), ("x", 1)) if bits & bit]
        if not allowed:
            lines.append(f"{label}: no access at all")
        else:
            lines.append(f"{label}: can " + ", ".join(allowed))

    extras = []
    if mode & 0o4000:
        extras.append("runs as the owner (setuid)")
    if mode & 0o2000:
        extras.append(
            "new files inherit the group (setgid)" if is_dir else "runs as the group (setgid)"
        )
    if mode & 0o1000:
        extras.append(
            "only a file's owner can delete it (sticky)" if is_dir else "sticky bit set"
        )
    if extras:
        lines.append("also: " + "; ".join(extras))

    return "\n".join(lines)


def consequences(mode: int, target: "Target") -> list[str]:
    """Things worth saying out loud about this particular choice."""
    out = []

    if target.is_dir and not mode & 0o100:
        out.append(
            "The owner cannot enter this directory. Everything inside becomes "
            "unreachable by name, even for the owner."
        )
    if not target.is_dir and mode & 0o111 == 0 and target.mode & 0o111:
        out.append(
            "This removes execute from a file that currently has it. If it is a "
            "program, it stops running."
        )
    if mode & 0o444 and not target.is_dir and mode & 0o111 == 0:
        out.append(
            "It stays readable, so anyone who can read it can copy it elsewhere "
            "and run the copy. Use 0700 or 0000 if that matters."
        )
    if mode & 0o002:
        out.append(
            "World-writable. Any user on the machine can change this. Almost "
            "never what you want."
        )
    if mode & 0o4000 and not target.is_dir:
        out.append(
            "Setuid. Anyone who can run this runs it as "
            f"{target.owner or 'its owner'}. Only correct for a program written "
            "to expect it."
        )
    if mode == 0 :
        out.append(
            "No access for anyone. Root can still change it back, but nothing "
            "else can read or run it."
        )
    if target.packaged:
        out.append(target.durability_note)
    return out
