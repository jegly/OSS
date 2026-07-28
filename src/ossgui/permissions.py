"""Permission controller — BUILD_PLAN §4.11.

The one section where "undo" has to be a real feature: chmod has no config file
behind it, so every change is recorded to a rollback journal before it is made.

Three parts:
  * a recommended path table with current vs target mode and owner
  * the SUID/SGID audit, with per-binary guidance on what stripping costs
  * read-only scans for the things that should not be there at all
"""

from __future__ import annotations

import grp
import os
import pwd
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

JOURNAL_PATH = Path("/var/lib/oss/perms.json")

#: Recursion into any of these is unrecoverable without a reinstall (§4.11.5).
NEVER_RECURSE = (
    "/", "/usr", "/etc", "/var", "/bin", "/sbin", "/lib", "/lib64",
    "/boot/efi", "/proc", "/sys", "/dev",
)

#: Paths whose mode must not be changed, and why. Shown greyed out so it is
#: clear the app is deliberately not offering them.
DO_NOT_CHANGE = {
    "/tmp": "1777 — the sticky bit is what stops users deleting each other's files. Removing world-write breaks nearly everything.",
    "/var/tmp": "1777, same reason as /tmp.",
    "/dev/shm": "1777, same reason as /tmp.",
    "/usr/bin": "755 — never tighten or recurse here.",
    "/usr/sbin": "755 — never tighten or recurse here.",
    "/usr/lib": "755 — never tighten or recurse here.",
    "/etc/passwd": "644 — must stay world-readable or name lookup breaks.",
    "/etc/group": "644 — same.",
}


@dataclass
class Row:
    """One path in the recommended table."""

    path: str
    target_mode: int
    owner: str = "root"
    group: str = "root"
    protects: str = ""
    tier: str = "recommended"  # recommended | aggressive | do-not-change
    note: str = ""
    glob: bool = False

    #: Filled in from the filesystem.
    current_mode: int | None = None
    current_owner: str = ""
    current_group: str = ""
    exists: bool = False

    @property
    def compliant(self) -> bool:
        return self.exists and self.current_mode == self.target_mode

    @property
    def summary(self) -> str:
        if not self.exists:
            return "not present on this system"
        current = f"{self.current_mode:04o}" if self.current_mode is not None else "?"
        if self.compliant:
            return f"{current} {self.current_owner}:{self.current_group} — already correct"
        ownership = f" {self.owner}:{self.group}" if self.owner or self.group else ""
        return (
            f"{current} {self.current_owner}:{self.current_group} → "
            f"{self.target_mode:04o}{ownership}"
        )


#: §4.11.1, with the "do not change" rows kept so the reasoning is visible.
TABLE: tuple[Row, ...] = (
    Row("/boot", 0o700, protects="Kernel images and initrd — stops non-root reading or listing your boot set", tier="aggressive"),
    Row("/boot/grub/grub.cfg", 0o600, protects="Boot menu and kernel command line — hides which hardening flags are set"),
    Row("/etc/default/grub", 0o600, protects="The source file for the above"),
    Row("/etc/shadow", 0o640, group="shadow", protects="Password hashes"),
    Row("/etc/gshadow", 0o640, group="shadow", protects="Group password hashes"),
    Row("/etc/shadow-", 0o600, protects="Backup copy, often missed and left readable"),
    Row("/etc/gshadow-", 0o600, protects="Backup copy, often missed and left readable"),
    Row("/etc/sudoers", 0o440, protects="sudo refuses to run if this is group or world writable", tier="do-not-change",
        note="Already correct at 440; sudo breaks if it is anything looser."),
    Row("/etc/ssh/sshd_config", 0o600, protects="Server config — hides your auth policy and port"),
    Row("/etc/crontab", 0o600, protects="Scheduled root commands"),
    Row("/etc/cron.d", 0o700, protects="Scheduled root commands"),
    Row("/etc/cron.hourly", 0o700, protects="Scheduled root commands"),
    Row("/etc/cron.daily", 0o700, protects="Scheduled root commands"),
    Row("/etc/cron.weekly", 0o700, protects="Scheduled root commands"),
    Row("/etc/cron.monthly", 0o700, protects="Scheduled root commands"),
    Row("/etc/cron.allow", 0o600, protects="Who may schedule jobs"),
    Row("/etc/at.allow", 0o600, protects="Who may schedule jobs"),
    Row("/etc/security/opasswd", 0o600, protects="Password history — old hashes live here"),
    Row("/var/log", 0o750, group="syslog", protects="Log directory listing", tier="aggressive"),
    Row("/var/log/auth.log", 0o640, owner="syslog", group="adm", protects="Login attempts and sudo use"),
    Row("/var/log/audit", 0o700, protects="auditd requires 700; CIS checks this"),
    Row("/var/log/wtmp", 0o660, group="utmp", protects="Login history"),
    Row("/var/log/btmp", 0o660, group="utmp", protects="Failed login history"),
    Row("/var/log/lastlog", 0o660, group="utmp", protects="Last-login records"),
    Row("/root", 0o700, protects="Root's home directory"),
    Row("/etc/issue", 0o644, protects="Pre-login banner"),
    Row("/etc/issue.net", 0o644, protects="Pre-login banner"),
    # Deliberately-not-offered rows, so the reasoning is on screen.
    *(
        Row(path, 0, protects=reason, tier="do-not-change", note=reason)
        for path, reason in DO_NOT_CHANGE.items()
    ),
)


def user_rows(home: str | None = None) -> list[Row]:
    """The per-user rows, which depend on whose home directory this is."""
    home = home or os.path.expanduser("~")
    user = Path(home).name
    return [
        Row(f"{home}/.ssh", 0o700, owner=user, group=user,
            protects="ssh ignores keys in a group-writable directory"),
        Row(f"{home}/.ssh/authorized_keys", 0o600, owner=user, group=user,
            protects="Which keys can log in as you"),
        Row(f"{home}/.gnupg", 0o700, owner=user, group=user, protects="GPG keyring"),
        Row(home, 0o750, owner=user, group=user,
            protects="Stops other local users browsing your files", tier="aggressive"),
    ]


def inspect(rows: list[Row]) -> list[Row]:
    """Fill in the current mode and owner for each row.

    An owner or group this machine does not have is dropped from the row rather
    than offered: the table is written in Debian terms, and ``syslog`` (rsyslog)
    and ``shadow`` (Debian only — Fedora and Arch keep /etc/shadow root-owned)
    simply do not exist everywhere. Left in, the row proposed a chown that could
    not be performed, and the mode fix that was the point of the row went with it.
    """
    for row in rows:
        if row.owner and not known_owner(row.owner):
            row.note = (
                row.note or f"This system has no {row.owner!r} user, so only the "
                f"mode is changed."
            )
            row.owner = ""
        if row.group and not known_group(row.group):
            row.note = (
                row.note or f"This system has no {row.group!r} group, so only the "
                f"mode is changed."
            )
            row.group = ""
        try:
            stat = Path(row.path).lstat()
        except OSError:
            row.exists = False
            continue
        row.exists = True
        row.current_mode = stat.st_mode & 0o7777
        try:
            row.current_owner = pwd.getpwuid(stat.st_uid).pw_name
        except KeyError:
            row.current_owner = str(stat.st_uid)
        try:
            row.current_group = grp.getgrgid(stat.st_gid).gr_name
        except KeyError:
            row.current_group = str(stat.st_gid)
    return rows


# --------------------------------------------------------------------------- #
#  SUID / SGID audit (§4.11.2)
# --------------------------------------------------------------------------- #

#: path -> (safe to strip?, what it costs)
SUID_GUIDANCE = {
    "/usr/bin/pkexec": ("no", "This app needs it to apply anything at all."),
    "/usr/bin/sudo": ("no", "You lose privilege escalation entirely."),
    "/usr/bin/su": ("usually", "`sudo -i` covers the same ground."),
    "/usr/bin/mount": ("usually", "Only affects manual mounts as a non-root user; udisks still handles removable media."),
    "/usr/bin/umount": ("usually", "Same as mount."),
    "/usr/bin/chsh": ("yes", "You cannot change your own shell; usermod as root still works."),
    "/usr/bin/chfn": ("yes", "You cannot change your own gecos field."),
    "/usr/bin/newgrp": ("yes", "Rarely used outside multi-group setups."),
    "/usr/bin/gpasswd": ("yes", "Rarely used outside multi-group setups."),
    "/usr/bin/wall": ("yes", "Terminal broadcast messages stop working."),
    "/usr/bin/write": ("yes", "Terminal messaging stops working."),
    "/usr/bin/at": ("yes", "Only matters if you use `at`."),
    "/usr/bin/fusermount3": ("no", "Breaks FUSE — sshfs, AppImage, some file managers."),
    "/usr/bin/umount.udisks2": ("no", "Breaks removable-media unmount in the desktop."),
    "/usr/sbin/pppd": ("usually", "Only matters for dial-up or PPPoE."),
    "/usr/bin/ssh-agent": ("usually", "Agent still works; the setgid bit is for ptrace protection."),
    "/usr/bin/sg": ("usually", "Group switching, rarely used."),
    "/usr/bin/passwd": ("no", "Users cannot change their own passwords."),
    "/usr/bin/crontab": ("usually", "Users cannot manage their own cron jobs."),
}


@dataclass
class SuidBinary:
    """One setuid or setgid binary found on the filesystem."""

    path: str
    mode: int
    setuid: bool
    setgid: bool
    package: str = ""
    safe_to_strip: str = "unknown"
    consequence: str = ""

    @property
    def unpackaged(self) -> bool:
        return not self.package

    @property
    def severity(self) -> str:
        # A setuid binary no package owns is a classic persistence mechanism.
        return "critical" if self.unpackaged else "info"


def scan_suid(roots: tuple[str, ...] = ("/usr", "/bin", "/sbin", "/opt")) -> list[SuidBinary]:
    """Every setuid/setgid file under *roots*."""
    out: list[SuidBinary] = []
    for root in roots:
        base = Path(root)
        if not base.exists():
            continue
        for dirpath, _dirnames, filenames in os.walk(base, onerror=lambda _e: None):
            for name in filenames:
                path = Path(dirpath) / name
                try:
                    stat = path.lstat()
                except OSError:
                    continue
                mode = stat.st_mode
                if not (mode & 0o170000) == 0o100000:
                    continue
                setuid = bool(mode & 0o4000)
                setgid = bool(mode & 0o2000)
                if not (setuid or setgid):
                    continue
                guidance = SUID_GUIDANCE.get(str(path), ("unknown", ""))
                out.append(
                    SuidBinary(
                        path=str(path),
                        mode=mode & 0o7777,
                        setuid=setuid,
                        setgid=setgid,
                        safe_to_strip=guidance[0],
                        consequence=guidance[1],
                    )
                )
    out.sort(key=lambda b: b.path)
    return out


def annotate_packages(binaries: list[SuidBinary]) -> list[SuidBinary]:
    """Ask dpkg which package owns each binary — the unpackaged ones matter."""
    if not binaries:
        return binaries
    try:
        result = subprocess.run(
            ["dpkg", "-S", *[b.path for b in binaries]],
            capture_output=True, text=True, timeout=60, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return binaries

    owners: dict[str, str] = {}
    for line in result.stdout.splitlines():
        package, _, path = line.partition(": ")
        if path:
            owners[path.strip()] = package.split(":")[0].strip()
    for binary in binaries:
        binary.package = owners.get(binary.path, "")
    return binaries


# --------------------------------------------------------------------------- #
#  Read-only scans (§4.11.3)
# --------------------------------------------------------------------------- #


@dataclass
class Scan:
    """Results of the read-only findings scans."""

    world_writable: list[str] = field(default_factory=list)
    unowned: list[str] = field(default_factory=list)
    writable_path_dirs: list[str] = field(default_factory=list)
    readable_homes: list[str] = field(default_factory=list)
    dangerous_dotfiles: list[str] = field(default_factory=list)


def run_scans(limit: int = 200) -> Scan:
    """The read-only findings. Deliberately bounded — this walks a lot of disk."""
    scan = Scan()

    for directory in os.environ.get("PATH", "").split(":"):
        if not directory:
            continue
        try:
            stat = Path(directory).stat()
        except OSError:
            continue
        if stat.st_mode & 0o022:
            scan.writable_path_dirs.append(f"{directory} (mode {stat.st_mode & 0o777:04o})")

    home_root = Path("/home")
    if home_root.is_dir():
        try:
            for entry in home_root.iterdir():
                try:
                    mode = entry.stat().st_mode & 0o777
                except OSError:
                    continue
                if mode & 0o007:
                    scan.readable_homes.append(f"{entry} (mode {mode:04o})")
                for name in (".rhosts", ".netrc", ".forward"):
                    candidate = entry / name
                    if candidate.exists():
                        scan.dangerous_dotfiles.append(str(candidate))
        except OSError:
            pass

    for root in ("/etc", "/var", "/usr/local"):
        base = Path(root)
        if not base.is_dir():
            continue
        for dirpath, _dirnames, filenames in os.walk(base, onerror=lambda _e: None):
            if len(scan.world_writable) >= limit:
                break
            for name in filenames:
                path = Path(dirpath) / name
                try:
                    stat = path.lstat()
                except OSError:
                    continue
                if (stat.st_mode & 0o170000) != 0o100000:
                    continue
                if stat.st_mode & 0o002:
                    scan.world_writable.append(str(path))
                    if len(scan.world_writable) >= limit:
                        break
    return scan


# --------------------------------------------------------------------------- #
#  Changes and the rollback journal
# --------------------------------------------------------------------------- #

_PATH_OK = re.compile(r"^/[^\0]{0,4095}$")


class PermissionError_(ValueError):
    """A path or mode we refuse to change."""


@dataclass
class Change:
    """One staged permission change, with the before-state for rollback."""

    path: str
    mode: int
    owner: str = ""
    group: str = ""
    before_mode: int | None = None
    before_owner: str = ""
    before_group: str = ""

    @property
    def summary(self) -> str:
        before = f"{self.before_mode:04o}" if self.before_mode is not None else "?"
        return f"{self.path}: {before} → {self.mode:04o}"


def validate_change(path: str, mode: int) -> None:
    if not _PATH_OK.match(path):
        raise PermissionError_(f"not an absolute path: {path!r}")
    if ".." in Path(path).parts:
        raise PermissionError_("paths must not contain ..")
    if not 0 <= mode <= 0o7777:
        raise PermissionError_(f"not a valid mode: {mode:o}")
    if path in DO_NOT_CHANGE:
        raise PermissionError_(f"{path} must not be changed: {DO_NOT_CHANGE[path]}")
    if path in NEVER_RECURSE and path != "/root":
        raise PermissionError_(f"{path} is a system directory this app will not touch")


def resolve_ownership(owner: str, group: str) -> tuple[int, int]:
    """``(uid, gid)`` for a chown, or -1 for a name that was not given.

    Raises rather than letting ``pwd``/``grp`` throw KeyError, because the
    caller is the privileged helper mid-transaction: it needs a failure it can
    roll back from and report, not an exception that escapes the transaction.

    Which is not hypothetical. Half the recommended table names an owner or
    group that only some distributions ship — ``syslog`` comes with rsyslog,
    and a journald-only machine has no such account; neither Fedora nor Arch
    has a ``shadow`` group at all.
    """
    uid = gid = -1
    if owner:
        try:
            uid = pwd.getpwnam(owner).pw_uid
        except KeyError as exc:
            raise PermissionError_(
                f"this system has no {owner!r} user, so the owner cannot be set"
            ) from exc
    if group:
        try:
            gid = grp.getgrnam(group).gr_gid
        except KeyError as exc:
            raise PermissionError_(
                f"this system has no {group!r} group, so the group cannot be set"
            ) from exc
    return uid, gid


def known_owner(name: str) -> bool:
    """Whether this machine has such a user."""
    try:
        pwd.getpwnam(name)
    except KeyError:
        return False
    return True


def known_group(name: str) -> bool:
    try:
        grp.getgrnam(name)
    except KeyError:
        return False
    return True


def from_payload(data: dict) -> list[Change]:
    """Validate a permissions payload from the GUI."""
    if not isinstance(data, dict):
        raise PermissionError_("permissions payload is not an object")
    out = []
    for path, spec in data.items():
        if not isinstance(path, str) or not isinstance(spec, dict):
            raise PermissionError_("each entry maps a path to a mode object")
        try:
            mode = int(spec.get("mode"))
        except (TypeError, ValueError) as exc:
            raise PermissionError_(f"bad mode for {path}") from exc
        validate_change(path, mode)
        owner = str(spec.get("owner", ""))
        group = str(spec.get("group", ""))
        for name in (owner, group):
            if name and not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", name):
                raise PermissionError_(f"not a usable user or group name: {name!r}")
        # Checked here as well as at chown time so an account this machine does
        # not have is refused before a single file has been written, instead of
        # part-way through and needing a rollback to undo.
        resolve_ownership(owner, group)
        out.append(Change(path=path, mode=mode, owner=owner, group=group))
    return out


def mode_string(mode: int) -> str:
    """``0640`` → ``-rw-r-----``, for the octal picker readout."""
    bits = [
        (0o400, "r"), (0o200, "w"), (0o100, "x"),
        (0o040, "r"), (0o020, "w"), (0o010, "x"),
        (0o004, "r"), (0o002, "w"), (0o001, "x"),
    ]
    out = ["-"]
    for index, (bit, char) in enumerate(bits):
        out.append(char if mode & bit else "-")
        if index == 2 and mode & 0o4000:
            out[-1] = "s" if mode & 0o100 else "S"
        if index == 5 and mode & 0o2000:
            out[-1] = "s" if mode & 0o010 else "S"
        if index == 8 and mode & 0o1000:
            out[-1] = "t" if mode & 0o001 else "T"
    return "".join(out)
