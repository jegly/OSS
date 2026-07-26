"""File integrity — BUILD_PLAN §4.24.

Tier 1 is package verification: ``dpkg -V`` (and ``debsums -ac`` when installed)
compare every file that came from a .deb against the distro's own checksums. No
baseline, no setup, instant — but blind to anything an attacker *added* that no
package owns.

Tier 2 is a full-system AIDE baseline. It needs the ``aide`` package and a
baseline captured while the machine is still trusted, so it is offered rather
than assumed.

The part that makes Tier 1 usable rather than a wall of noise is two things:

* **Severity by where the change landed.** A changed binary in /usr/bin is not
  the same finding as a changed file in /usr/share/doc.
* **Explaining changes with apt.** Most real differences are package upgrades.
  Cross-referencing each changed file's package against /var/log/dpkg.log means
  what survives is the set with *no* package-manager event behind it — which is
  the actual signal.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

VERIFY_TIMEOUT = 300

#: Directories whose contents are executed, so a change there is code changing.
BINARY_DIRS = ("/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/lib/", "/lib/")

#: Places that exist to make something run again later — the persistence spots.
PERSISTENCE_PATTERNS = (
    "/etc/systemd/system/",
    "/lib/systemd/system/",
    "/usr/lib/systemd/system/",
    "/etc/cron",
    "/var/spool/cron/",
    "/etc/init.d/",
    "/etc/rc",
    "/etc/xdg/autostart/",
    "/etc/profile",
    "/etc/bash.bashrc",
)

#: Files that decide who may log in and what they may do.
AUTH_FILES = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/pam.conf",
    "/etc/security/",
    "/etc/pam.d/",
)

SEVERITIES = ("critical", "high", "info")

#: dpkg -V prints an rpm-style 9-character attribute string, then the path.
#: Position 2 is the checksum; '5' there means the content differs.
_VERIFY_ROW = re.compile(r"^(?P<attrs>[?\w]{9}|missing)\s+(?:c\s+)?(?P<path>/\S.*?)\s*$")

_DPKG_LOG_ROW = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<action>install|upgrade|configure|remove|purge)\s+(?P<package>\S+)"
)


@dataclass
class Finding:
    """One file that does not match what its package says it should be."""

    path: str
    attrs: str
    severity: str = "info"
    reason: str = ""
    package: str = ""
    #: Set when an apt event around this file's mtime explains the difference.
    explained_by: str = ""

    @property
    def content_changed(self) -> bool:
        return self.attrs == "missing" or (len(self.attrs) > 1 and self.attrs[1] == "5")

    @property
    def missing(self) -> bool:
        return self.attrs == "missing"

    @property
    def what(self) -> str:
        if self.missing:
            return "missing"
        parts = []
        labels = [
            (0, "size"), (1, "checksum"), (2, "mode"), (3, "device"),
            (4, "symlink"), (5, "owner"), (6, "group"), (7, "mtime"), (8, "caps"),
        ]
        for index, label in labels:
            if index < len(self.attrs) and self.attrs[index] not in "?.":
                parts.append(label)
        return ", ".join(parts) or "differs"


@dataclass
class Report:
    """Everything Tier 1 found."""

    findings: list[Finding] = field(default_factory=list)
    #: Paths the check could not read — a plain user cannot stat all of /usr.
    unreadable: int = 0
    tool: str = ""
    ran: bool = False
    error: str = ""

    def by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity and not f.explained_by]

    @property
    def explained(self) -> list[Finding]:
        return [f for f in self.findings if f.explained_by]

    @property
    def actionable(self) -> list[Finding]:
        return [f for f in self.findings if not f.explained_by]


def classify(path: str, attrs: str) -> tuple[str, str]:
    """``(severity, reason)`` from where the change landed (§4.24.3)."""
    changed = attrs == "missing" or (len(attrs) > 1 and attrs[1] == "5")

    for pattern in PERSISTENCE_PATTERNS:
        if path.startswith(pattern):
            return "critical", (
                "This is a persistence location — something here runs again on "
                "the next boot, login or timer."
            )

    if changed and any(path.startswith(d) for d in BINARY_DIRS):
        return "critical", (
            "An executable that does not match what its package shipped. This is "
            "what a trojaned binary looks like."
        )

    for auth in AUTH_FILES:
        if path.startswith(auth):
            return "high", (
                "Decides who can log in and what they can do. Changes here are "
                "often legitimate — but they should be ones you made."
            )

    if path.startswith("/etc/"):
        return "high" if changed else "info", (
            "Configuration under /etc. Editing config is normal; the question is "
            "whether you edited this one."
        )

    if not changed:
        return "info", "Only metadata differs — mode, owner or timestamp."
    return "info", "Content differs from the package."


def _run(argv: list[str]) -> tuple[int, str]:
    if shutil.which(argv[0]) is None and not Path(argv[0]).exists():
        return 127, f"{argv[0]} is not installed"
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=VERIFY_TIMEOUT, check=False
        )
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {VERIFY_TIMEOUT}s"
    except OSError as exc:
        return 127, str(exc)
    return result.returncode, result.stdout + result.stderr


def parse_verify(output: str) -> tuple[list[Finding], int]:
    """Parse ``dpkg -V`` output into findings, counting unreadable paths."""
    findings: list[Finding] = []
    unreadable = 0
    for line in output.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if "Permission denied" in line or "Operation not permitted" in line:
            unreadable += 1
            continue
        match = _VERIFY_ROW.match(line)
        if match is None:
            continue
        path = match.group("path")
        attrs = match.group("attrs")
        severity, reason = classify(path, attrs)
        findings.append(Finding(path=path, attrs=attrs, severity=severity, reason=reason))
    return findings, unreadable


def verify() -> Report:
    """Run Tier 1. Prefers debsums when present; falls back to dpkg -V."""
    report = Report()

    if shutil.which("debsums"):
        # -a includes config files, -c reports only what changed.
        code, output = _run(["debsums", "-ac"])
        report.tool = "debsums -ac"
        if code in (0, 1, 2):
            for line in output.splitlines():
                path = line.strip()
                if path.startswith("/"):
                    severity, reason = classify(path, "?5???????")
                    report.findings.append(
                        Finding(path=path, attrs="?5???????", severity=severity, reason=reason)
                    )
            report.ran = True
            return report

    code, output = _run(["dpkg", "-V"])
    report.tool = "dpkg -V"
    if code == 127:
        report.error = output
        return report
    report.findings, report.unreadable = parse_verify(output)
    report.ran = True
    return report


# --------------------------------------------------------------------------- #
#  Explaining changes with apt (§4.24.4)
# --------------------------------------------------------------------------- #


def package_for(path: str) -> str:
    """Which package owns this file, via dpkg -S."""
    code, output = _run(["dpkg", "-S", path])
    if code != 0:
        return ""
    first = output.splitlines()[0] if output.splitlines() else ""
    package, _, _ = first.partition(":")
    return package.strip()


def apt_events(log_path: str = "/var/log/dpkg.log") -> dict[str, datetime]:
    """Package -> most recent install/upgrade time, from the dpkg log."""
    events: dict[str, datetime] = {}
    try:
        text = Path(log_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return events
    for line in text.splitlines():
        match = _DPKG_LOG_ROW.match(line.strip())
        if match is None:
            continue
        package = match.group("package").split(":")[0]
        try:
            when = datetime.strptime(match.group("date"), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        if package not in events or when > events[package]:
            events[package] = when
    return events


def explain(report: Report, window_hours: int = 48) -> Report:
    """Tag findings whose package was installed or upgraded around their mtime.

    What is left after this is the set of changes with no package-manager event
    behind them — the reasoning a human does by hand, done up front.
    """
    events = apt_events()
    if not events:
        return report

    for finding in report.findings:
        if not finding.package:
            finding.package = package_for(finding.path)
        when = events.get(finding.package)
        if when is None:
            continue
        try:
            mtime = datetime.fromtimestamp(Path(finding.path).stat().st_mtime)
        except OSError:
            # A missing file has no mtime, but a recent upgrade still explains it.
            if finding.missing and datetime.now() - when < timedelta(days=30):
                finding.explained_by = f"{finding.package} changed {when:%Y-%m-%d}"
            continue
        if abs((mtime - when).total_seconds()) < window_hours * 3600:
            finding.explained_by = (
                f"explained by an apt event: {finding.package} {when:%Y-%m-%d %H:%M}"
            )
    return report


# --------------------------------------------------------------------------- #
#  Tier 2 — our own baseline: hash a set of paths, rescan later, diff (§4.24.1)
# --------------------------------------------------------------------------- #

#: Paths worth watching by default: where persistence lives (§4.24.2).
DEFAULT_WATCHED = (
    "/etc",
    "/boot",
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/lib/systemd/system",
    "/etc/systemd/system",
)

#: Volatile paths that change constantly and would drown the report.
DEFAULT_EXCLUDED = (
    "/etc/mtab",
    "/etc/adjtime",
    "/etc/machine-id",
    "/etc/resolv.conf",
    "/etc/ld.so.cache",
    "/etc/blkid.tab",
    "/etc/lvm/archive",
    "/etc/cups/subscriptions.conf",
    "/etc/apparmor.d/cache",
)

BASELINE_PATH = Path("/var/lib/hardening-gui/baseline.json")

#: Don't hash anything enormous — a baseline is about identity, not archiving.
MAX_HASH_BYTES = 64 * 1024 * 1024


@dataclass
class Entry:
    """One file's identity in the baseline."""

    sha256: str
    size: int
    mode: int
    uid: int
    gid: int
    mtime: int
    #: ctime matters: mtime is trivially forged with `touch -r`, but ctime updates
    #: whenever the inode is written and cannot be set directly. A file with a
    #: matching mtime and a changed ctime is a tampering tell (§4.24.2).
    ctime: int

    def to_list(self) -> list:
        return [self.sha256, self.size, self.mode, self.uid, self.gid, self.mtime, self.ctime]

    @classmethod
    def from_list(cls, data: list) -> "Entry":
        return cls(str(data[0]), *(int(x) for x in data[1:7]))

    def differences(self, other: "Entry") -> list[str]:
        out = []
        if self.sha256 != other.sha256:
            out.append(f"sha256 {self.sha256[:12]}… → {other.sha256[:12]}…")
        if self.mode != other.mode:
            out.append(f"mode {self.mode:04o} → {other.mode:04o}")
        if self.uid != other.uid or self.gid != other.gid:
            out.append(f"owner {self.uid}:{self.gid} → {other.uid}:{other.gid}")
        if self.size != other.size:
            out.append(f"size {self.size} → {other.size}")
        if self.mtime != other.mtime:
            out.append("mtime changed")
        if self.ctime != other.ctime and self.mtime == other.mtime:
            out.append("ctime changed but mtime did not — a tampering tell")
        return out


def hash_file(path: Path) -> str:
    """SHA-256 of a file, or a marker for what stopped us reading it."""
    import hashlib

    try:
        if path.stat().st_size > MAX_HASH_BYTES:
            return "too-large"
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return "unreadable"


def scan(
    watched: tuple[str, ...] = DEFAULT_WATCHED,
    excluded: tuple[str, ...] = DEFAULT_EXCLUDED,
    progress=None,
) -> dict[str, Entry]:
    """Walk *watched* and record each regular file's identity."""
    import os

    out: dict[str, Entry] = {}
    for root in watched:
        base = Path(root)
        if not base.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(base, onerror=lambda _e: None):
            if any(dirpath.startswith(skip) for skip in excluded):
                dirnames[:] = []
                continue
            for name in filenames:
                path = Path(dirpath) / name
                if any(str(path).startswith(skip) for skip in excluded):
                    continue
                try:
                    stat = path.lstat()
                except OSError:
                    continue
                if not (stat.st_mode & 0o170000) == 0o100000:
                    continue  # regular files only; symlink targets are hashed once
                out[str(path)] = Entry(
                    sha256=hash_file(path),
                    size=stat.st_size,
                    mode=stat.st_mode & 0o7777,
                    uid=stat.st_uid,
                    gid=stat.st_gid,
                    mtime=int(stat.st_mtime),
                    ctime=int(stat.st_ctime),
                )
            if progress is not None:
                progress(len(out))
    return out


def save_baseline(entries: dict[str, Entry], path: Path = BASELINE_PATH) -> str:
    """Write the baseline and return its own SHA-256.

    Record that hash somewhere off this machine. A baseline sitting on the same
    disk catches opportunistic malware, not someone who already has root and can
    rewrite the baseline along with the files (§4.24.5).
    """
    import hashlib
    import json as json_module
    import os

    payload = {
        "version": 1,
        "created": datetime.now().isoformat(timespec="seconds"),
        "entries": {p: e.to_list() for p, e in sorted(entries.items())},
    }
    text = json_module.dumps(payload, separators=(",", ":"))
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(text, encoding="utf-8")
    os.chmod(temp, 0o600)
    temp.replace(path)
    return hashlib.sha256(text.encode()).hexdigest()


def load_baseline(path: Path = BASELINE_PATH) -> tuple[dict[str, Entry], str]:
    """``(entries, created)``. Empty when there is no baseline yet."""
    import json as json_module

    try:
        raw = json_module.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}, ""
    entries = {
        str(p): Entry.from_list(v) for p, v in (raw.get("entries") or {}).items()
    }
    return entries, str(raw.get("created", ""))


def diff_baseline(
    baseline: dict[str, Entry], current: dict[str, Entry]
) -> list[Finding]:
    """What changed since the baseline, ranked by where it landed."""
    findings: list[Finding] = []

    for path, now in current.items():
        before = baseline.get(path)
        if before is None:
            severity, reason = classify(path, "?5???????")
            findings.append(
                Finding(
                    path=path,
                    attrs="new",
                    severity=severity,
                    reason="New file since the baseline. " + reason,
                )
            )
            continue
        differences = before.differences(now)
        if differences:
            severity, reason = classify(path, "?5???????" if before.sha256 != now.sha256 else "??2??????")
            findings.append(
                Finding(
                    path=path,
                    attrs="changed",
                    severity=severity,
                    reason="; ".join(differences),
                )
            )

    for path in baseline:
        if path not in current:
            severity, reason = classify(path, "missing")
            findings.append(
                Finding(path=path, attrs="missing", severity=severity, reason="Gone since the baseline.")
            )

    order = {"critical": 0, "high": 1, "info": 2}
    findings.sort(key=lambda f: (order.get(f.severity, 3), f.path))
    return findings


def aide_available() -> bool:
    return shutil.which("aide") is not None


def aide_baseline_path() -> Path:
    return Path("/var/lib/aide/aide.db")


def aide_baseline_age_days() -> int | None:
    """How old the AIDE baseline is, or None when there isn't one."""
    path = aide_baseline_path()
    try:
        mtime = datetime.fromtimestamp(path.stat().st_mtime)
    except OSError:
        return None
    return (datetime.now() - mtime).days
