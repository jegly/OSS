"""AppArmor profiles — BUILD_PLAN §4.15.

Per-profile enforce/complain/disable, re-enabling profiles that ship disabled,
and the unconfined-processes-with-listening-sockets view.

`apparmor-utils` (aa-enforce, aa-complain, aa-disable) is not installed on a
stock system, so this does what those scripts do underneath instead: mode is a
symlink in one of two directories, and `apparmor_parser` reloads the result.

    enforce   no symlink anywhere      + apparmor_parser -r <profile>
    complain  /etc/apparmor.d/force-complain/<name>  + apparmor_parser -r
    disable   /etc/apparmor.d/disable/<name>         + apparmor_parser -R

What can be read without root:
  /etc/apparmor.d/                 which profiles exist
  /etc/apparmor.d/disable/         which are held disabled
  /etc/apparmor.d/force-complain/  which are forced to complain
The *live* mode of each loaded profile is in /sys/kernel/security/apparmor,
which is root-only, so it takes one privileged read.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

PROFILE_DIR = Path("/etc/apparmor.d")
DISABLE_DIR = PROFILE_DIR / "disable"
COMPLAIN_DIR = PROFILE_DIR / "force-complain"

PARSER = "/usr/sbin/apparmor_parser"
AA_STATUS = "/usr/sbin/aa-status"

MODES = ("enforce", "complain", "disable")

#: A profile *file* name. These are filenames under /etc/apparmor.d, not paths:
#: no slashes, no traversal, nothing that could point outside the directory.
_PROFILE_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}$")

#: Directories and files under /etc/apparmor.d that are not profiles.
_NOT_PROFILES = {
    "abi", "abstractions", "disable", "force-complain", "local", "tunables",
    "cache", "README",
}


class ApparmorError(ValueError):
    """A profile name or mode we refuse to act on."""


@dataclass(frozen=True)
class Profile:
    """One profile, its configured mode and its live mode."""

    name: str
    #: What the symlinks say it should be.
    configured: str = "enforce"
    #: What the kernel says it currently is, once a privileged read has happened.
    live: str = ""
    #: True when the profile is loaded into the kernel at all.
    loaded: bool = False

    @property
    def drifted(self) -> bool:
        """Configured one way, actually running another."""
        return bool(self.live) and self.live != self.configured

    @property
    def summary(self) -> str:
        if not self.live:
            return self.configured
        if self.drifted:
            return f"{self.live} (configured {self.configured})"
        return self.live


@dataclass
class State:
    """Every profile on the system."""

    profiles: list[Profile] = field(default_factory=list)
    #: Processes with a listening socket and no profile confining them.
    unconfined: list[tuple[str, str]] = field(default_factory=list)
    #: False until a privileged read has filled in live modes.
    live_loaded: bool = False
    enabled: bool = True

    def by_name(self) -> dict[str, Profile]:
        return {p.name: p for p in self.profiles}

    def counts(self) -> dict[str, int]:
        out = {mode: 0 for mode in MODES}
        for profile in self.profiles:
            key = profile.live or profile.configured
            out[key] = out.get(key, 0) + 1
        return out

    def copy(self) -> "State":
        return State(
            profiles=list(self.profiles),
            unconfined=list(self.unconfined),
            live_loaded=self.live_loaded,
            enabled=self.enabled,
        )


def validate(name: str) -> None:
    if not _PROFILE_FILE.match(name):
        raise ApparmorError(f"not a valid profile name: {name!r}")
    if name in _NOT_PROFILES:
        raise ApparmorError(f"{name} is not a profile")


def validate_mode(mode: str) -> None:
    if mode not in MODES:
        raise ApparmorError(f"unknown mode {mode!r}")


def _listdir(path: Path) -> set[str]:
    try:
        return {entry.name for entry in path.iterdir()}
    except OSError:
        return set()


def read_unprivileged() -> State:
    """Which profiles exist and how they are configured, from readable files."""
    state = State(enabled=Path("/sys/module/apparmor/parameters/enabled").exists())

    disabled = _listdir(DISABLE_DIR)
    complaining = _listdir(COMPLAIN_DIR)

    names = []
    for entry in sorted(_listdir(PROFILE_DIR)):
        if entry in _NOT_PROFILES or entry.startswith("."):
            continue
        if not _PROFILE_FILE.match(entry):
            continue
        if (PROFILE_DIR / entry).is_dir():
            continue
        names.append(entry)

    for name in names:
        if name in disabled:
            configured = "disable"
        elif name in complaining:
            configured = "complain"
        else:
            configured = "enforce"
        state.profiles.append(Profile(name=name, configured=configured))
    return state


def parse_status(output: str) -> tuple[dict[str, str], list[tuple[str, str]]]:
    """Parse ``aa-status --json`` into live modes and unconfined processes."""
    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ApparmorError(f"aa-status did not return usable JSON: {exc}") from exc

    modes: dict[str, str] = {}
    for name, mode in (data.get("profiles") or {}).items():
        # The kernel names a profile by its attachment path; the file that
        # declares it is usually named after the binary's basename.
        modes[name] = str(mode)

    unconfined: list[tuple[str, str]] = []
    processes = data.get("processes") or {}
    for name, entries in processes.items():
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue
            if entry.get("status") == "unconfined":
                unconfined.append((str(entry.get("pid", "?")), name))
    return modes, unconfined


def match_live(state: State, modes: dict[str, str]) -> State:
    """Attach live modes to the configured profile list.

    The kernel keys profiles by attachment path (/usr/bin/foo) while the files
    are named after the binary (usr.bin.foo, or just foo), so matching is by
    basename with the dotted-path form also considered.
    """
    lookup: dict[str, str] = {}
    for key, mode in modes.items():
        lookup[key] = mode
        lookup[key.rsplit("/", 1)[-1]] = mode
        lookup[key.strip("/").replace("/", ".")] = mode

    updated = []
    for profile in state.profiles:
        stem = profile.name.rsplit(".", 1)[-1]
        live = lookup.get(profile.name) or lookup.get(stem) or ""
        updated.append(
            Profile(
                name=profile.name,
                configured=profile.configured,
                live=live,
                loaded=bool(live),
            )
        )
    state.profiles = updated
    state.live_loaded = True
    return state


@dataclass
class Change:
    """One staged mode change, as the file operations it becomes."""

    name: str
    mode: str
    #: Symlinks to create: (link path, target path).
    create: list[tuple[str, str]] = field(default_factory=list)
    #: Symlinks to remove.
    remove: list[str] = field(default_factory=list)
    #: The reload command for this profile.
    command: list[str] = field(default_factory=list)
    why: str = ""


def plan_change(name: str, mode: str) -> Change:
    """Turn "set profile X to mode Y" into symlink operations plus a reload."""
    validate(name)
    validate_mode(mode)

    profile_path = str(PROFILE_DIR / name)
    disable_link = str(DISABLE_DIR / name)
    complain_link = str(COMPLAIN_DIR / name)

    change = Change(name=name, mode=mode)
    if mode == "enforce":
        change.remove = [disable_link, complain_link]
        change.command = [PARSER, "-r", "-W", profile_path]
        change.why = f"enforce {name}"
    elif mode == "complain":
        change.remove = [disable_link]
        change.create = [(complain_link, profile_path)]
        change.command = [PARSER, "-r", "-W", profile_path]
        change.why = f"complain {name} — violations are logged and allowed"
    else:
        change.remove = [complain_link]
        change.create = [(disable_link, profile_path)]
        # -R unloads it; without this the profile keeps enforcing until reboot.
        change.command = [PARSER, "-R", profile_path]
        change.why = f"disable {name} — unloaded from the kernel"
    return change


def plan_changes(changes: dict[str, str]) -> list[Change]:
    return [plan_change(name, changes[name]) for name in sorted(changes)]


def from_payload(data: dict) -> dict[str, str]:
    """Validate an apparmor payload from the GUI."""
    if not isinstance(data, dict):
        raise ApparmorError("apparmor payload is not an object")
    out: dict[str, str] = {}
    for name, mode in data.items():
        if not isinstance(name, str) or not isinstance(mode, str):
            raise ApparmorError("profile names and modes must both be strings")
        validate(name)
        validate_mode(mode)
        out[name] = mode
    return out


def read_status_output() -> str | None:
    """`aa-status --json`, or None when it cannot be run."""
    if not Path(AA_STATUS).exists() and shutil.which("aa-status") is None:
        return None
    try:
        result = subprocess.run(
            [AA_STATUS, "--json"], capture_output=True, text=True, timeout=20, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None
