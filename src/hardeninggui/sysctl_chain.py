"""Read the *effective* sysctl configuration, not just one file.

systemd-sysctl merges several directories. Files are collected from all of them,
sorted by filename across the whole set, and applied in that order — so a
later-sorting filename wins per key, and a file in ``/etc`` shadows a
same-named file in ``/usr/lib`` entirely.

    /etc/sysctl.d/  →  /run/sysctl.d/  →  /usr/lib/sysctl.d/  →  /etc/sysctl.conf

On Ubuntu 26.04 ``/lib`` is a symlink to ``usr/lib``, so ``/lib/sysctl.d`` and
``/usr/lib/sysctl.d`` are the same directory. That directory is the *vendor*
layer: anything customised there is replaced on the next procps or systemd
upgrade. Finding customisations there is a headline finding, not a detail.

Syntax handled, per sysctl.d(5):

* ``key = value`` — an assignment.
* ``-key = value`` — assign, but do not fail if the key does not exist.
* ``key.*.sub = value`` — a glob, expanded against the keys that exist.
* ``-key`` with no value — exclude that key from an earlier glob.
* ``key/with/slashes`` — an alternative separator, equivalent to dots.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

#: In application order. /etc/sysctl.conf is applied last of all.
DIRECTORIES = ("/etc/sysctl.d", "/run/sysctl.d", "/usr/lib/sysctl.d")
LEGACY_FILE = "/etc/sysctl.conf"

#: Where we write. Never the vendor layer (§2).
OUR_LAYER = "/etc/sysctl.d"
VENDOR_LAYER = "/usr/lib/sysctl.d"

_LINE = re.compile(r"^\s*(?P<minus>-?)(?P<key>[^\s=]+)\s*(?:=\s*(?P<value>.*?))?\s*$")


@dataclass
class Assignment:
    """One ``key = value`` line, and where it came from."""

    key: str
    value: str
    source: Path
    line_number: int
    ignore_errors: bool = False
    glob: bool = False
    exclusion: bool = False

    @property
    def in_vendor_layer(self) -> bool:
        return str(self.source).startswith(VENDOR_LAYER)


@dataclass
class KeyResult:
    """The winning value for one key, and everything that was overridden."""

    key: str
    value: str
    winner: Assignment
    overridden: list[Assignment] = field(default_factory=list)

    @property
    def duplicated(self) -> bool:
        return bool(self.overridden)

    @property
    def conflicted(self) -> bool:
        """Set more than once with *different* values — the dangerous case."""
        return any(a.value != self.value for a in self.overridden)

    @property
    def sources(self) -> list[Path]:
        return [a.source for a in self.overridden] + [self.winner.source]


@dataclass
class Chain:
    """The merged result across every layer."""

    keys: dict[str, KeyResult] = field(default_factory=dict)
    #: Assignments whose key does not exist on this kernel.
    invalid: list[Assignment] = field(default_factory=list)
    #: Files that could not be read.
    unreadable: list[tuple[Path, str]] = field(default_factory=list)

    def conflicts(self) -> list[KeyResult]:
        return [k for k in self.keys.values() if k.conflicted]

    def duplicates(self) -> list[KeyResult]:
        return [k for k in self.keys.values() if k.duplicated and not k.conflicted]

    def vendor_layer_edits(self) -> list[KeyResult]:
        """Keys whose winning assignment lives in the layer upgrades overwrite."""
        return [k for k in self.keys.values() if k.winner.in_vendor_layer]


def _normalise(key: str) -> str:
    """``net/ipv4/x`` and ``net.ipv4.x`` are the same key."""
    return key.replace("/", ".")


def _key_exists(key: str) -> bool:
    return Path("/proc/sys/" + key.replace(".", "/")).exists()


def _existing_keys() -> list[str]:
    """Every key the running kernel actually has, for glob expansion."""
    out: list[str] = []
    root = "/proc/sys"
    for dirpath, _dirnames, filenames in os.walk(root):
        prefix = dirpath[len(root) + 1 :].replace("/", ".")
        for name in filenames:
            out.append(f"{prefix}.{name}" if prefix else name)
    return out


def ordered_files() -> list[Path]:
    """Every config file, in the order systemd-sysctl applies them.

    Files are sorted by *basename* across all directories, and the first
    directory in the list that has a given basename wins — that is how a file in
    /etc shadows the same filename in /usr/lib.
    """
    by_name: dict[str, Path] = {}
    for directory in DIRECTORIES:
        base = Path(directory)
        if not base.is_dir():
            continue
        try:
            entries = sorted(base.glob("*.conf"))
        except OSError:
            continue
        for path in entries:
            by_name.setdefault(path.name, path)

    files = [by_name[name] for name in sorted(by_name)]
    legacy = Path(LEGACY_FILE)
    if legacy.is_file():
        files.append(legacy)  # applied last, so it overrides everything
    return files


def parse_file(path: Path) -> tuple[list[Assignment], str]:
    """Parse one file. Returns ``(assignments, error)``."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], str(exc)

    out: list[Assignment] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        match = _LINE.match(line)
        if match is None:
            continue
        key = _normalise(match.group("key"))
        value = match.group("value")
        minus = match.group("minus") == "-"

        if value is None:
            # `-key` with no value excludes that key from an earlier glob.
            if minus:
                out.append(
                    Assignment(key, "", path, number, ignore_errors=True, exclusion=True)
                )
            continue

        out.append(
            Assignment(
                key=key,
                value=" ".join(value.split()),
                source=path,
                line_number=number,
                ignore_errors=minus,
                glob="*" if "*" in key else False,
            )
        )
    return out, ""


def read(check_kernel: bool = True) -> Chain:
    """Merge every layer into the effective configuration."""
    chain = Chain()
    available = _existing_keys() if check_kernel else []
    excluded: set[str] = set()

    for path in ordered_files():
        assignments, error = parse_file(path)
        if error:
            chain.unreadable.append((path, error))
            continue

        for assignment in assignments:
            if assignment.exclusion:
                excluded.add(assignment.key)
                continue

            if "*" in assignment.key:
                targets = [
                    key
                    for key in fnmatch.filter(available, assignment.key)
                    if key not in excluded
                ]
            else:
                targets = [assignment.key]

            for key in targets:
                if check_kernel and not _key_exists(key):
                    # An invalid key is silently ignored by sysctl, which is how
                    # kernel.exec-shield sat in a config for years doing nothing.
                    if not assignment.ignore_errors:
                        chain.invalid.append(assignment)
                    continue

                resolved = Assignment(
                    key=key,
                    value=assignment.value,
                    source=assignment.source,
                    line_number=assignment.line_number,
                    ignore_errors=assignment.ignore_errors,
                    glob=bool(assignment.glob),
                )
                previous = chain.keys.get(key)
                if previous is None:
                    chain.keys[key] = KeyResult(key, resolved.value, resolved)
                else:
                    previous.overridden.append(previous.winner)
                    previous.winner = resolved
                    previous.value = resolved.value

    return chain


def findings(chain: Chain) -> list[tuple[str, str, str]]:
    """``(severity, title, detail)`` for the dashboard's findings list."""
    out: list[tuple[str, str, str]] = []

    for key in sorted(chain.conflicts(), key=lambda k: k.key):
        others = ", ".join(
            f"{a.source.name}:{a.line_number}={a.value}" for a in key.overridden
        )
        out.append((
            "high",
            f"{key.key} is set to conflicting values",
            f"{key.winner.source.name}:{key.winner.line_number} sets {key.value} and "
            f"wins because it sorts last. Also set by: {others}. Whichever parses "
            f"last silently wins, so the value you get is not the one you may expect.",
        ))

    seen_invalid: set[str] = set()
    for assignment in chain.invalid:
        if assignment.key in seen_invalid:
            continue
        seen_invalid.add(assignment.key)
        out.append((
            "high",
            f"{assignment.key} does not exist on this kernel",
            f"Set in {assignment.source.name}:{assignment.line_number}. sysctl "
            f"ignores unknown keys silently, so this line has never done anything.",
        ))

    vendor = chain.vendor_layer_edits()
    if vendor:
        files = sorted({k.winner.source.name for k in vendor})
        out.append((
            "high",
            f"{len(vendor)} setting(s) live in the vendor layer",
            f"These are winning from {VENDOR_LAYER}, which package upgrades "
            f"replace: {', '.join(files)}. Moving them into {OUR_LAYER} keeps them "
            f"across upgrades — same values, a layer that is yours.",
        ))

    duplicates = chain.duplicates()
    if duplicates:
        out.append((
            "info",
            f"{len(duplicates)} key(s) set more than once with the same value",
            "Harmless, but it means several files are trying to own the same "
            "setting: " + ", ".join(sorted(k.key for k in duplicates)[:8]) + "…",
        ))

    for path, error in chain.unreadable:
        out.append(("info", f"Could not read {path}", error))

    return out


def migration_selection(chain: Chain, catalogue) -> dict[str, str]:
    """Vendor-layer keys that map onto a catalogue flag, ready to re-apply from /etc.

    This is the upgrade path for a hand-hardened machine: the same values, staged
    through the app so they land in the layer that survives package upgrades.
    """
    by_key = {flag.key: flag for flag in catalogue.flags.values() if flag.section == "sysctl"}
    out: dict[str, str] = {}
    for result in chain.vendor_layer_edits():
        flag = by_key.get(result.key)
        if flag is not None and flag.value_is_allowed(result.value):
            out[flag.id] = result.value
    return out
