"""The flag catalogue: sections and flags loaded from TOML data files.

This module is imported by the privileged helper as well as the GUI, so it stays
stdlib-only (``tomllib``) and never imports ``gi``.

Data layout — one file per section in ``data/catalogue``::

    [section]
    id     = "sysctl"
    title  = "sysctl.d"
    nav    = "System"
    target = "/etc/sysctl.d/99-hardening-gui.conf"
    syntax = "keyval"
    reload = [["sysctl", "--system"]]

    [[flag]]
    id = "kptr_restrict"
    ...

Everything the app knows how to write is described here; the helper compiles its
allowlist from the same files, so a flag that is not in the catalogue cannot be
applied even by a tampered GUI.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import paths

#: Risk levels, in ascending severity. Drives card borders and badges (§3).
RISKS = ("safe", "caution", "breaking", "one-way")

#: File syntaxes the renderer knows. See :mod:`hardeninggui.render`.
SYNTAXES = (
    "keyval",  # key = value          (sysctl, pwquality, faillock)
    "ini",  # [Section] Key=value  (journald, coredump, resolved, NetworkManager)
    "sshd",  # Key value            (sshd_config.d)
    "logindefs",  # KEY value            (/etc/login.defs, in-place)
    "sudoers",  # Defaults ...         (sudoers.d)
    "apt",  # Key "value";         (apt.conf.d)
    "modprobe",  # blacklist/install    (modprobe.d)
    "grub",  # cmdline + GRUB_ vars (default/grub.d)
    "services",  # systemctl mask/disable, no file
    "gsettings",  # gsettings set, no file
    "auditd",  # audit rules
    "special",  # section handled by dedicated UI + code (ufw, fstab, perms, usb)
)


class CatalogueError(Exception):
    """Malformed catalogue data. Always a packaging bug, never user input."""


@dataclass(frozen=True)
class Flag:
    """One toggleable hardening setting."""

    id: str
    section: str
    group: str
    title: str
    key: str
    value: str
    default: str
    desc: str = ""
    why: str = ""
    help: str = ""
    risk: str = "safe"
    breaks: str = ""
    reboot: bool = False
    hw: bool = False
    values: tuple[str, ...] = ()
    labels: tuple[str, ...] = ()
    #: Live values that count as *already satisfying* this flag even though they
    #: don't equal it, because they are strictly stronger — lockdown=confidentiality
    #: satisfies lockdown=integrity. Only meaningful where the ordering is real:
    #: rp_filter's "loose" is not a stronger "strict", so it lists nothing.
    satisfied_by: tuple[str, ...] = ()
    #: Values that are individually irreversible on a flag whose lower settings
    #: are not (ptrace_scope 3, lockdown=confidentiality). The review dialog gates
    #: on these the same way it gates on ``risk = "one-way"``.
    one_way_values: tuple[str, ...] = ()
    #: Live-state probe hint, e.g. "/proc/sys/kernel/kptr_restrict". Derived for
    #: sysctl flags, explicit for anything whose live value lives elsewhere.
    probe: str = ""
    #: Free-form extra directives emitted alongside this flag (modprobe softdep).
    extra: tuple[str, ...] = ()
    #: Override the section's target file. Lets one sidebar entry (e.g. "pam")
    #: write several files — pwquality.conf, faillock.conf, login.defs.
    target: str = ""
    #: Override the section's syntax, for a flag whose own target needs it.
    syntax: str = ""
    #: ``[Section]`` header when this flag's own target is an ini file.
    ini_section: str = ""
    #: Emit this key last in its file. ``kernel.modules_disabled`` has to be the
    #: final line, or the same `sysctl --system` run can't load what later keys need.
    apply_last: bool = False
    #: This flag's target is a pre-existing system file, not a drop-in we own —
    #: faillock.conf and login.defs have no drop-in directory. Undo is restoring
    #: the .bak, not deleting the file, and the banner says so.
    in_place: bool = False
    #: The user types this value (SSH AllowUsers, Port, DNS resolvers). The card
    #: shows a text entry instead of a toggle.
    editable: bool = False
    #: Anchored regex every editable value must match. Required when ``editable``.
    pattern: str = ""

    @property
    def is_choice(self) -> bool:
        """True when the card shows a dropdown instead of a toggle (§3)."""
        return bool(self.values)

    @property
    def one_way(self) -> bool:
        return self.risk == "one-way"

    def is_one_way_at(self, value: str) -> bool:
        """Whether choosing *value* is the irreversible option."""
        return self.one_way or value in self.one_way_values

    def label_for(self, value: str) -> str:
        """Human label for *value* — the dropdown text."""
        if self.values and value in self.values:
            idx = self.values.index(value)
            if idx < len(self.labels):
                return self.labels[idx]
        return value

    def value_is_allowed(self, value: str) -> bool:
        """Allowlist check. The helper's only defence against a bad payload."""
        if self.values:
            return value in self.values
        if self.editable:
            # An editable flag has no fixed value, so the pattern is the whole
            # guard: it must be present, anchored, and it must match.
            return bool(self.pattern) and re.fullmatch(self.pattern, value) is not None
        return value == self.value


@dataclass
class Section:
    """A group of flags sharing one target file and one reload command."""

    id: str
    title: str
    nav: str
    syntax: str
    target: str = ""
    reload: tuple[tuple[str, ...], ...] = ()
    desc: str = ""
    order: int = 100
    #: ``[Section]`` header for ``ini`` syntax files.
    ini_section: str = ""
    #: Optional package this section needs; absence is a degraded UI state (§1.1).
    requires_pkg: str = ""
    #: In-place edit of an existing file rather than a drop-in — needs a .bak.
    in_place: bool = False
    #: False for a section whose dedicated UI and apply logic is not built yet.
    #: The section still appears in the sidebar, showing what it will cover, and
    #: stages nothing — so it can never silently half-apply.
    implemented: bool = True
    #: BUILD_PLAN section this maps to, shown in the placeholder.
    plan_ref: str = ""
    flags: list[Flag] = field(default_factory=list)

    def target_for(self, flag: Flag) -> str:
        return flag.target or self.target

    def syntax_for(self, flag: Flag) -> str:
        return flag.syntax or self.syntax

    def ini_section_for(self, flag: Flag) -> str:
        return flag.ini_section or self.ini_section

    def targets(self) -> list[str]:
        """Every distinct file this section writes, in catalogue order."""
        out: list[str] = []
        for flag in self.flags:
            target = self.target_for(flag)
            if target and target not in out:
                out.append(target)
        if self.target and self.target not in out:
            out.append(self.target)
        return out

    @property
    def group_order(self) -> list[str]:
        """Distinct flag groups, in catalogue order."""
        seen: list[str] = []
        for flag in self.flags:
            if flag.group not in seen:
                seen.append(flag.group)
        return seen


@dataclass
class Catalogue:
    """Every section and flag the app knows about."""

    sections: list[Section] = field(default_factory=list)
    flags: dict[str, Flag] = field(default_factory=dict)

    def section(self, section_id: str) -> Section:
        for section in self.sections:
            if section.id == section_id:
                return section
        raise KeyError(section_id)

    def get(self, flag_id: str) -> Flag | None:
        return self.flags.get(flag_id)

    def nav_groups(self) -> list[tuple[str, list[Section]]]:
        """Sections bucketed under their sidebar header, in `nav` order (§7)."""
        order = ["System", "Network", "Access", "Monitoring", "Desktop"]
        buckets: dict[str, list[Section]] = {}
        for section in self.sections:
            buckets.setdefault(section.nav, []).append(section)
        known = [(nav, buckets.pop(nav)) for nav in order if nav in buckets]
        return known + sorted(buckets.items())

    def by_group(self) -> list[tuple[str, str, list[Flag]]]:
        """``(section_id, group, flags)`` in catalogue order — the Overview list."""
        out: list[tuple[str, str, list[Flag]]] = []
        for section in self.sections:
            for group in section.group_order:
                out.append(
                    (section.id, group, [f for f in section.flags if f.group == group])
                )
        return out


def _require(table: dict, key: str, where: str) -> object:
    if key not in table:
        raise CatalogueError(f"{where}: missing required key {key!r}")
    return table[key]


def _parse_flag(raw: dict, section: Section, path: Path) -> Flag:
    where = f"{path.name}:[[flag]] {raw.get('id', '?')}"
    flag_id = str(_require(raw, "id", where))
    values = tuple(str(v) for v in raw.get("values", ()))
    labels = tuple(str(v) for v in raw.get("labels", ()))
    if labels and len(labels) != len(values):
        raise CatalogueError(f"{where}: {len(labels)} labels for {len(values)} values")
    one_way_values = tuple(str(v) for v in raw.get("one_way_values", ()))
    for one_way in one_way_values:
        if values and one_way not in values:
            raise CatalogueError(f"{where}: one_way_values entry {one_way!r} not in values")
    risk = str(raw.get("risk", "safe"))
    if risk not in RISKS:
        raise CatalogueError(f"{where}: unknown risk {risk!r}")

    key = str(raw.get("key", flag_id))
    value = str(_require(raw, "value", where))
    if values and value not in values:
        raise CatalogueError(f"{where}: default selection {value!r} not in values")

    editable = bool(raw.get("editable", False))
    pattern = str(raw.get("pattern", ""))
    if editable and not pattern:
        raise CatalogueError(f"{where}: editable flags must declare a pattern")
    if pattern:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise CatalogueError(f"{where}: bad pattern: {exc}") from exc
        if value and re.fullmatch(pattern, value) is None:
            raise CatalogueError(f"{where}: default value {value!r} fails its own pattern")

    probe = str(raw.get("probe", ""))
    if not probe and section.syntax == "keyval" and section.id == "sysctl":
        probe = "/proc/sys/" + key.replace(".", "/")

    syntax = str(raw.get("syntax", ""))
    if syntax and syntax not in SYNTAXES:
        raise CatalogueError(f"{where}: unknown syntax {syntax!r}")

    return Flag(
        id=flag_id,
        section=section.id,
        group=str(raw.get("group", section.title)),
        title=str(_require(raw, "title", where)),
        key=key,
        value=value,
        default=str(raw.get("default", "")),
        desc=str(raw.get("desc", "")),
        why=str(raw.get("why", "")),
        help=str(raw.get("help", "")),
        risk=risk,
        breaks=str(raw.get("breaks", "")),
        reboot=bool(raw.get("reboot", False)),
        hw=bool(raw.get("hw", False)),
        values=values,
        labels=labels,
        satisfied_by=tuple(str(v) for v in raw.get("satisfied_by", ())),
        one_way_values=one_way_values,
        probe=probe,
        extra=tuple(str(v) for v in raw.get("extra", ())),
        target=str(raw.get("target", "")),
        syntax=syntax,
        ini_section=str(raw.get("ini_section", "")),
        apply_last=bool(raw.get("apply_last", False)),
        in_place=bool(raw.get("in_place", section.in_place)),
        editable=editable,
        pattern=pattern,
    )


def _parse_section(raw: dict, path: Path) -> Section:
    where = f"{path.name}:[section]"
    syntax = str(_require(raw, "syntax", where))
    if syntax not in SYNTAXES:
        raise CatalogueError(f"{where}: unknown syntax {syntax!r}")
    reload_cmds = tuple(
        tuple(str(part) for part in cmd) for cmd in raw.get("reload", ())
    )
    return Section(
        id=str(_require(raw, "id", where)),
        title=str(_require(raw, "title", where)),
        nav=str(raw.get("nav", "System")),
        syntax=syntax,
        target=str(raw.get("target", "")),
        reload=reload_cmds,
        desc=str(raw.get("desc", "")),
        order=int(raw.get("order", 100)),
        ini_section=str(raw.get("ini_section", "")),
        requires_pkg=str(raw.get("requires_pkg", "")),
        in_place=bool(raw.get("in_place", False)),
        implemented=bool(raw.get("implemented", True)),
        plan_ref=str(raw.get("plan_ref", "")),
    )


def load(directory: Path | None = None) -> Catalogue:
    """Load every ``*.toml`` in *directory* (default: shipped catalogue)."""
    directory = directory or paths.catalogue_dir()
    if not directory.is_dir():
        raise CatalogueError(f"catalogue directory not found: {directory}")

    catalogue = Catalogue()
    for path in sorted(directory.glob("*.toml")):
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
        section = _parse_section(_require(raw, "section", path.name), path)
        for raw_flag in raw.get("flag", ()):
            flag = _parse_flag(raw_flag, section, path)
            if flag.id in catalogue.flags:
                raise CatalogueError(f"duplicate flag id {flag.id!r} in {path.name}")
            catalogue.flags[flag.id] = flag
            section.flags.append(flag)
        catalogue.sections.append(section)

    catalogue.sections.sort(key=lambda s: (s.order, s.title))
    if not catalogue.flags:
        raise CatalogueError(f"no flags found in {directory}")
    return catalogue
