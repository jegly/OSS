"""Turn a selection of flags into file contents and commands.

Shared by the GUI (to build the review diff) and by the helper (to do the actual
writing), so both are guaranteed to agree about what Apply means. Stdlib only.

A *selection* is ``{flag_id: value}``. A flag absent from the selection is not
set; when a section ends up with no selected flags its drop-in is **removed**,
which is exactly the "undo is file deletion" model of §8.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from . import probe
from .catalogue import Catalogue, Flag, Section

BANNER = (
    "# Managed by hardening-gui. Do not edit by hand.\n"
    "# Delete this file to revert this section to stock.\n"
)

#: For targets that are pre-existing system files rather than drop-ins we own.
#: Deleting one of these does not revert anything — restoring the .bak does.
IN_PLACE_BANNER = (
    "# Managed by hardening-gui. Do not edit by hand.\n"
    "# The original file was saved alongside this one as .bak — restore it to revert.\n"
)

#: Commands the helper is allowed to run. Anything else is rejected, so a
#: tampered payload cannot turn the helper into a shell.
ALLOWED_COMMANDS = frozenset(
    {
        "/usr/sbin/sysctl",
        "/usr/sbin/depmod",
        "/usr/sbin/update-grub",
        "/usr/sbin/update-initramfs",
        "/usr/bin/systemctl",
        "/usr/sbin/ufw",
        "/usr/sbin/sshd",
        "/usr/sbin/visudo",
        "/usr/sbin/auditctl",
        "/usr/sbin/augenrules",
        "/usr/bin/mount",
        "/usr/bin/update-desktop-database",
        "/usr/sbin/apparmor_parser",
        "/usr/sbin/aa-status",
    }
)


class RenderError(Exception):
    """A selection we refuse to turn into file content."""


@dataclass
class FileWrite:
    """One target file to create or replace."""

    path: str
    content: str
    mode: int = 0o644
    #: In-place edit of a pre-existing file — the helper keeps a .bak forever.
    in_place: bool = False
    section: str = ""


@dataclass
class FileRemove:
    """A drop-in to delete because its section has nothing selected."""

    path: str
    section: str = ""


@dataclass
class Command:
    """A post-write command. ``user`` commands run unprivileged, in the GUI."""

    argv: tuple[str, ...]
    why: str = ""
    user: bool = False

    def __str__(self) -> str:
        return shlex.join(self.argv)


@dataclass
class Plan:
    """Everything one Apply transaction will do."""

    writes: list[FileWrite] = field(default_factory=list)
    removes: list[FileRemove] = field(default_factory=list)
    commands: list[Command] = field(default_factory=list)
    user_commands: list[Command] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not (self.writes or self.removes or self.commands or self.user_commands)

    def touched_paths(self) -> list[str]:
        """Files this transaction writes — the scope for an AIDE update (§4.24.6)."""
        return [w.path for w in self.writes] + [r.path for r in self.removes]


def _selected(section: Section, selection: dict[str, str]) -> list[tuple[Flag, str]]:
    return [(f, selection[f.id]) for f in section.flags if f.id in selection]


# --------------------------------------------------------------------------- #
# Per-syntax body renderers. Each returns the file body without the banner.
# --------------------------------------------------------------------------- #


def _body_keyval(pairs: list[tuple[Flag, str]]) -> str:
    # kernel.modules_disabled has to be the last line in the file: once it is set,
    # `sysctl --system` can no longer load anything a later key needs (§4.1).
    ordered = sorted(pairs, key=lambda pair: pair[0].apply_last)
    return "".join(f"{flag.key} = {value}\n" for flag, value in ordered)


def _body_ini(pairs: list[tuple[Flag, str]], default_header: str) -> str:
    """Grouped ``[Header]`` / ``Key=value`` blocks.

    One file can carry several headers — NetworkManager needs ``[device]`` and
    ``[connection]`` side by side — so keys are bucketed by their own header,
    in first-appearance order.
    """
    buckets: dict[str, list[str]] = {}
    for flag, value in pairs:
        header = flag.ini_section or default_header
        buckets.setdefault(header, []).append(f"{flag.key}={value}\n")
    out = []
    for header, lines in buckets.items():
        if header:
            out.append(f"[{header}]\n")
        out.extend(lines)
        out.append("\n")
    return "".join(out).rstrip("\n") + "\n"


def _body_sshd(pairs: list[tuple[Flag, str]]) -> str:
    return "".join(f"{flag.key} {value}\n" for flag, value in pairs)


def _body_sudoers(pairs: list[tuple[Flag, str]]) -> str:
    lines = []
    for flag, value in pairs:
        # A bare directive (use_pty, !visiblepw) carries its whole text in `key`
        # and an empty `value`; everything else is key=value.
        lines.append(f"Defaults {flag.key}\n" if value == "" else f"Defaults {flag.key}={value}\n")
    return "".join(lines)


def _body_apt(pairs: list[tuple[Flag, str]]) -> str:
    lines = []
    for flag, value in pairs:
        # A brace-delimited value is an apt list and must not be quoted.
        rendered = value if value.startswith("{") else f'"{value}"'
        lines.append(f"{flag.key} {rendered};\n")
    return "".join(lines)


def _body_modprobe(pairs: list[tuple[Flag, str]]) -> str:
    lines = []
    for flag, value in pairs:
        if value != "1":
            continue
        module = flag.key
        lines.append(f"blacklist {module}\n")
        # /bin/false, never /bin/true: it fails loudly instead of pretending to
        # have loaded the module (§4.5).
        lines.append(f"install {module} /bin/false\n")
        for extra in flag.extra:
            lines.append(f"{extra}\n")
    return "".join(lines)


def _body_grub(pairs: list[tuple[Flag, str]]) -> str:
    params: list[str] = []
    assignments: list[str] = []
    for flag, value in pairs:
        if flag.key.startswith("GRUB_"):
            assignments.append(f"{flag.key}={value}\n")
        elif value == "":
            params.append(flag.key)
        else:
            params.append(f"{flag.key}={value}")
    body = ""
    if params:
        body += (
            'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT '
            + " ".join(params)
            + '"\n'
        )
    return body + "".join(assignments)


def _body_auditd(pairs: list[tuple[Flag, str]]) -> str:
    # `-e 2` makes the rule set immutable, so it has to be the last line — every
    # rule after it would be rejected (§4.14).
    lines = []
    for flag, value in sorted(pairs, key=lambda pair: pair[0].apply_last):
        if value != "1":
            continue
        lines.append(f"{flag.key}\n")
        for extra in flag.extra:
            lines.append(f"{extra}\n")
    return "".join(lines)


_LOGINDEF_KEY = re.compile(r"^\s*#?\s*([A-Z_]+)\b")


def _body_logindefs(pairs: list[tuple[Flag, str]], current: str) -> str:
    """Rewrite ``/etc/login.defs`` in place: replace managed keys, append the rest.

    login.defs has no drop-in directory, so this is a real in-place edit. Existing
    lines are rewritten where possible so the file keeps its comments and order.
    """
    wanted = {flag.key: value for flag, value in pairs}
    out: list[str] = []
    seen: set[str] = set()
    for line in current.splitlines(keepends=True):
        match = _LOGINDEF_KEY.match(line)
        key = match.group(1) if match else None
        if key in wanted and not line.lstrip().startswith("#"):
            if key not in seen:
                out.append(f"{key}\t{wanted[key]}\n")
                seen.add(key)
            continue  # drop duplicate assignments of a managed key
        out.append(line)
    missing = [(k, v) for k, v in wanted.items() if k not in seen]
    if missing:
        if out and not out[-1].endswith("\n"):
            out.append("\n")
        out.append("\n# --- hardening-gui ---\n")
        out.extend(f"{key}\t{value}\n" for key, value in missing)
    return "".join(out)


def _service_commands(pairs: list[tuple[Flag, str]]) -> list[Command]:
    cmds = []
    for flag, value in pairs:
        if value == "mask":
            cmds.append(
                Command(("/usr/bin/systemctl", "mask", "--now", flag.key), f"mask {flag.key}")
            )
        elif value == "disable":
            cmds.append(
                Command(("/usr/bin/systemctl", "disable", "--now", flag.key), f"disable {flag.key}")
            )
    return cmds


def _gsettings_commands(pairs: list[tuple[Flag, str]]) -> list[Command]:
    # gsettings writes the *user's* dconf database, so these must not run as root.
    cmds = []
    for flag, value in pairs:
        schema, _, key = flag.key.rpartition(" ")
        if not schema:
            raise RenderError(f"gsettings flag {flag.id!r} needs 'schema key' in key")
        cmds.append(
            Command(
                ("/usr/bin/gsettings", "set", schema, key, value),
                f"{schema} {key} = {value}",
                user=True,
            )
        )
    return cmds


# --------------------------------------------------------------------------- #


def render_section(
    section: Section,
    selection: dict[str, str],
    current: dict[str, str] | None = None,
) -> Plan:
    """Build the plan for one section.

    A section normally writes one drop-in, but a flag may override the target
    (``pam`` writes pwquality.conf, faillock.conf and login.defs), so the work is
    bucketed by resolved target file.

    *current* maps target path to its existing content, required for in-place
    targets (login.defs) and ignored otherwise.
    """
    current = current or {}
    plan = Plan()
    all_pairs = _selected(section, selection)

    if section.syntax == "services":
        plan.commands.extend(_service_commands(all_pairs))
        return plan
    if section.syntax == "gsettings":
        plan.user_commands.extend(_gsettings_commands(all_pairs))
        return plan
    if section.syntax == "special":
        # ufw / fstab / permissions / usb carry their own payload types; they are
        # planned by their own modules, not from the flag selection alone.
        return plan

    touched = False
    for target in section.targets():
        pairs = [(f, v) for f, v in all_pairs if section.target_for(f) == target]
        syntax = section.syntax
        in_place = section.in_place
        if pairs:
            syntax = section.syntax_for(pairs[0][0])
            in_place = pairs[0][0].in_place or section.in_place

        if syntax == "logindefs":
            if not pairs:
                continue  # nothing selected: leave the system file alone
            if target not in current:
                raise RenderError(f"in-place target {target} needs its current content")
            content = _body_logindefs(pairs, current[target])
            if content != current[target]:
                plan.writes.append(
                    FileWrite(
                        path=target, content=content, in_place=True, section=section.id
                    )
                )
                touched = True
            continue

        if not pairs:
            # Nothing selected. Only a file we actually own gets deleted, and only
            # if it is there — otherwise a plain Apply would try to remove every
            # drop-in the app has never written.
            if target in current and not in_place:
                plan.removes.append(FileRemove(path=target, section=section.id))
                touched = True
            continue

        if syntax == "keyval":
            body = _body_keyval(pairs)
        elif syntax == "ini":
            body = _body_ini(pairs, section.ini_section)
        elif syntax == "sshd":
            body = _body_sshd(pairs)
        elif syntax == "sudoers":
            body = _body_sudoers(pairs)
        elif syntax == "apt":
            body = _body_apt(pairs)
        elif syntax == "modprobe":
            body = _body_modprobe(pairs)
        elif syntax == "grub":
            body = _body_grub(pairs)
        elif syntax == "auditd":
            body = _body_auditd(pairs)
        else:  # pragma: no cover - guarded by SYNTAXES on load
            raise RenderError(f"no renderer for syntax {syntax!r}")

        mode = 0o440 if syntax == "sudoers" else 0o644
        content = (IN_PLACE_BANNER if in_place else BANNER) + body
        if content != current.get(target):
            plan.writes.append(
                FileWrite(
                    path=target,
                    content=content,
                    mode=mode,
                    in_place=in_place,
                    section=section.id,
                )
            )
            touched = True

    if touched:
        # Reverting needs the reload too — a deleted sysctl drop-in changes
        # nothing live until `sysctl --system` runs.
        plan.commands.extend(Command(cmd, f"reload {section.id}") for cmd in section.reload)
    return plan


def render(
    catalogue: Catalogue,
    selection: dict[str, str],
    current: dict[str, str] | None = None,
    sections: list[str] | None = None,
) -> Plan:
    """Build the full plan for a selection across every section.

    *current* maps target path to existing content, for in-place sections.
    *sections* limits the plan to those section ids (used by per-section undo).
    """
    current = current or {}
    plan = Plan()
    for section in catalogue.sections:
        if sections is not None and section.id not in sections:
            continue
        if section.requires_pkg and not probe.package_present(section.requires_pkg):
            # The tool that would read this file is not installed. Writing it
            # anyway means the reload command fails and takes the whole
            # transaction down with it.
            continue
        sub = render_section(section, selection, current)
        plan.writes.extend(sub.writes)
        plan.removes.extend(sub.removes)
        plan.commands.extend(sub.commands)
        plan.user_commands.extend(sub.user_commands)

    plan.commands = _dedupe_commands(plan.commands)
    plan.user_commands = _dedupe_commands(plan.user_commands)
    return plan


def _dedupe_commands(commands: list[Command]) -> list[Command]:
    """Collapse repeats (many sections share ``systemctl daemon-reload``)."""
    seen: set[tuple[str, ...]] = set()
    out: list[Command] = []
    for command in commands:
        if command.argv in seen:
            continue
        seen.add(command.argv)
        out.append(command)
    return out


def validate_commands(plan: Plan) -> list[str]:
    """Reject any command outside the allowlist. Returns a list of problems."""
    problems = []
    for command in plan.commands:
        if not command.argv:
            problems.append("empty command")
        elif command.argv[0] not in ALLOWED_COMMANDS:
            problems.append(f"command not allowed: {command.argv[0]}")
    return problems
