"""Read the live system state, so every flag knows where it stands (§6).

There is no daemon and no journal: the drop-in files the app wrote *are* the
record, and drift is a file-versus-live mismatch computed at startup. Everything
here is read-only and unprivileged — if a value can't be read we say so rather
than guessing.

Stdlib only; shared with the helper, which uses the same functions for the
post-Apply read-back.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from enum import Enum
from pathlib import Path

from . import branding
from .catalogue import Catalogue, Flag, Section

#: How long any probe subprocess gets before we give up on it.
TIMEOUT = 10


class State(str, Enum):
    """The five states from §6, in the order the UI lists them."""

    APPLIED = "applied"  # ● live value == selected value
    PENDING_REBOOT = "pending-reboot"  # ◐ on disk, live differs, boot-time flag
    DIFFERS = "differs"  # ◍ live != our file — something else changed it
    NOT_SET = "not-set"  # ○ system default
    INVALID = "invalid"  # ✕ key/module doesn't exist on this kernel
    UNKNOWN = "unknown"  # we could not read it (unreadable, no tool)


@dataclass
class FlagState:
    """What we know about one flag right now."""

    flag_id: str
    state: State
    live: str | None = None
    on_disk: str | None = None
    note: str = ""


@dataclass
class SystemFacts:
    """Everything read once at startup and reused across every flag."""

    #: Contents of each catalogue target file that exists.
    files: dict[str, str]
    #: /proc/cmdline, split into tokens.
    cmdline: list[str]
    #: Loaded modules -> refcount, from /proc/modules.
    modules: dict[str, int]
    #: Enabled/masked state per unit, from systemctl.
    units: dict[str, str]
    #: gsettings values, keyed "schema key".
    gsettings: dict[str, str]
    #: CPU vulnerability status from sysfs, keyed by bug name.
    vulnerabilities: dict[str, str]
    #: True when we are running over SSH — gates the lockout warnings.
    over_ssh: bool = False


def _read_text(path: str | Path) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return None


def _run(argv: list[str]) -> str | None:
    """Run a read-only command, return stdout or None if it isn't usable."""
    if not os.path.isabs(argv[0]) and shutil.which(argv[0]) is None:
        return None
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=TIMEOUT, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def read_sysctl(key: str) -> tuple[str | None, str]:
    """``(value, status)`` where status is ``ok``, ``absent`` or ``unreadable``.

    The distinction matters: a key that is *absent* would silently do nothing if
    written (``kernel.exec-shield`` on this machine, §5.4), while several real
    keys — ``vm.mmap_rnd_bits``, the ``apparmor_restrict_*`` set — are mode 0600
    and simply can't be read unprivileged. Calling the second case "invalid here"
    would be a lie, so it gets its own state and the helper reads it back as root.
    """
    path = Path("/proc/sys/" + key.replace(".", "/"))
    if not path.exists():
        return None, "absent"
    raw = _read_text(path)
    if raw is None:
        return None, "unreadable"
    # Multi-value keys (kernel.printk, ip_local_port_range) are tab-separated.
    return " ".join(raw.split()), "ok"


def read_modules() -> dict[str, int]:
    """Loaded modules and their refcounts, so a blacklist can say 'needs reboot'."""
    raw = _read_text("/proc/modules") or ""
    out: dict[str, int] = {}
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            try:
                out[parts[0]] = int(parts[2])
            except ValueError:
                out[parts[0]] = 0
    return out


def read_cmdline() -> list[str]:
    return (_read_text("/proc/cmdline") or "").split()


def read_units() -> dict[str, str]:
    """Unit -> enablement state (enabled/disabled/masked/static)."""
    out: dict[str, str] = {}
    raw = _run(["/usr/bin/systemctl", "list-unit-files", "--no-legend", "--no-pager"])
    for line in (raw or "").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            out[parts[0]] = parts[1]
    return out


def read_gsettings(keys: list[str]) -> dict[str, str]:
    """Current value of each ``"schema key"`` pair, as gsettings prints it."""
    out: dict[str, str] = {}
    for pair in keys:
        schema, _, key = pair.rpartition(" ")
        if not schema:
            continue
        raw = _run(["/usr/bin/gsettings", "get", schema, key])
        if raw is not None:
            # gsettings quotes strings and prints booleans bare.
            out[pair] = raw.strip().strip("'")
    return out


def read_vulnerabilities() -> dict[str, str]:
    """``/sys/devices/system/cpu/vulnerabilities/*`` — greys out 'Not affected' rows."""
    out: dict[str, str] = {}
    base = Path("/sys/devices/system/cpu/vulnerabilities")
    if not base.is_dir():
        return out
    try:
        entries = sorted(base.iterdir())
    except OSError:
        return out
    for entry in entries:
        text = _read_text(entry)
        if text is not None:
            out[entry.name] = text.strip()
    return out


#: Optional tools, and the binary that proves each one is installed.
_PACKAGE_BINARIES = {
    "auditd": "auditctl",
    "aide": "aide",
    "usbguard": "usbguard",
    "openssh-server": "sshd",
    "debsums": "debsums",
}


def package_present(package: str) -> bool:
    """Whether an optional package is installed.

    Sections that need one degrade gracefully rather than failing: without this
    check, staging the audit rules on a machine with no auditd would write the
    rules file and then fail on ``augenrules``, rolling back the whole
    transaction over a section the user could not have known was unavailable.
    """
    binary = _PACKAGE_BINARIES.get(package, package)
    if shutil.which(binary):
        return True
    return any(
        os.path.exists(f"{prefix}/{binary}")
        for prefix in ("/usr/sbin", "/usr/bin", "/sbin", "/bin")
    )


@lru_cache(maxsize=1)
def sudo_implementation() -> str:
    """Which sudo this system has: ``sudo-rs``, ``gnu`` or ``unknown``.

    Ubuntu 26.04 ships sudo-rs, a Rust reimplementation that supports a subset of
    sudoers. Four directives GNU sudo has — logfile, log_input, log_output and
    requiretty — are rejected by it, so staging them would fail the whole
    transaction at visudo time on a directive the user could not know was absent.
    """
    raw = _run(["sudo", "--version"]) or ""
    lowered = raw.lower()
    if "sudo-rs" in lowered:
        return "sudo-rs"
    if "sudo version" in lowered:
        return "gnu"
    return "unknown"


#: Capability tokens a flag can declare a dependency on, and how to test each.
def has_capability(token: str) -> bool:
    if token == "gnu-sudo":
        # "unknown" is treated as available: better to let visudo have the final
        # say than to hide a flag because a version string could not be parsed.
        return sudo_implementation() != "sudo-rs"
    return True


def capability_reason(token: str) -> str:
    if token == "gnu-sudo":
        return (
            "This directive only exists in GNU sudo. Ubuntu 26.04 ships sudo-rs, "
            "which does not implement it — visudo rejects it, so it cannot be "
            "applied here."
        )
    return f"Requires {token}, which is not available on this system."


#: Drop-in directories that only work because another file includes them.
#: Writing into one of these when the include line is missing produces a file
#: that is silently ignored — which is the failure mode this whole app exists to
#: catch, so it is worth checking rather than assuming.
#:
#:   directory -> (file that must include it, marker, what to add)
INCLUDE_MECHANISMS = {
    "/etc/sudoers.d": (
        "/etc/sudoers",
        ("@includedir /etc/sudoers.d", "#includedir /etc/sudoers.d"),
        "@includedir /etc/sudoers.d",
    ),
    "/etc/ssh/sshd_config.d": (
        "/etc/ssh/sshd_config",
        ("Include /etc/ssh/sshd_config.d/*.conf",),
        "Include /etc/ssh/sshd_config.d/*.conf",
    ),
    "/etc/default/grub.d": (
        "/usr/sbin/grub-mkconfig",
        ("grub.d",),
        "(shipped by grub-common; nothing to add)",
    ),
}


def include_check(directory: str) -> tuple[str, str]:
    """``(status, detail)`` for a drop-in directory's include mechanism.

    Status is ``ok``, ``missing``, or ``unreadable`` — the last because
    ``/etc/sudoers`` is mode 0440, so an unprivileged check genuinely cannot
    tell, and saying "missing" there would be a false alarm.
    """
    entry = INCLUDE_MECHANISMS.get(directory)
    if entry is None:
        return "ok", ""
    source, markers, remedy = entry

    path = Path(source)
    if not path.exists():
        return "missing", f"{source} does not exist"
    content = _read_text(path)
    if content is None:
        return "unreadable", (
            f"{source} is not readable without root, so this cannot be confirmed "
            f"here — the helper re-checks it before writing."
        )
    if any(marker in content for marker in markers):
        return "ok", ""
    return "missing", (
        f"{source} does not include {directory}, so a file written there would be "
        f"ignored. Add:  {remedy}"
    )


def broken_includes(catalogue: Catalogue) -> list[tuple[str, str]]:
    """``(section id, detail)`` for sections whose drop-in dir is not included."""
    out = []
    for section in catalogue.sections:
        for target in section.targets():
            directory = str(Path(target).parent)
            if directory not in INCLUDE_MECHANISMS:
                continue
            if section.requires_pkg and not package_present(section.requires_pkg):
                continue
            status, detail = include_check(directory)
            if status == "missing":
                out.append((section.id, detail))
    return out


def read_target_files(catalogue: Catalogue) -> dict[str, str]:
    """Current content of every catalogue target file that exists and is readable."""
    out: dict[str, str] = {}
    for section in catalogue.sections:
        for target in section.targets():
            if target in out:
                continue
            content = _read_text(target)
            if content is not None:
                out[target] = content
    return out


def gather(catalogue: Catalogue) -> SystemFacts:
    """One pass over the system, at startup and after every Apply."""
    gsettings_keys = [
        flag.key
        for section in catalogue.sections
        if section.syntax == "gsettings"
        for flag in section.flags
    ]
    return SystemFacts(
        files=read_target_files(catalogue),
        cmdline=read_cmdline(),
        modules=read_modules(),
        units=read_units(),
        gsettings=read_gsettings(gsettings_keys),
        vulnerabilities=read_vulnerabilities(),
        over_ssh=bool(os.environ.get("SSH_CONNECTION")),
    )


# --------------------------------------------------------------------------- #
#  Per-syntax "what does the file say" and "what is live" readers
# --------------------------------------------------------------------------- #

_KEYVAL = re.compile(r"^\s*([^\s#=]+)\s*=\s*(.*?)\s*$")


def _parse_keyval(content: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in content.splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = _KEYVAL.match(line)
        if match:
            out[match.group(1)] = match.group(2)
    return out


def _parse_space_separated(content: str) -> dict[str, str]:
    """``Key value`` files: sshd_config, login.defs."""
    out: dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        out[parts[0]] = parts[1].strip() if len(parts) > 1 else ""
    return out


def _parse_ini(content: str) -> dict[str, str]:
    """``Key=value`` under ``[Header]``, keyed by bare key (our keys are unique)."""
    return _parse_keyval(content)


def _parse_apt(content: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip().rstrip(";")
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            out[parts[0]] = parts[1].strip().strip('"')
    return out


def _parse_sudoers(content: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped.startswith("Defaults"):
            continue
        directive = stripped[len("Defaults") :].strip()
        key, sep, value = directive.partition("=")
        out[key.strip()] = value.strip() if sep else ""
    return out


def _parse_modprobe(content: str) -> set[str]:
    out: set[str] = set()
    for line in content.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "blacklist":
            out.add(parts[1])
    return out


def _parse_grub_file(content: str) -> tuple[set[str], dict[str, str]]:
    """Cmdline tokens and ``GRUB_*`` assignments from a grub.d drop-in."""
    tokens: set[str] = set()
    assignments: dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or "=" not in stripped:
            continue
        name, _, value = stripped.partition("=")
        value = value.strip().strip('"')
        if name.strip().startswith("GRUB_CMDLINE_LINUX"):
            tokens.update(t for t in value.split() if not t.startswith("$"))
        else:
            assignments[name.strip()] = value
    return tokens, assignments


def _cmdline_value(cmdline: list[str], key: str) -> str | None:
    """Last occurrence wins, matching how the kernel parses its command line."""
    found: str | None = None
    for token in cmdline:
        name, sep, value = token.partition("=")
        if name == key:
            found = value if sep else ""
    return found


def is_ours(content: str) -> bool:
    """Whether this file was written by us, judged by the banner we stamp on it.

    Only meaningful for in-place targets — a file like /etc/login.defs or
    faillock.conf exists whether or not we have ever touched it, so reading a
    hardened value out of one says nothing about who set it. Treating those as
    "ours" made the app adopt the pam package's own defaults and then rewrite the
    file to say the same thing.
    """
    return branding.MARKER in content


def on_disk_value(section: Section, flag: Flag, facts: SystemFacts) -> str | None:
    """What our own drop-in currently says for this flag, or None if absent."""
    target = section.target_for(flag)
    content = facts.files.get(target)
    if content is None:
        return None
    if (flag.in_place or section.in_place) and not is_ours(content):
        return None
    syntax = section.syntax_for(flag)

    if syntax in ("keyval", "ini"):
        return (_parse_keyval if syntax == "keyval" else _parse_ini)(content).get(flag.key)
    if syntax in ("sshd", "logindefs"):
        return _parse_space_separated(content).get(flag.key)
    if syntax == "apt":
        return _parse_apt(content).get(flag.key)
    if syntax == "sudoers":
        return _parse_sudoers(content).get(flag.key)
    if syntax == "modprobe":
        return "1" if flag.key in _parse_modprobe(content) else None
    if syntax == "auditd":
        return "1" if flag.key in content.splitlines() else None
    if syntax == "grub":
        tokens, assignments = _parse_grub_file(content)
        if flag.key.startswith("GRUB_"):
            return assignments.get(flag.key)
        for token in tokens:
            name, sep, value = token.partition("=")
            if name == flag.key:
                return value if sep else ""
        return None
    return None


def live_value(section: Section, flag: Flag, facts: SystemFacts) -> tuple[str | None, str]:
    """``(live value, status)`` — status is ``ok``, ``absent`` or ``unreadable``."""
    syntax = section.syntax_for(flag)

    if section.id == "sysctl":
        return read_sysctl(flag.key)

    if syntax == "grub":
        if flag.key.startswith("GRUB_"):
            # A GRUB_ variable has no live counterpart — the generated grub.cfg is
            # the only evidence, so treat the file as authoritative.
            return None, "unreadable"
        return _cmdline_value(facts.cmdline, flag.key), "ok"

    if syntax == "modprobe":
        # "Live" for a blacklist means: is the module currently loaded?
        return ("0" if flag.key in facts.modules else "1"), "ok"

    if syntax == "services":
        state = facts.units.get(flag.key)
        if state is None:
            return None, "absent"
        if state == "masked":
            return "mask", "ok"
        if state in ("disabled", "enabled"):
            return ("disable" if state == "disabled" else "enabled"), "ok"
        return state, "ok"

    if syntax == "gsettings":
        value = facts.gsettings.get(flag.key)
        return value, ("ok" if value is not None else "absent")

    # Everything else (sshd, pam, sudoers, ini, apt) has no cheap live readout —
    # the file is the state. The helper's read-back re-reads the file after write.
    return None, "unreadable"


def satisfies(section: Section, flag: Flag, live: str | None, reference: str) -> bool:
    """Whether the live value already meets what *reference* asks for.

    Usually plain equality. The exceptions are values that are strictly stronger
    than what was asked: a masked unit satisfies "disable" (systemd masking is
    disabling plus a symlink to /dev/null), and anything a flag lists in
    ``satisfied_by`` does the same for its own ordering.
    """
    if live is None:
        return False
    if live == reference:
        return True
    if section.syntax_for(flag) == "services" and live == "mask":
        return True
    return live in flag.satisfied_by


def flag_state(
    section: Section,
    flag: Flag,
    facts: SystemFacts,
    selected: str | None,
) -> FlagState:
    """Compute the §6 state for one flag.

    The reference the live value is compared against is, in order: what our own
    drop-in says, else what the user has staged, else the flag's hardened value.
    That last case is what makes a machine hardened by hand read as *applied*
    rather than *not set* — the state describes the machine, not our bookkeeping.
    """
    on_disk = on_disk_value(section, flag, facts)
    live, status = live_value(section, flag, facts)

    if status == "absent":
        note = (
            f"{flag.key} is not installed on this system, so there is nothing to "
            "turn off."
            if section.syntax_for(flag) == "services"
            else "No such key on this kernel — writing it would silently do nothing."
        )
        return FlagState(flag.id, State.INVALID, on_disk=on_disk, note=note)

    if status == "unreadable":
        # No live readout available unprivileged. The file is all we can go on.
        if on_disk is None:
            return FlagState(
                flag.id,
                State.NOT_SET if not flag.probe else State.UNKNOWN,
                note="" if not flag.probe else "Root-only value; re-read after Apply.",
            )
        state = State.PENDING_REBOOT if flag.reboot else State.APPLIED
        return FlagState(flag.id, state, on_disk=on_disk)

    reference = on_disk if on_disk is not None else (selected or flag.value)
    if satisfies(section, flag, live, reference):
        return FlagState(flag.id, State.APPLIED, live=live, on_disk=on_disk)

    if on_disk is None:
        return FlagState(flag.id, State.NOT_SET, live=live)

    # Our file says one thing, the machine says another.
    if flag.reboot:
        return FlagState(
            flag.id,
            State.PENDING_REBOOT,
            live=live,
            on_disk=on_disk,
            note="Written to disk; takes effect on the next boot.",
        )
    if section.syntax_for(flag) == "modprobe":
        return FlagState(
            flag.id,
            State.PENDING_REBOOT,
            live=live,
            on_disk=on_disk,
            note="Blacklisted, but still loaded (refcount "
            f"{facts.modules.get(flag.key, 0)}). Needs a reboot.",
        )
    return FlagState(
        flag.id,
        State.DIFFERS,
        live=live,
        on_disk=on_disk,
        note="Our drop-in says one thing and the live value says another — "
        "something else on the system changed it.",
    )


def all_states(
    catalogue: Catalogue,
    facts: SystemFacts,
    selection: dict[str, str] | None = None,
) -> dict[str, FlagState]:
    """State for every flag in the catalogue."""
    selection = selection or {}
    out: dict[str, FlagState] = {}
    for section in catalogue.sections:
        for flag in section.flags:
            out[flag.id] = flag_state(section, flag, facts, selection.get(flag.id))
    return out


# --------------------------------------------------------------------------- #
#  Cross-section consistency checks surfaced at review time
# --------------------------------------------------------------------------- #


def kdump_conflict(facts: SystemFacts, selection: dict[str, str]) -> str | None:
    """crashkernel= reserved *and* kexec disabled = kdump can never fire (§4.4)."""
    has_crashkernel = any(t.startswith("crashkernel=") for t in facts.cmdline)
    kexec_disabled = (
        selection.get("kexec_load_disabled") == "1"
        or read_sysctl("kernel.kexec_load_disabled")[0] == "1"
    )
    if has_crashkernel and kexec_disabled:
        return (
            "crashkernel= is reserving memory for kdump, but kexec is disabled, so "
            "the crash kernel can never load: the reserved RAM is wasted and crash "
            "dumps silently do not happen. Either drop crashkernel and keep kexec "
            "disabled (the hardening choice), or leave kexec alone to keep kdump."
        )
    return None


def slab_debug_redundancy(selection: dict[str, str]) -> str | None:
    """slab_debug already disables merging, so slab_nomerge adds only cost (§5.4)."""
    if "slab_debug" in selection and "slab_nomerge" in selection:
        return (
            "slab_debug=FZP already disables slab merging on its own, so "
            "slab_nomerge adds nothing while it is on."
        )
    return None


def dot_without_firewall_port(selection: dict[str, str]) -> str | None:
    """DNSOverTLS with 853/tcp blocked outbound means no DNS at all (§4.6)."""
    if selection.get("resolved_dns_over_tls") != "yes":
        return None
    status = _run(["/usr/sbin/ufw", "status"])
    if status is None:
        return None  # ufw not readable unprivileged; the helper re-checks
    if "deny (outgoing)" not in status.lower():
        return None
    if "853" in status:
        return None
    return (
        "DNS over TLS needs outbound 853/tcp, the firewall default is deny "
        "outgoing, and no rule allows 853. Applying this as-is stops all name "
        "resolution. Add `ufw allow out 853/tcp` first."
    )


def ipv6_redundant(selection: dict[str, str]) -> bool:
    """True when IPv6 is off, so the remaining IPv6 flags are moot (§4.3)."""
    return selection.get("disable_ipv6_all") == "1" or "ipv6_disable_boot" in selection


def unaffected_mitigations(catalogue: Catalogue, facts: SystemFacts) -> set[str]:
    """Flag ids whose CPU bug reports 'Not affected' — greyed out in the UI (§4.4)."""
    #: flag id -> sysfs vulnerability file name
    mapping = {
        "pti_on": "meltdown",
        "spectre_v2": "spectre_v2",
        "spectre_v2_user": "spectre_v2",
        "spec_store_bypass_disable": "spec_store_bypass",
        "ssbd_force": "spec_store_bypass",
        "l1tf": "l1tf",
        "mds": "mds",
        "tsx_async_abort": "tsx_async_abort",
        "mmio_stale_data": "mmio_stale_data",
        "retbleed": "retbleed",
        "gather_data_sampling": "gather_data_sampling",
        "reg_file_data_sampling": "reg_file_data_sampling",
        "spec_rstack_overflow": "spec_rstack_overflow",
        "srbds": "srbds",
        "kvm_nx_huge_pages": "itlb_multihit",
    }
    out: set[str] = set()
    for flag_id, bug in mapping.items():
        status = facts.vulnerabilities.get(bug, "")
        if status.startswith("Not affected") and flag_id in catalogue.flags:
            out.add(flag_id)
    return out
