"""Turn a running system into a preset — BUILD_PLAN §5.2.

Four steps, and the third is the one that matters:

1. **Read the effective config**, not the files: the merged sysctl chain *and*
   the live ``/proc/sys`` values, ``/proc/cmdline`` as well as the grub files,
   parsed modprobe directives, the firewall, the unit states.
2. **Normalise**: map raw keys, modules and rules onto catalogue flag ids;
   collect valid-but-unknown keys as custom entries; tag hardware quirks.
3. **Validate**: drop keys with no ``/proc/sys`` entry on this kernel, invalid
   grub parameters, malformed modprobe lines — each one *reported*, never
   silently kept.
4. **Emit** the preset plus a findings report.

Step 3 is why this exists rather than being a file copy. A machine hardened by
hand accumulates keys that have never done anything: ``kernel.exec-shield`` and
``security.bprm_checkIP`` were both live in the reference machine's config, and
neither has existed in a kernel for years. Copying the files forward carries the
mistakes; capturing the *effective state* and validating it does not.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from . import probe, sysctl_chain, tomlemit, ufw as ufw_module
from .catalogue import Catalogue
from .probe import State


@dataclass
class Finding:
    """Something worth reporting about the configuration we just read."""

    severity: str  # high | info
    title: str
    detail: str


@dataclass
class Capture:
    """The result: a selection, plus everything we noticed on the way."""

    selection: dict[str, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    #: Valid keys in effect that no catalogue flag covers.
    unknown_keys: dict[str, str] = field(default_factory=dict)
    #: Flags whose live value is not one the catalogue allows.
    out_of_range: dict[str, str] = field(default_factory=dict)
    #: Modules blacklisted on this machine that the catalogue has no flag for.
    unknown_modules: list[str] = field(default_factory=list)
    #: Firewall state, carried alongside the flag selection.
    firewall: ufw_module.State | None = None

    @property
    def high(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "high"]

    def summary(self) -> str:
        return (
            f"{len(self.selection)} settings captured · "
            f"{len(self.high)} finding(s) worth acting on · "
            f"{len(self.unknown_keys)} key(s) not in the catalogue"
        )


def _catalogue_sysctl_keys(catalogue: Catalogue) -> dict[str, str]:
    """sysctl key -> flag id, for mapping raw keys onto the catalogue."""
    return {
        flag.key: flag.id
        for flag in catalogue.flags.values()
        if flag.section == "sysctl"
    }


def _catalogue_modules(catalogue: Catalogue) -> dict[str, str]:
    return {
        flag.key: flag.id
        for flag in catalogue.flags.values()
        if flag.section == "modprobe"
    }


def run(catalogue: Catalogue, facts: probe.SystemFacts | None = None) -> Capture:
    """Capture this system."""
    facts = facts or probe.gather(catalogue)
    result = Capture()

    # ---- 1 & 2: what is actually in effect, mapped onto flag ids ---------- #
    states = probe.all_states(catalogue, facts)
    for flag_id, state in states.items():
        if state.state not in (State.APPLIED, State.PENDING_REBOOT):
            continue
        flag = catalogue.flags[flag_id]
        value = state.on_disk or state.live or flag.value
        if flag.value_is_allowed(value):
            result.selection[flag_id] = value
        else:
            # In effect, but set to something this app would not write. Reported
            # rather than dropped silently or forced into range.
            result.out_of_range[flag_id] = value

    # ---- 3: validate the sysctl layer, and report what it turns up -------- #
    chain = sysctl_chain.read()
    for severity, title, detail in sysctl_chain.findings(chain):
        result.findings.append(Finding(severity, title, detail))

    known_keys = _catalogue_sysctl_keys(catalogue)
    for key, key_result in chain.keys.items():
        if key not in known_keys:
            result.unknown_keys[key] = key_result.value

    if result.unknown_keys:
        result.findings.append(
            Finding(
                "info",
                f"{len(result.unknown_keys)} sysctl key(s) in effect that this app does not manage",
                "They are recorded in the preset as custom entries so carrying it to "
                "another machine does not quietly drop them: "
                + ", ".join(sorted(result.unknown_keys)[:8])
                + ("…" if len(result.unknown_keys) > 8 else ""),
            )
        )

    if result.out_of_range:
        result.findings.append(
            Finding(
                "high",
                f"{len(result.out_of_range)} setting(s) are in effect with a value outside what this app offers",
                "Captured as-is rather than rounded to the nearest allowed value: "
                + ", ".join(f"{k}={v}" for k, v in sorted(result.out_of_range.items())[:6]),
            )
        )

    # ---- modules the catalogue has no flag for --------------------------- #
    known_modules = _catalogue_modules(catalogue)
    blacklisted = _read_blacklists()
    result.unknown_modules = sorted(blacklisted - set(known_modules))
    if result.unknown_modules:
        result.findings.append(
            Finding(
                "info",
                f"{len(result.unknown_modules)} blacklisted module(s) not in the catalogue",
                "Recorded so the preset does not lose them: "
                + ", ".join(result.unknown_modules[:10])
                + ("…" if len(result.unknown_modules) > 10 else ""),
            )
        )

    # ---- cross-section checks -------------------------------------------- #
    kdump = probe.kdump_conflict(facts, result.selection)
    if kdump:
        result.findings.append(Finding("high", "kdump can never fire", kdump))
    redundant = probe.slab_debug_redundancy(result.selection)
    if redundant:
        result.findings.append(Finding("info", "Redundant boot flags", redundant))

    # ---- the firewall ---------------------------------------------------- #
    result.firewall = ufw_module.read_unprivileged()
    missing = result.firewall.missing_recommended()
    if missing:
        result.findings.append(
            Finding(
                "high",
                f"{len(missing)} outbound allowance(s) missing under a deny-outgoing policy",
                "; ".join(f"{rule.summary} — {why}" for rule, why in missing),
            )
        )

    loaded_but_blacklisted = [
        catalogue.flags[i].key
        for i, s in states.items()
        if s.state is State.PENDING_REBOOT and catalogue.flags[i].section == "modprobe"
    ]
    if loaded_but_blacklisted:
        result.findings.append(
            Finding(
                "info",
                f"{len(loaded_but_blacklisted)} blacklisted module(s) still loaded",
                "A blacklist stops a module loading; it does not unload one already "
                "in the kernel. These need a reboot: "
                + ", ".join(loaded_but_blacklisted[:8]),
            )
        )
    return result


def _read_blacklists() -> set[str]:
    """Every module blacklisted anywhere in /etc/modprobe.d."""
    from pathlib import Path

    out: set[str] = set()
    for directory in ("/etc/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d"):
        base = Path(directory)
        if not base.is_dir():
            continue
        try:
            files = sorted(base.glob("*.conf"))
        except OSError:
            continue
        for path in files:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line in text.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "blacklist":
                    # Normalise to underscores: a hyphenated blacklist line is
                    # silently ignored by modprobe, which is a finding in itself.
                    out.add(parts[1].replace("-", "_"))
    return out


def to_toml(result: Capture, name: str = "captured") -> str:
    """The preset file for a capture, including the unmanaged extras."""
    entries = [
        {"id": flag_id, "value": result.selection[flag_id]}
        for flag_id in sorted(result.selection)
    ]

    data: dict = {
        "preset": {
            "name": name,
            "desc": f"Captured from this system, {date.today():%Y-%m}. {result.summary()}",
        },
        "set": entries,
    }

    if result.unknown_keys:
        data["custom_sysctl"] = dict(sorted(result.unknown_keys.items()))
    if result.unknown_modules:
        data["custom_modules"] = {"blacklist": result.unknown_modules}
    if result.out_of_range:
        data["out_of_range"] = dict(sorted(result.out_of_range.items()))

    header = (
        f"{name} — captured from a running system by hardening-gui.\n"
        "\n"
        "Read from the effective live state, not copied from the config files, so\n"
        "keys that were set but have never done anything are not carried forward.\n"
        "\n"
        "custom_sysctl and custom_modules record settings in effect that this app\n"
        "does not manage — kept so carrying this preset elsewhere does not quietly\n"
        "drop them, but not applied by the app itself."
    )
    return tomlemit.dumps(data, header=header)


def findings_report(result: Capture) -> str:
    """A plain-text findings report, for saving alongside the preset."""
    lines = [
        "Capture findings",
        "=" * 60,
        result.summary(),
        "",
    ]
    for severity in ("high", "info"):
        matching = [f for f in result.findings if f.severity == severity]
        if not matching:
            continue
        lines.append(f"{severity.upper()} ({len(matching)})")
        lines.append("-" * 60)
        for finding in matching:
            lines.append(f"* {finding.title}")
            for chunk in _wrap(finding.detail, 74):
                lines.append(f"    {chunk}")
            lines.append("")
    if not result.findings:
        lines.append("Nothing to report.")
    return "\n".join(lines) + "\n"


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current: list[str] = []
    for word in words:
        if sum(len(w) + 1 for w in current) + len(word) > width and current:
            lines.append(" ".join(current))
            current = []
        current.append(word)
    if current:
        lines.append(" ".join(current))
    return lines
