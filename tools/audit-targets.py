#!/usr/bin/python3
"""Audit every file the app would write, against the system it writes to.

The app's contract is narrow: the user picks flags, and it writes them to a file
*it owns*. It must never overwrite a file the user or a package wrote — with the
handful of in-place exceptions that have no drop-in mechanism, which must be
declared and backed up.

This checks that contract per target, on the machine it is run on:

  1. we do not write over a file any package owns, unless declared in-place
  2. our filename is ours alone — no collision with an existing file
  3. our file sorts last in its directory, so our values win
  4. the consuming tool actually reads the directory we write into
  5. the rendered content passes that tool's own validator, where one exists

    python3 tools/audit-targets.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ossgui import catalogue as catalogue_module  # noqa: E402
from ossgui import probe, render  # noqa: E402

PASS, WARN, FAIL = "ok  ", "warn", "FAIL"

#: Consuming tool per directory, and how to prove it reads it.
READERS = {
    "/etc/sysctl.d": ("systemd-sysctl", "man systemd-sysctl / sysctl.d(5)"),
    "/etc/modprobe.d": ("modprobe", "modprobe.d(5)"),
    "/etc/default/grub.d": ("grub-mkconfig", "sourced by /usr/sbin/grub-mkconfig"),
    "/etc/ssh/sshd_config.d": ("sshd", "Include in sshd_config"),
    "/etc/security/pwquality.conf.d": ("libpwquality", "pwquality.conf(5)"),
    "/etc/sudoers.d": ("sudo", "@includedir in /etc/sudoers"),
    "/etc/systemd/journald.conf.d": ("systemd-journald", "journald.conf(5)"),
    "/etc/systemd/coredump.conf.d": ("systemd-coredump", "coredump.conf(5)"),
    "/etc/systemd/resolved.conf.d": ("systemd-resolved", "resolved.conf(5)"),
    "/etc/NetworkManager/conf.d": ("NetworkManager", "NetworkManager.conf(5)"),
    "/etc/audit/rules.d": ("augenrules", "auditd.conf(5)"),
    "/etc/apt/apt.conf.d": ("apt", "apt.conf(5)"),
    "/etc/apparmor.d/disable": ("apparmor_parser", "apparmor(7)"),
    "/etc/apparmor.d/force-complain": ("apparmor_parser", "apparmor(7)"),
    "/etc/systemd/system": ("systemd", "unit drop-in directories"),
    "/etc/grub.d": ("grub-mkconfig", "scripts run by grub-mkconfig"),
    "/etc/usbguard": ("usbguard", "usbguard-daemon.conf(5)"),
    "/etc": ("various", "in-place system files"),
}

results: list[tuple[str, str, str]] = []


def record(status: str, target: str, detail: str) -> None:
    results.append((status, target, detail))


def package_owner(path: str) -> str:
    """Which package ships this file, or "" if none does."""
    if shutil.which("dpkg") is None:
        return ""
    try:
        out = subprocess.run(
            ["dpkg", "-S", path], capture_output=True, text=True, timeout=20, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if out.returncode != 0:
        return ""
    first = out.stdout.splitlines()[0] if out.stdout.splitlines() else ""
    return first.partition(":")[0].strip()


def audit_target(section, target: str, in_place: bool) -> None:
    path = Path(target)
    directory = str(path.parent)

    # 1. Do we write over something a package owns?
    owner = package_owner(target)
    if owner and not in_place:
        record(FAIL, target, f"owned by package '{owner}' but not declared in-place")
    elif owner and in_place:
        record(PASS, target, f"in-place edit of a {owner} file — backed up to .bak")
    elif in_place:
        record(PASS, target, "declared in-place; no package owns it")
    else:
        record(PASS, target, "our own drop-in, owned by no package")

    # 2. Is the name ours alone?
    if not in_place and path.exists():
        content = path.read_text(encoding="utf-8", errors="replace")
        if not probe.is_ours(content):
            record(
                FAIL,
                target,
                "a file with this name already exists and is NOT ours — "
                "writing it would overwrite someone else's config",
            )

    # 3. Does our filename sort last, so our values win?
    #    Only files the tool actually reads count: a README in /etc/sysctl.d is
    #    not a competitor, because systemd-sysctl requires a .conf extension.
    if not in_place and path.parent.is_dir():
        suffix = path.suffix or ""
        try:
            siblings = sorted(
                q.name for q in path.parent.glob("*")
                if q.is_file() and (not suffix or q.suffix == suffix)
            )
        except OSError:
            siblings = []
        later = [n for n in siblings if n > path.name and n != path.name]
        if later:
            record(
                WARN,
                target,
                f"these sort after ours and would win: {', '.join(later[:4])}",
            )

    # 4. Is there a known reader for this directory?
    reader = READERS.get(directory)
    if reader is None:
        record(WARN, target, f"no documented reader recorded for {directory}")

    # 5. Include mechanism, where the directory needs one.
    status, detail = probe.include_check(directory)
    if status == "missing":
        if section.requires_pkg and not probe.package_present(section.requires_pkg):
            record(PASS, target, f"{section.requires_pkg} not installed; section skipped")
        else:
            record(FAIL, target, detail)


def validate_rendered(catalogue) -> None:
    """Run each consuming tool's own validator over what we would write."""
    print("\nSyntax validation of rendered output")
    print("-" * 74)

    # What the app would actually write: capability-gated flags are excluded,
    # because staging refuses them. Testing flags the app will not write would
    # report a failure that cannot happen.
    selection = {
        flag.id: flag.value
        for flag in catalogue.flags.values()
        if not flag.editable
        and not flag.is_one_way_at(flag.value)
        and all(probe.has_capability(token) for token in flag.needs)
    }
    current = probe.read_target_files(catalogue)
    plan = render.render(catalogue, selection, current=current)

    checks = {
        "/etc/sudoers.d": (["/usr/sbin/visudo", "-c", "-f"], "visudo -c"),
        "/etc/ssh/sshd_config.d": (["/usr/sbin/sshd", "-t", "-f"], "sshd -t"),
        "/etc/audit/rules.d": (["/usr/sbin/auditctl", "-R"], "auditctl -R"),
    }

    for write in plan.writes:
        directory = str(Path(write.path).parent)
        entry = checks.get(directory)
        if entry is None:
            continue
        argv, label = entry
        if not Path(argv[0]).exists():
            print(f"  {'skip':4}  {write.path}  ({argv[0]} not installed)")
            continue
        handle, name = tempfile.mkstemp(suffix=".conf")
        temp = Path(name)
        try:
            temp.write_text(write.content, encoding="utf-8")
            temp.chmod(0o440 if "sudoers" in directory else 0o644)
            out = subprocess.run(
                [*argv, str(temp)], capture_output=True, text=True, timeout=30, check=False
            )
            status = PASS if out.returncode == 0 else FAIL
            detail = (out.stdout + out.stderr).strip().splitlines()
            print(f"  {status}  {write.path}  {label}: {detail[0] if detail else 'clean'}")
        finally:
            temp.unlink(missing_ok=True)

    # apt.conf has no -t flag, but apt-config will parse a file we point it at.
    apt_write = next((w for w in plan.writes if "apt.conf.d" in w.path), None)
    if apt_write and shutil.which("apt-config"):
        handle, name = tempfile.mkstemp(suffix=".conf")
        temp = Path(name)
        try:
            temp.write_text(apt_write.content, encoding="utf-8")
            out = subprocess.run(
                ["apt-config", "dump"],
                capture_output=True, text=True, timeout=20, check=False,
                env={"APT_CONFIG": str(temp), "PATH": "/usr/bin:/bin"},
            )
            ok = out.returncode == 0 and "Syntax error" not in out.stderr
            print(f"  {PASS if ok else FAIL}  {apt_write.path}  apt-config parses it")
        finally:
            temp.unlink(missing_ok=True)

    # sysctl can be asked to parse without applying.
    sysctl_write = next((w for w in plan.writes if "sysctl.d" in w.path), None)
    if sysctl_write and Path("/usr/sbin/sysctl").exists():
        handle, name = tempfile.mkstemp(suffix=".conf")
        temp = Path(name)
        try:
            temp.write_text(sysctl_write.content, encoding="utf-8")
            out = subprocess.run(
                ["/usr/sbin/sysctl", "--dry-run", "-p", str(temp)],
                capture_output=True, text=True, timeout=30, check=False,
            )
            bad = [
                l for l in (out.stdout + out.stderr).splitlines()
                if "cannot stat" in l or "unknown key" in l or "Invalid" in l
            ]
            print(
                f"  {PASS if not bad else FAIL}  {sysctl_write.path}  "
                f"sysctl --dry-run: {len(bad)} unusable key(s)"
            )
            for line in bad[:6]:
                print(f"          {line.strip()}")
        finally:
            temp.unlink(missing_ok=True)


def main() -> int:
    catalogue = catalogue_module.load()

    print("Target audit")
    print("=" * 74)
    seen: set[str] = set()
    for section in catalogue.sections:
        for target in section.targets():
            if not target or target in seen:
                continue
            seen.add(target)
            owning = [f for f in section.flags if section.target_for(f) == target]
            in_place = section.in_place or any(f.in_place for f in owning)
            audit_target(section, target, in_place)

    width = max(len(t) for _s, t, _d in results)
    for status, target, detail in results:
        print(f"  {status}  {target:<{width}}  {detail}")

    validate_rendered(catalogue)

    failures = [r for r in results if r[0] == FAIL]
    warnings = [r for r in results if r[0] == WARN]
    print("\n" + "=" * 74)
    print(f"{len(seen)} targets · {len(failures)} failure(s) · {len(warnings)} warning(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
