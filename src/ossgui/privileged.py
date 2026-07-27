"""Client side of the pkexec handoff — one password prompt per Apply.

The GUI stages changes unprivileged and renders its own copy of the plan for the
review diff; this module is the only thing that crosses the privilege boundary,
and all it sends is a mapping of flag ids to values.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path

from . import apply as apply_module, paths

#: pkexec asks for a password and the user may take their time over it.
APPLY_TIMEOUT = 900

#: pkexec's own exit code for "the user dismissed the authentication dialog".
PKEXEC_CANCELLED = 126
PKEXEC_FAILED = 127


@dataclass
class ApplyOutcome:
    """The helper's result, plus whether we even got that far."""

    ok: bool
    cancelled: bool = False
    error: str = ""
    steps: list[dict] = field(default_factory=list)
    outcomes: dict[str, str] = field(default_factory=dict)
    needs_reboot: list[str] = field(default_factory=list)
    rolled_back: bool = False
    #: Firewall state, populated by read_firewall().
    firewall: dict = field(default_factory=dict)
    #: AppArmor state, populated by read_apparmor().
    apparmor: dict = field(default_factory=dict)
    #: Integrity results, populated by the integrity_* calls.
    integrity: dict = field(default_factory=dict)
    raw: str = ""

    @property
    def failed_flags(self) -> list[str]:
        return [k for k, v in self.outcomes.items() if v in ("failed", "didnt-take")]


def _payload_dir() -> Path:
    """A private directory for the payload, so nothing can swap it under us."""
    base = os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
    directory = Path(base) / paths.PROG
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    return directory


def build_payload(
    selection: dict[str, str],
    sections: list[str] | None = None,
    firewall: dict | None = None,
    unit_changes: dict[str, str] | None = None,
    apparmor_changes: dict[str, str] | None = None,
    extras: dict | None = None,
    snap_changes: dict[str, str] | None = None,
    package_removals: list[str] | None = None,
    accounts: dict | None = None,
) -> dict:
    payload: dict = {"version": 1, "selection": dict(selection)}
    if sections is not None:
        payload["sections"] = list(sections)
    if firewall is not None:
        payload["ufw"] = firewall
    if unit_changes:
        payload["units"] = dict(unit_changes)
    if apparmor_changes:
        payload["apparmor"] = dict(apparmor_changes)
    if snap_changes:
        payload["snap"] = dict(snap_changes)
    if package_removals:
        payload["packages"] = {"remove": sorted(package_removals)}
    if accounts:
        payload["accounts"] = accounts
    for key, value in (extras or {}).items():
        if value:
            payload[key] = value
    return payload


def read_firewall() -> ApplyOutcome:
    """One privileged read of the firewall rules, writing nothing.

    `ufw status` needs root and the rule files are root-only, so the rule list
    cannot be shown without this. Policies and the enabled state come from
    readable files and are already on screen before this runs.
    """
    return _invoke({"version": 1, "action": "read-firewall"})


def read_apparmor() -> ApplyOutcome:
    """One privileged read of live AppArmor modes and unconfined processes.

    /sys/kernel/security/apparmor is root-only, so the configured mode (from
    symlinks anyone can see) is on screen first and this fills in what is
    actually running.
    """
    return _invoke({"version": 1, "action": "read-apparmor"})


def integrity_verify() -> ApplyOutcome:
    """Tier 1 package verification, run as root so nothing is skipped.

    `dpkg -V` works unprivileged but cannot stat root-only paths, so a plain-user
    run silently misses part of the filesystem.
    """
    return _invoke({"version": 1, "action": "integrity-verify"})


def integrity_baseline() -> ApplyOutcome:
    """Hash the watched paths and store the baseline."""
    return _invoke({"version": 1, "action": "integrity-baseline"})


def integrity_check() -> ApplyOutcome:
    """Rescan and report what changed since the baseline."""
    return _invoke({"version": 1, "action": "integrity-check"})


def apply(
    selection: dict[str, str],
    sections: list[str] | None = None,
    firewall: dict | None = None,
    unit_changes: dict[str, str] | None = None,
    apparmor_changes: dict[str, str] | None = None,
    extras: dict | None = None,
    snap_changes: dict[str, str] | None = None,
    package_removals: list[str] | None = None,
    accounts: dict | None = None,
    on_progress=None,
) -> ApplyOutcome:
    """Hand the selection to the helper through pkexec and parse the result.

    *on_progress* is called from a reader thread with each line the helper
    reports, so the dialog can say what is happening instead of spinning.
    """
    return _invoke(
        build_payload(
            selection, sections, firewall, unit_changes, apparmor_changes, extras,
            snap_changes, package_removals, accounts,
        ),
        on_progress,
    )


def _invoke(payload: dict, on_progress=None) -> ApplyOutcome:
    """Write the payload somewhere private and run the helper under pkexec."""
    helper = paths.helper_path()
    if not Path(helper).exists():
        return ApplyOutcome(
            False,
            error=(
                f"The privileged helper is not installed at {helper}, so nothing "
                f"can be applied. This is expected when running from a source "
                f"checkout — the helper ships in the package. Install it with:\n\n"
                f"    sudo dpkg -i build/oss_0.1.0_all.deb"
            ),
        )
    if shutil.which("pkexec") is None:
        return ApplyOutcome(False, error="pkexec is not available on this system")

    directory = _payload_dir()
    handle, name = tempfile.mkstemp(dir=directory, suffix=".json", prefix="apply-")
    payload_path = Path(name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(payload, stream)
        os.chmod(payload_path, stat.S_IRUSR | stat.S_IWUSR)

        try:
            stdout, stderr, returncode = _run_streaming(
                ["pkexec", helper, str(payload_path)], on_progress
            )
        except subprocess.TimeoutExpired:
            return ApplyOutcome(False, error="the helper did not finish in time")
        except OSError as exc:
            return ApplyOutcome(False, error=f"could not start pkexec: {exc}")

        completed = _Completed(stdout, stderr, returncode)
        if completed.returncode == PKEXEC_CANCELLED:
            return ApplyOutcome(False, cancelled=True, error="Authentication cancelled.")
        if completed.returncode == PKEXEC_FAILED and not completed.stdout.strip():
            return ApplyOutcome(
                False,
                error="pkexec refused to run the helper: "
                + (completed.stderr.strip() or "no detail given"),
            )

        return _parse(completed.stdout, completed.stderr, completed.returncode)
    finally:
        payload_path.unlink(missing_ok=True)


@dataclass
class _Completed:
    """The shape subprocess.run used to hand back, kept so _parse is unchanged."""

    stdout: str
    stderr: str
    returncode: int


def _run_streaming(argv: list[str], on_progress) -> tuple[str, str, int]:
    """Run the helper, forwarding its progress lines as they arrive.

    subprocess.run() would block until the helper exits, which is why the
    dialog could only show a spinner: on a real machine update-initramfs and a
    couple of dozen systemctl calls take minutes, and "still going" looked
    identical to "hung". stderr is read line by line while it runs; stdout is
    collected whole, because that is the JSON result.
    """
    process = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    stderr_lines: list[str] = []

    def pump() -> None:
        assert process.stderr is not None
        for line in process.stderr:
            stderr_lines.append(line)
            if on_progress is not None and line.startswith(apply_module.PROGRESS_PREFIX):
                on_progress(line[len(apply_module.PROGRESS_PREFIX):].strip())

    # One reader thread per pipe, and the timeout enforced by wait() on the
    # main thread.
    #
    # Deliberately not communicate(): it reads *both* pipes itself, so with the
    # pump already on stderr there were two readers on one stream and
    # communicate() closed it mid-iteration, silently dropping 73KB of 256KB in
    # the test. But reading stdout inline here instead is no better — read()
    # blocks until the helper exits, so APPLY_TIMEOUT never fires and a hung
    # helper hangs the application with it. Both of those were real, and both
    # were caught by tests/test_streaming.py rather than by reasoning about it.
    stdout_chunks: list[str] = []

    def collect() -> None:
        assert process.stdout is not None
        stdout_chunks.append(process.stdout.read())

    readers = [
        threading.Thread(target=pump, daemon=True),
        threading.Thread(target=collect, daemon=True),
    ]
    for reader in readers:
        reader.start()

    try:
        try:
            process.wait(timeout=APPLY_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise
    finally:
        # Joined on every path, timeout included: a reader still blocked on a
        # pipe after this returns is a thread leaked per apply.
        for reader in readers:
            reader.join(timeout=5)
        for pipe in (process.stdout, process.stderr):
            if pipe is not None and not pipe.closed:
                pipe.close()

    return "".join(stdout_chunks), "".join(stderr_lines), process.returncode


def _parse(stdout: str, stderr: str, returncode: int) -> ApplyOutcome:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return ApplyOutcome(
            False,
            error=(stderr.strip() or stdout.strip() or f"helper exited {returncode}"),
            raw=stdout,
        )
    return ApplyOutcome(
        ok=bool(data.get("ok")),
        error=str(data.get("error", "")),
        steps=list(data.get("steps", [])),
        outcomes=dict(data.get("outcomes", {})),
        needs_reboot=list(data.get("needs_reboot", [])),
        rolled_back=bool(data.get("rolled_back", False)),
        firewall=dict(data.get("ufw", {})),
        apparmor=dict(data.get("apparmor", {})),
        integrity=dict(data.get("integrity", {})),
        raw=stdout,
    )


def run_user_commands(commands, on_progress=None) -> list[tuple[str, bool, str]]:
    """Run the unprivileged half of a plan — gsettings writes the *user's* dconf.

    These deliberately never go through pkexec: run as root they would write
    root's dconf database and change nothing about the logged-in session.
    """
    results = []
    total = len(commands)
    for index, command in enumerate(commands, 1):
        # Each of these spawns a process with a 30s ceiling, so a stalled dconf
        # can hold the whole run for minutes. Reporting per command is the
        # difference between "slow" and "the dialog has died".
        if on_progress is not None:
            on_progress(f"Applying desktop settings  ({index} of {total})")
        try:
            completed = subprocess.run(
                list(command.argv), capture_output=True, text=True, timeout=30, check=False
            )
            output = (completed.stdout + completed.stderr).strip()
            results.append((str(command), completed.returncode == 0, output))
        except (OSError, subprocess.SubprocessError) as exc:
            results.append((str(command), False, str(exc)))
    return results
