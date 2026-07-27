"""The apply transaction: validate, back up, write, reload, read back, report.

This runs inside the privileged helper. It is deliberately the only place in the
codebase that writes to the system, and it never trusts anything from the GUI
except a mapping of flag ids to values — every file it writes it renders itself
from the shipped catalogue (§9).

Transaction shape (§8)::

    back up each target to .bak
    validate   sshd -t · visudo -c · auditctl dry run
    write files
    run reload commands, checking exit codes
    on failure: restore .bak, re-run reloads, report
    read each value back and compare to what was intended
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import accounts as accounts_module
from . import apparmor as apparmor_module
from . import bootloader as bootloader_module
from . import filemode as filemode_module
from . import fstab as fstab_module
from . import permissions as permissions_module
from . import distro, probe, render, ufw as ufw_module, units as units_module
from . import sandbox as sandbox_module
from . import packages as packages_module
from . import snapd as snapd_module
from . import usb as usb_module
from .catalogue import Catalogue
from .render import ALLOWED_COMMANDS, Plan

#: How long any single command in the transaction gets. update-initramfs is slow.
COMMAND_TIMEOUT = 300

#: A full-system hash walk is minutes of CPU, not seconds (§4.24.8).
SCAN_TIMEOUT = 1800

BACKUP_SUFFIX = ".bak"


@dataclass
class Step:
    """One thing that happened, in order, for the report."""

    kind: str  # backup | write | remove | command | validate | readback
    detail: str
    ok: bool = True
    output: str = ""


@dataclass
class Result:
    """What the helper hands back to the GUI."""

    ok: bool = True
    steps: list[Step] = field(default_factory=list)
    #: flag id -> "applied" | "pending-reboot" | "failed" | "didnt-take"
    outcomes: dict[str, str] = field(default_factory=dict)
    error: str = ""
    rolled_back: bool = False
    needs_reboot: list[str] = field(default_factory=list)
    #: Firewall state, for the read-only query the ufw page makes at open time.
    ufw: dict = field(default_factory=dict)
    #: AppArmor live modes and unconfined processes, for the same reason.
    apparmor: dict = field(default_factory=dict)
    #: Integrity results: package verification, or a baseline capture/check.
    integrity: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


#: Prefix marking a progress line on stderr. stdout carries the JSON result and
#: has to stay parseable, so progress goes to stderr one flushed line at a time.
PROGRESS_PREFIX = "@@ "


def progress(text: str) -> None:
    """Tell the GUI what the transaction is doing right now.

    The helper is a single subprocess that says nothing until it exits, so
    without this the dialog can only spin — and a slow update-initramfs looks
    exactly like a hang. Anything that can take more than a moment reports
    before it starts, not after it finishes.
    """
    print(f"{PROGRESS_PREFIX}{text}", file=sys.stderr, flush=True)


class ApplyError(Exception):
    """Something went wrong badly enough to roll the transaction back."""


def target_path(path: str) -> Path:
    """Resolve a catalogue target, honouring a test root.

    ``OSS_ROOT`` relocates every write under a sandbox directory so the
    transaction can be exercised for real in tests. It is ignored outright when
    running as root, so it can never redirect the privileged helper's writes.
    """
    prefix = os.environ.get("OSS_ROOT") if os.geteuid() != 0 else None
    if not prefix:
        return Path(path)
    return Path(prefix) / path.lstrip("/")


# --------------------------------------------------------------------------- #
#  Payload validation — the helper's real security boundary
# --------------------------------------------------------------------------- #


def validate_payload(catalogue: Catalogue, payload: dict) -> dict[str, str]:
    """Check the GUI's request against the catalogue and return the selection.

    Every id must exist and every value must be allowed by the flag's own rules.
    Nothing here is interpolated into a shell, and no file content from the
    payload is used — that is what keeps the helper short enough to audit.
    """
    if not isinstance(payload, dict):
        raise ApplyError("payload is not an object")
    if payload.get("version") != 1:
        raise ApplyError(f"unsupported payload version {payload.get('version')!r}")

    raw = payload.get("selection")
    if not isinstance(raw, dict):
        raise ApplyError("payload has no selection object")

    selection: dict[str, str] = {}
    for flag_id, value in raw.items():
        if not isinstance(flag_id, str) or not isinstance(value, str):
            raise ApplyError("selection keys and values must both be strings")
        flag = catalogue.get(flag_id)
        if flag is None:
            raise ApplyError(f"unknown flag id {flag_id!r}")
        section = catalogue.section(flag.section)
        if not section.implemented:
            raise ApplyError(f"section {section.id!r} cannot be applied by this build")
        if not flag.value_is_allowed(value):
            raise ApplyError(f"value {value!r} is not allowed for flag {flag_id!r}")
        selection[flag_id] = value

    sections = payload.get("sections")
    if sections is not None:
        if not isinstance(sections, list) or not all(isinstance(s, str) for s in sections):
            raise ApplyError("sections must be a list of strings")
        known = {s.id for s in catalogue.sections}
        for section_id in sections:
            if section_id not in known:
                raise ApplyError(f"unknown section {section_id!r}")

    return selection


# --------------------------------------------------------------------------- #
#  File operations
# --------------------------------------------------------------------------- #


def _refuse_symlink(path: Path) -> None:
    """Never write through a symlink — that is how a drop-in becomes a shell."""
    if path.is_symlink():
        raise ApplyError(f"{path} is a symlink; refusing to write through it")


def backup(path: Path) -> Path | None:
    """Copy *path* to ``path.bak``, preserving mode and owner. Idempotent-safe."""
    if not path.exists():
        return None
    _refuse_symlink(path)
    destination = path.with_name(path.name + BACKUP_SUFFIX)
    shutil.copy2(path, destination)
    if os.geteuid() == 0:
        stat = path.stat()
        os.chown(destination, stat.st_uid, stat.st_gid)
    return destination


def write_atomic(path: Path, content: str, mode: int) -> None:
    """Write via a temp file in the same directory, then rename over the target."""
    _refuse_symlink(path)
    _ensure_parent(path)
    handle, temp_name = tempfile.mkstemp(dir=path.parent, prefix=".oss-")
    temp = Path(temp_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, mode)
        if os.geteuid() == 0:
            os.chown(temp, 0, 0)
        os.replace(temp, path)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


def restore(path: Path) -> bool:
    """Put the .bak back. Returns False when there was nothing to restore."""
    # Same rule as backup() and write_atomic(): a target that has become a
    # symlink since the transaction started must not be written through, or the
    # rollback becomes the write primitive the rest of this module refuses to
    # offer.
    _refuse_symlink(path)
    backup_path = path.with_name(path.name + BACKUP_SUFFIX)
    if not backup_path.exists():
        # No backup means the file did not exist before this transaction.
        path.unlink(missing_ok=True)
        return True
    shutil.copy2(backup_path, path)
    return True


def run(argv: tuple[str, ...] | list[str], stdin: str | None = None) -> tuple[int, str]:
    """Run one allowlisted command. Returns ``(returncode, combined output)``."""
    argv = list(argv)
    if argv[0] not in ALLOWED_COMMANDS:
        raise ApplyError(f"command not on the allowlist: {argv[0]}")
    try:
        result = subprocess.run(
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {COMMAND_TIMEOUT}s"
    except OSError as exc:
        return 127, str(exc)
    return result.returncode, (result.stdout + result.stderr).strip()


# --------------------------------------------------------------------------- #
#  Pre-write validators — what stops §4.7, §4.9 and §4.14 locking you out
# --------------------------------------------------------------------------- #


def validate_write(write: render.FileWrite, result: Result) -> None:
    """Run the syntax checker for this target against a candidate copy.

    The candidate is written to a temp file and checked *before* the real file is
    touched, so a config that would break sshd or sudo never reaches disk.
    """
    path = target_path(write.path)
    if "/sshd_config.d/" in write.path:
        _validate_sshd(write, result)
    elif "/sudoers.d/" in write.path or path.name == "sudoers":
        _validate_sudoers(write, result)
    elif "/audit/rules.d/" in write.path:
        _validate_auditd(write, result)


def _ensure_parent(path: Path) -> None:
    """Create a target's directory with an explicit mode.

    Never the inherited umask: a directory pkexec's environment happened to
    create 0777 would be a hole opened by the tool that exists to close them,
    and ``/etc/sudoers.d`` is one of the directories this creates.
    """
    if not path.parent.is_dir():
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, 0o755)


def _with_candidate(write: render.FileWrite):
    """Context: the candidate content in a temp file next to the real target."""
    path = target_path(write.path)
    # Validation runs before any write, so this is usually what creates the
    # directory — doing it without a mode here would leave write_atomic's own
    # guard with nothing left to guard.
    _ensure_parent(path)
    handle, name = tempfile.mkstemp(dir=path.parent, prefix=".oss-check-")
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        stream.write(write.content)
    os.chmod(name, write.mode)
    return Path(name)


def _validate_sshd(write: render.FileWrite, result: Result) -> None:
    if not Path("/usr/sbin/sshd").exists():
        return  # openssh-server not installed; nothing will read this file yet
    candidate = _with_candidate(write)
    try:
        # -T with the drop-in in place makes sshd parse the whole effective config.
        code, output = run(["/usr/sbin/sshd", "-t", "-f", "/etc/ssh/sshd_config"])
        # The drop-in isn't in place yet, so also check the fragment on its own.
        fragment_code, fragment_output = run(["/usr/sbin/sshd", "-t", "-f", str(candidate)])
        ok = fragment_code == 0
        result.steps.append(
            Step("validate", f"sshd -t {write.path}", ok, fragment_output or output)
        )
        if not ok:
            raise ApplyError(f"sshd rejected the candidate config: {fragment_output}")
    finally:
        candidate.unlink(missing_ok=True)


def _validate_sudoers(write: render.FileWrite, result: Result) -> None:
    candidate = _with_candidate(write)
    try:
        code, output = run(["/usr/sbin/visudo", "-c", "-f", str(candidate)])
        ok = code == 0
        result.steps.append(Step("validate", f"visudo -c {write.path}", ok, output))
        if not ok:
            # A broken sudoers file costs root access. Never install one.
            raise ApplyError(f"visudo rejected the candidate sudoers file: {output}")
    finally:
        candidate.unlink(missing_ok=True)


def _validate_auditd(write: render.FileWrite, result: Result) -> None:
    if not Path("/usr/sbin/auditctl").exists():
        return  # auditd not installed
    candidate = _with_candidate(write)
    try:
        # Strip the immutable directive for the check: -e 2 would lock the running
        # rule set during a dry run and make every later change need a reboot.
        checkable = "\n".join(
            line for line in write.content.splitlines() if line.strip() != "-e 2"
        )
        candidate.write_text(checkable + "\n", encoding="utf-8")
        code, output = run(["/usr/sbin/auditctl", "-R", str(candidate)])
        ok = code == 0
        result.steps.append(Step("validate", f"auditctl -R {write.path}", ok, output))
        if not ok:
            raise ApplyError(f"auditctl rejected the candidate rules: {output}")
    finally:
        candidate.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
#  The transaction
# --------------------------------------------------------------------------- #


def apply_plan(
    catalogue: Catalogue,
    plan: Plan,
    selection: dict[str, str],
    firewall: "ufw_module.State | None" = None,
    unit_changes: dict[str, str] | None = None,
    apparmor_changes: dict[str, str] | None = None,
    extras: dict | None = None,
    snap_changes: dict[str, str] | None = None,
    package_removals: list[str] | None = None,
    package_purge: bool = False,
    account_changes: list[tuple[list[str], str]] | None = None,
) -> Result:
    """Run the whole transaction, rolling back on any failure."""
    result = Result()

    problems = render.validate_commands(plan)
    if problems:
        result.ok = False
        result.error = "; ".join(problems)
        return result

    touched: list[Path] = []
    # Captured before anything changes: the rollback needs to know what each
    # unit's enablement was *before* this transaction to undo a mask correctly,
    # and after the fact that information is gone.
    prior_units = probe.read_units() if any(c.mutates for c in plan.commands) else {}
    try:
        # 1. Validate every candidate before anything is written.
        progress(f"Checking {len(plan.writes)} file(s) before writing anything")
        for write in plan.writes:
            # A drop-in whose directory nothing includes is a file that gets
            # silently ignored. Better to fail loudly than to report success.
            directory = str(Path(write.path).parent)
            status, detail = probe.include_check(directory)
            if status == "missing":
                raise ApplyError(
                    f"{write.path} would be ignored: {detail}"
                )
            validate_write(write, result)

        # 2. Back up, then write.
        for index, write in enumerate(plan.writes, 1):
            progress(f"Writing {write.path}  ({index} of {len(plan.writes)})")
            path = target_path(write.path)
            if backup(path) is not None:
                result.steps.append(Step("backup", f"{write.path} -> {write.path}{BACKUP_SUFFIX}"))
            write_atomic(path, write.content, write.mode)
            touched.append(path)
            result.steps.append(Step("write", write.path))

        for removal in plan.removes:
            path = target_path(removal.path)
            if path.exists():
                backup(path)
                path.unlink()
                touched.append(path)
                result.steps.append(Step("remove", removal.path))

        # 3. Reload. An exit code here means the system rejected our work.
        for index, command in enumerate(plan.commands, 1):
            progress(f"{command.why or str(command)}  ({index} of {len(plan.commands)})")
            code, output = run(command.argv)
            ok = code == 0
            result.steps.append(Step("command", str(command), ok, output))
            if not ok:
                raise ApplyError(f"{command} failed with exit {code}: {output}")

        extras = extras or {}
        if "sandbox" in extras:
            apply_sandbox(extras["sandbox"], result, touched)
        if "permissions" in extras:
            apply_permissions(extras["permissions"], result)
        if "bootloader" in extras:
            apply_bootloader(extras["bootloader"], result, touched)
        if "fstab" in extras:
            apply_fstab(extras["fstab"], result, touched)
        if "usb" in extras:
            apply_usb(extras["usb"], result, touched)
        if "filemode" in extras:
            apply_filemode(extras["filemode"], result)

        # Package removal goes last of all: it is the only step that cannot be
        # rolled back by restoring a file, so everything else should already have
        # succeeded before we get here.
        for argv, why in packages_module.plan_commands(
            package_removals or [], package_purge
        ):
            code, output = run(argv)
            ok = code == 0
            result.steps.append(Step("command", " ".join(argv), ok, output[-2000:]))
            if not ok:
                raise ApplyError(f"{why} failed: {output[-400:]}")

        # Account deletion goes right after packages: also not something a
        # restored .bak can undo, so it waits until everything reversible has
        # already succeeded.
        for argv, why in accounts_module.plan_commands(account_changes or []):
            code, output = run(argv)
            ok = code == 0
            result.steps.append(Step("command", " ".join(argv), ok, output))
            if not ok:
                raise ApplyError(f"{why} failed: {output}")

        # Snap interfaces: snapd applies these immediately, no reload needed.
        for argv, why in snapd_module.plan_commands(snap_changes or {}):
            code, output = run(argv)
            ok = code == 0
            result.steps.append(Step("command", " ".join(argv), ok, output))
            if not ok:
                raise ApplyError(f"{why} failed: {output}")

        # 4. AppArmor profile modes, which are symlinks plus a parser reload.
        if apparmor_changes:
            apply_apparmor(apparmor_changes, result)

        # 5. Arbitrary unit changes, which the flag catalogue cannot express.
        for argv, why in units_module.plan_commands(unit_changes or {}):
            code, output = run(argv)
            ok = code == 0
            result.steps.append(Step("command", " ".join(argv), ok, output))
            if not ok:
                raise ApplyError(f"{why} failed: {output}")

        # 6. The firewall, last: its rules are the thing most likely to cut the
        #    connection this session is running over.
        if firewall is not None:
            apply_firewall(firewall, result)

    except ApplyError as exc:
        result.ok = False
        result.error = str(exc)
        result.rolled_back = _rollback(touched, plan, result, prior_units)
        return result
    except OSError as exc:
        result.ok = False
        result.error = f"{type(exc).__name__}: {exc}"
        result.rolled_back = _rollback(touched, plan, result, prior_units)
        return result

    # 4. Read back. Invalid sysctl keys fail silently, so this is the only way to
    #    know whether what we wrote actually took (§8).
    progress(f"Reading {len(selection)} setting(s) back off the live system")
    result.outcomes, result.needs_reboot = read_back(catalogue, selection)
    result.steps.append(
        Step("readback", f"{len(result.outcomes)} flags re-read", True)
    )
    return result


def unit_inverse(argv: tuple[str, ...], prior: dict[str, str]) -> tuple[str, ...] | None:
    """The command that puts a unit back the way *prior* says it was.

    ``systemctl mask`` and ``disable`` have no file behind them for a rollback
    to restore, and they are not self-inverse, so undoing them means issuing
    the opposite command — but only as far as the unit's own starting state.
    Blindly unmasking would *enable* something the user had masked themselves
    long before this transaction, which is a worse outcome than the failure
    being recovered from.
    """
    if len(argv) < 3 or argv[0] != "/usr/bin/systemctl":
        return None
    action, unit = argv[1], argv[-1]
    was = prior.get(unit)
    if was is None:
        # Never seen in list-unit-files, so there is no prior state to restore
        # and no safe assumption to make about one.
        return None
    if action == "mask":
        if was == "masked":
            return None
        if was == "enabled":
            return ("/usr/bin/systemctl", "unmask", unit)
        return ("/usr/bin/systemctl", "unmask", unit)
    if action == "disable":
        if was == "enabled":
            return ("/usr/bin/systemctl", "enable", unit)
        return None
    return None


def _rollback(
    touched: list[Path],
    plan: Plan,
    result: Result,
    prior_units: dict[str, str] | None = None,
) -> bool:
    """Restore every file we changed and put the system back over the top.

    Reloads are re-run, because that is how a restored (or deleted) drop-in
    takes effect. Mutations are *not* — re-running ``systemctl mask --now``
    would apply it again rather than undo it — and are inverted from the unit
    state captured before the transaction started instead.
    """
    progress("Something failed — rolling the whole transaction back")
    restored = True
    for path in touched:
        try:
            restore(path)
            result.steps.append(Step("restore", str(path)))
        except (OSError, ApplyError) as exc:
            # ApplyError as well as OSError: restore() refuses a target that has
            # become a symlink, and letting that escape would abandon the
            # remaining files mid-rollback — the one moment where finishing
            # matters most.
            restored = False
            result.steps.append(Step("restore", str(path), False, str(exc)))

    prior_units = prior_units or {}
    for command in plan.commands:
        if not command.mutates:
            code, output = run(command.argv)
            result.steps.append(
                Step("command", f"rollback: {command}", code == 0, output)
            )
            continue

        inverse = unit_inverse(tuple(command.argv), prior_units)
        if inverse is None:
            result.steps.append(
                Step(
                    "command",
                    f"rollback: nothing to undo for {command}",
                    True,
                    "already in this state before the transaction, or no "
                    "recorded prior state to return to",
                )
            )
            continue
        code, output = run(inverse)
        if code != 0:
            restored = False
        result.steps.append(
            Step("command", f"rollback: {shlex.join(inverse)}", code == 0, output)
        )
    return restored


def read_back(
    catalogue: Catalogue, selection: dict[str, str]
) -> tuple[dict[str, str], list[str]]:
    """Re-read every selected flag and classify the outcome."""
    facts = probe.gather(catalogue)
    outcomes: dict[str, str] = {}
    needs_reboot: list[str] = []

    skip_cache: dict[str, str] = {}
    for flag_id, value in selection.items():
        flag = catalogue.get(flag_id)
        if flag is None:
            continue
        section = catalogue.section(flag.section)

        # A section the plan skipped wrote nothing, so there is nothing to read
        # back. Verifying it anyway found the value absent and called it "did
        # not take", which reports a failure for something never attempted —
        # on a desktop without openssh-server that is 26 phantom failures.
        if section.id not in skip_cache:
            skip_cache[section.id] = render.section_skip_reason(section)
        if skip_cache[section.id]:
            outcomes[flag_id] = "skipped"
            continue

        state = probe.flag_state(section, flag, facts, value)

        if state.state is probe.State.APPLIED:
            outcomes[flag_id] = "applied"
        elif state.state is probe.State.PENDING_REBOOT:
            outcomes[flag_id] = "pending-reboot"
            needs_reboot.append(flag_id)
        elif state.state is probe.State.INVALID:
            # The key does not exist here: we wrote a line that will never do
            # anything. Reporting success for this is exactly the bug §8 warns about.
            outcomes[flag_id] = "failed"
        elif state.state is probe.State.UNKNOWN:
            outcomes[flag_id] = "applied" if state.on_disk == value else "didnt-take"
        else:
            outcomes[flag_id] = "didnt-take"

    return outcomes, needs_reboot


def read_firewall() -> Result:
    """Read-only: the firewall state, including the root-only rule list.

    A separate action so the ufw page can load the current rules with one
    authentication and without staging or writing anything.
    """
    result = Result()
    state = ufw_module.read_unprivileged()
    code, output = run([ufw_module.UFW_BIN, "status", "verbose"])
    if code != 0:
        result.ok = False
        result.error = f"could not read the firewall: {output}"
        return result
    state.rules = ufw_module.parse_status(output)
    state.rules_loaded = True
    result.ufw = ufw_module.to_payload(state)
    result.steps.append(Step("readback", f"read {len(state.rules)} firewall rule(s)"))
    return result


def read_apparmor() -> Result:
    """Read-only: live profile modes and unconfined processes."""
    result = Result()
    output = apparmor_module.read_status_output()
    if output is None:
        result.ok = False
        result.error = "aa-status could not be run"
        return result
    try:
        modes, unconfined = apparmor_module.parse_status(output)
    except apparmor_module.ApparmorError as exc:
        result.ok = False
        result.error = str(exc)
        return result
    result.apparmor = {"modes": modes, "unconfined": unconfined}
    result.steps.append(Step("readback", f"read {len(modes)} apparmor profile(s)"))
    return result


def integrity_baseline() -> Result:
    """Hash the watched paths and store the baseline (§4.24.1 'init')."""
    from . import integrity as integrity_module

    result = Result()
    entries = integrity_module.scan()
    digest = integrity_module.save_baseline(entries)
    result.integrity = {
        "action": "baseline",
        "count": len(entries),
        "sha256": digest,
        "path": str(integrity_module.BASELINE_PATH),
    }
    result.steps.append(
        Step("write", f"baseline of {len(entries)} file(s) -> {integrity_module.BASELINE_PATH}")
    )
    return result


def integrity_check() -> Result:
    """Rescan and diff against the stored baseline (§4.24.1 'check')."""
    from . import integrity as integrity_module

    result = Result()
    baseline, created = integrity_module.load_baseline()
    if not baseline:
        result.ok = False
        result.error = "There is no baseline yet — capture one first."
        return result

    current = integrity_module.scan()
    findings = integrity_module.diff_baseline(baseline, current)
    result.integrity = {
        "action": "check",
        "created": created,
        "baseline_count": len(baseline),
        "scanned": len(current),
        "findings": [
            {
                "path": f.path,
                "attrs": f.attrs,
                "severity": f.severity,
                "reason": f.reason,
            }
            for f in findings[:2000]
        ],
    }
    result.steps.append(Step("readback", f"{len(findings)} change(s) since the baseline"))
    return result


def integrity_verify() -> Result:
    """Tier 1 package verification, run as root so nothing is unreadable."""
    from . import integrity as integrity_module

    result = Result()
    report = integrity_module.explain(integrity_module.verify())
    result.integrity = {
        "action": "verify",
        "tool": report.tool,
        "unreadable": report.unreadable,
        "error": report.error,
        "findings": [
            {
                "path": f.path,
                "attrs": f.attrs,
                "severity": f.severity,
                "reason": f.reason,
                "package": f.package,
                "explained_by": f.explained_by,
            }
            for f in report.findings
        ],
    }
    result.ok = report.ran
    result.error = report.error
    result.steps.append(Step("readback", f"{report.tool}: {len(report.findings)} finding(s)"))
    return result


def apply_sandbox(
    changes: dict[str, list[str]], result: Result, touched: list[Path] | None = None
) -> None:
    """Write or remove per-unit drop-ins, then reload systemd (§4.12)."""
    touched = touched if touched is not None else []
    changed = False
    for change in sandbox_module.plan_changes(changes):
        path = target_path(change.path)
        if change.removing:
            if path.exists():
                backup(path)
                path.unlink()
                touched.append(path)
                result.steps.append(Step("remove", change.path))
                changed = True
            continue
        backup(path)
        write_atomic(path, change.content, 0o644)
        touched.append(path)
        result.steps.append(Step("write", change.path))
        changed = True

    if changed:
        code, output = run(["/usr/bin/systemctl", "daemon-reload"])
        result.steps.append(Step("command", "systemctl daemon-reload", code == 0, output))
        if code != 0:
            raise ApplyError(f"daemon-reload failed: {output}")


def apply_bootloader(
    payload: dict, result: Result, touched: list[Path] | None = None
) -> None:
    """Install or remove the GRUB superuser password script (§4.23)."""
    path = target_path(bootloader_module.PASSWORD_SCRIPT)
    parsed = bootloader_module.from_payload(payload)

    if parsed is None:
        if path.exists():
            backup(path)
            path.unlink()
            (touched if touched is not None else []).append(path)
            result.steps.append(Step("remove", bootloader_module.PASSWORD_SCRIPT))
        else:
            return
    else:
        username, digest = parsed
        backup(path)
        (touched if touched is not None else []).append(path)
        # 0700: the file contains a password hash, and grub.d scripts are executed.
        write_atomic(path, bootloader_module.render_script(username, digest), 0o700)
        result.steps.append(Step("write", bootloader_module.PASSWORD_SCRIPT))

    # Resolved per family: update-grub is a Debian wrapper that does not exist
    # on Arch or Fedora. See ossgui.distro.
    argv = distro.resolve_command(("/usr/sbin/update-grub",))
    code, output = run(argv)
    result.steps.append(Step("command", shlex.join(argv), code == 0, output))
    if code != 0:
        raise ApplyError(f"{shlex.join(argv)} failed: {output}")


def apply_permissions(changes: list, result: Result) -> None:
    """chmod/chown with a rollback journal, because there is no file to delete."""
    import json as json_module

    journal_path = target_path(str(permissions_module.JOURNAL_PATH))
    journal: list[dict] = []
    try:
        journal = json_module.loads(journal_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        journal = []

    for change in changes:
        path = target_path(change.path)
        if not path.exists():
            result.steps.append(Step("write", f"{change.path} does not exist", False, "skipped"))
            continue
        stat = path.lstat()
        change.before_mode = stat.st_mode & 0o7777

        # Record the before-state *first*: if the chmod succeeds and something
        # later fails, the journal is what makes undo possible at all.
        journal.append({
            "path": change.path,
            "before_mode": change.before_mode,
            "before_uid": stat.st_uid,
            "before_gid": stat.st_gid,
            "after_mode": change.mode,
        })
        journal_path.parent.mkdir(parents=True, exist_ok=True)
        write_atomic(journal_path, json_module.dumps(journal, indent=1), 0o600)

        os.chmod(path, change.mode)
        result.steps.append(
            Step("write", f"{change.path}: {change.before_mode:04o} -> {change.mode:04o}")
        )

        if change.owner or change.group:
            import grp as grp_module
            import pwd as pwd_module

            uid = pwd_module.getpwnam(change.owner).pw_uid if change.owner else -1
            gid = grp_module.getgrnam(change.group).gr_gid if change.group else -1
            os.chown(path, uid, gid)
            result.steps.append(
                Step("write", f"{change.path}: owner -> {change.owner}:{change.group}")
            )


def apply_filemode(changes: list, result: Result) -> None:
    """Change the mode of arbitrary paths, journalling the before-state first.

    A statoverride is recorded through dpkg so a package upgrade cannot quietly
    put the old mode back; a plain chmod is done here so the rollback journal is
    written before the change, not after.
    """
    import json as json_module

    journal_path = target_path(str(permissions_module.JOURNAL_PATH))
    try:
        journal = json_module.loads(journal_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        journal = []

    for change in changes:
        path = target_path(change.path)
        if not path.exists():
            result.steps.append(
                Step("write", f"{change.path} does not exist", False, "skipped")
            )
            continue

        stat = path.lstat()
        change.before_mode = stat.st_mode & 0o7777
        journal.append({
            "path": change.path,
            "before_mode": change.before_mode,
            "before_uid": stat.st_uid,
            "before_gid": stat.st_gid,
            "after_mode": change.mode,
            "durable": change.durable,
        })
        journal_path.parent.mkdir(parents=True, exist_ok=True)
        write_atomic(journal_path, json_module.dumps(journal, indent=1), 0o600)

        if not change.durable:
            os.chmod(path, change.mode)
            result.steps.append(Step("write", change.summary))

    # The durable form and the immutable flag are programs, so they run after the
    # journal is safely on disk.
    for argv, why in filemode_module.plan_commands(changes):
        code, output = run(argv)
        ok = code == 0
        result.steps.append(Step("command", " ".join(argv), ok, output))
        if not ok:
            raise ApplyError(f"{why} failed: {output}")


def apply_fstab(
    changes: dict[str, set[str]], result: Result, touched: list[Path] | None = None
) -> None:
    """Test every option set with a live remount before touching fstab (§4.10).

    This is the whole safety story for this section: an option combination the
    kernel rejects fails here, with the filesystem still mounted as it was,
    rather than at boot with no way to fix it.
    """
    path = target_path(fstab_module.FSTAB)
    try:
        current = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ApplyError(f"cannot read {fstab_module.FSTAB}: {exc}") from exc

    entries = {e.mount: e for e in fstab_module.parse(current)}
    for mount, options in changes.items():
        entry = entries.get(mount)
        if entry is None:
            raise ApplyError(f"no fstab entry for {mount}")
        argv = fstab_module.remount_argv(mount, options, entry)
        code, output = run(argv)
        result.steps.append(Step("validate", " ".join(argv), code == 0, output))
        if code != 0:
            raise ApplyError(
                f"{mount} could not be remounted with those options, so fstab was "
                f"not touched: {output}"
            )

    backup(path)
    write_atomic(path, fstab_module.render_fstab(current, changes), 0o644)
    # Registered for rollback: of everything this transaction writes, an fstab
    # left in a half-applied state is the one that costs you the next boot.
    (touched if touched is not None else []).append(path)
    result.steps.append(Step("write", fstab_module.FSTAB))


def apply_usb(
    payload: dict, result: Result, touched: list[Path] | None = None
) -> None:
    """Write the USBGuard policy, and only then consider enabling it (§4.18)."""
    parsed = usb_module.from_payload(payload)

    registry = touched if touched is not None else []

    rules_path = target_path(usb_module.RULES_PATH)
    backup(rules_path)
    write_atomic(rules_path, parsed["rules"], 0o600)
    registry.append(rules_path)
    result.steps.append(Step("write", usb_module.RULES_PATH))

    config_path = target_path(usb_module.CONFIG_PATH)
    backup(config_path)
    write_atomic(config_path, usb_module.daemon_config(parsed["implicit"]), 0o600)
    registry.append(config_path)
    result.steps.append(Step("write", usb_module.CONFIG_PATH))

    if parsed["enable"]:
        for argv in (
            ["/usr/bin/systemctl", "enable", "--now", "usbguard.service"],
        ):
            code, output = run(argv)
            result.steps.append(Step("command", " ".join(argv), code == 0, output))
            if code != 0:
                raise ApplyError(f"could not start usbguard: {output}")


def apply_apparmor(changes: dict[str, str], result: Result) -> None:
    """Set profile modes by managing the symlinks, then reloading each profile."""
    for change in apparmor_module.plan_changes(changes):
        for link in change.remove:
            path = target_path(link)
            # Only ever a symlink we own, never a real file.
            if path.is_symlink():
                path.unlink()
                result.steps.append(Step("remove", link))

        for link, destination in change.create:
            path = target_path(link)
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_symlink():
                path.unlink()
            elif path.exists():
                raise ApplyError(f"{link} exists and is not a symlink; refusing to replace it")
            path.symlink_to(destination)
            result.steps.append(Step("write", f"{link} -> {destination}"))

        code, output = run(change.command)
        ok = code == 0
        result.steps.append(Step("command", " ".join(change.command), ok, output))
        if not ok:
            raise ApplyError(f"{change.why} failed: {output}")


def apply_firewall(wanted: ufw_module.State, result: Result) -> None:
    """Run the firewall commands, appending each to the report."""
    current = ufw_module.read_unprivileged()
    code, output = run([ufw_module.UFW_BIN, "status", "verbose"])
    if code == 0:
        current.rules = ufw_module.parse_status(output)
        current.rules_loaded = True

    for argv, why in ufw_module.plan_commands(current, wanted):
        code, output = run(argv)
        ok = code == 0
        result.steps.append(Step("command", " ".join(argv), ok, output))
        if not ok:
            raise ApplyError(f"{why} failed: {output}")


def run_payload(catalogue: Catalogue, payload: dict) -> Result:
    """Validate a payload, render the plan ourselves, and run it."""
    action = payload.get("action", "apply")
    if action == "read-firewall":
        return read_firewall()
    if action == "read-apparmor":
        return read_apparmor()
    if action == "integrity-verify":
        return integrity_verify()
    if action == "integrity-baseline":
        return integrity_baseline()
    if action == "integrity-check":
        return integrity_check()
    if action != "apply":
        return Result(ok=False, error=f"unknown action {action!r}")

    try:
        selection = validate_payload(catalogue, payload)
    except ApplyError as exc:
        return Result(ok=False, error=str(exc))

    wanted_firewall = None
    if "ufw" in payload:
        try:
            wanted_firewall = ufw_module.from_payload(payload["ufw"])
        except ufw_module.UfwError as exc:
            return Result(ok=False, error=f"bad firewall payload: {exc}")

    unit_changes: dict[str, str] = {}
    if "units" in payload:
        try:
            unit_changes = units_module.from_payload(payload["units"])
        except units_module.UnitError as exc:
            return Result(ok=False, error=f"bad units payload: {exc}")

    extras: dict[str, object] = {}
    parsers = {
        "sandbox": (sandbox_module.from_payload, sandbox_module.SandboxError),
        "permissions": (permissions_module.from_payload, permissions_module.PermissionError_),
        "fstab": (fstab_module.from_payload, fstab_module.FstabError),
        "usb": (usb_module.from_payload, usb_module.UsbError),
        "filemode": (filemode_module.from_payload, filemode_module.ModeError),
    }
    for key, (parser, error_type) in parsers.items():
        if key in payload:
            try:
                extras[key] = parser(payload[key])
            except error_type as exc:
                return Result(ok=False, error=f"bad {key} payload: {exc}")
    if "bootloader" in payload:
        try:
            bootloader_module.from_payload(payload["bootloader"])
        except bootloader_module.BootloaderError as exc:
            return Result(ok=False, error=f"bad bootloader payload: {exc}")
        extras["bootloader"] = payload["bootloader"]

    package_removals: list[str] = []
    package_purge = False
    if "packages" in payload:
        try:
            package_removals, package_purge = packages_module.from_payload(
                payload["packages"]
            )
        except packages_module.PackageError as exc:
            return Result(ok=False, error=f"refusing this removal: {exc}")

    snap_changes: dict[str, str] = {}
    if "snap" in payload:
        try:
            snap_changes = snapd_module.from_payload(payload["snap"])
        except snapd_module.SnapError as exc:
            return Result(ok=False, error=f"bad snap payload: {exc}")

    apparmor_changes: dict[str, str] = {}
    if "apparmor" in payload:
        try:
            apparmor_changes = apparmor_module.from_payload(payload["apparmor"])
        except apparmor_module.ApparmorError as exc:
            return Result(ok=False, error=f"bad apparmor payload: {exc}")

    account_changes: list[tuple[list[str], str]] = []
    if "accounts" in payload:
        try:
            account_changes = accounts_module.from_payload(payload["accounts"])
        except accounts_module.AccountError as exc:
            return Result(ok=False, error=f"refusing this account change: {exc}")

    sections = payload.get("sections")
    current = probe.read_target_files(catalogue)
    try:
        plan = render.render(catalogue, selection, current=current, sections=sections)
    except render.RenderError as exc:
        return Result(ok=False, error=f"could not build the plan: {exc}")

    if (
        plan.is_empty
        and wanted_firewall is None
        and not unit_changes
        and not apparmor_changes
        and not snap_changes
        and not package_removals
        and not extras
        and not account_changes
    ):
        return Result(ok=True, error="", steps=[Step("write", "nothing to do", True)])

    return apply_plan(
        catalogue, plan, selection, wanted_firewall, unit_changes, apparmor_changes,
        extras, snap_changes, package_removals, package_purge, account_changes,
    )
