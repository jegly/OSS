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
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import probe, render, ufw as ufw_module, units as units_module
from .catalogue import Catalogue
from .render import ALLOWED_COMMANDS, Plan

#: How long any single command in the transaction gets. update-initramfs is slow.
COMMAND_TIMEOUT = 300

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

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


class ApplyError(Exception):
    """Something went wrong badly enough to roll the transaction back."""


def target_path(path: str) -> Path:
    """Resolve a catalogue target, honouring a test root.

    ``HARDENING_GUI_ROOT`` relocates every write under a sandbox directory so the
    transaction can be exercised for real in tests. It is ignored outright when
    running as root, so it can never redirect the privileged helper's writes.
    """
    prefix = os.environ.get("HARDENING_GUI_ROOT") if os.geteuid() != 0 else None
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
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(dir=path.parent, prefix=".hardening-gui-")
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


def _with_candidate(write: render.FileWrite):
    """Context: the candidate content in a temp file next to the real target."""
    path = target_path(write.path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, name = tempfile.mkstemp(dir=path.parent, prefix=".hardening-gui-check-")
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
) -> Result:
    """Run the whole transaction, rolling back on any failure."""
    result = Result()

    problems = render.validate_commands(plan)
    if problems:
        result.ok = False
        result.error = "; ".join(problems)
        return result

    touched: list[Path] = []
    try:
        # 1. Validate every candidate before anything is written.
        for write in plan.writes:
            validate_write(write, result)

        # 2. Back up, then write.
        for write in plan.writes:
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
        for command in plan.commands:
            code, output = run(command.argv)
            ok = code == 0
            result.steps.append(Step("command", str(command), ok, output))
            if not ok:
                raise ApplyError(f"{command} failed with exit {code}: {output}")

        # 4. Arbitrary unit changes, which the flag catalogue cannot express.
        for argv, why in units_module.plan_commands(unit_changes or {}):
            code, output = run(argv)
            ok = code == 0
            result.steps.append(Step("command", " ".join(argv), ok, output))
            if not ok:
                raise ApplyError(f"{why} failed: {output}")

        # 5. The firewall, last: its rules are the thing most likely to cut the
        #    connection this session is running over.
        if firewall is not None:
            apply_firewall(firewall, result)

    except ApplyError as exc:
        result.ok = False
        result.error = str(exc)
        result.rolled_back = _rollback(touched, plan, result)
        return result
    except OSError as exc:
        result.ok = False
        result.error = f"{type(exc).__name__}: {exc}"
        result.rolled_back = _rollback(touched, plan, result)
        return result

    # 4. Read back. Invalid sysctl keys fail silently, so this is the only way to
    #    know whether what we wrote actually took (§8).
    result.outcomes, result.needs_reboot = read_back(catalogue, selection)
    result.steps.append(
        Step("readback", f"{len(result.outcomes)} flags re-read", True)
    )
    return result


def _rollback(touched: list[Path], plan: Plan, result: Result) -> bool:
    """Restore every file we changed and re-run the reloads over the old state."""
    restored = True
    for path in touched:
        try:
            restore(path)
            result.steps.append(Step("restore", str(path)))
        except OSError as exc:
            restored = False
            result.steps.append(Step("restore", str(path), False, str(exc)))
    for command in plan.commands:
        code, output = run(command.argv)
        result.steps.append(
            Step("command", f"rollback: {command}", code == 0, output)
        )
    return restored


def read_back(
    catalogue: Catalogue, selection: dict[str, str]
) -> tuple[dict[str, str], list[str]]:
    """Re-read every selected flag and classify the outcome."""
    facts = probe.gather(catalogue)
    outcomes: dict[str, str] = {}
    needs_reboot: list[str] = []

    for flag_id, value in selection.items():
        flag = catalogue.get(flag_id)
        if flag is None:
            continue
        section = catalogue.section(flag.section)
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

    sections = payload.get("sections")
    current = probe.read_target_files(catalogue)
    try:
        plan = render.render(catalogue, selection, current=current, sections=sections)
    except render.RenderError as exc:
        return Result(ok=False, error=f"could not build the plan: {exc}")

    if plan.is_empty and wanted_firewall is None and not unit_changes:
        return Result(ok=True, error="", steps=[Step("write", "nothing to do", True)])

    return apply_plan(catalogue, plan, selection, wanted_firewall, unit_changes)
