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
from dataclasses import dataclass, field
from pathlib import Path

from . import paths

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
    selection: dict[str, str], sections: list[str] | None = None
) -> dict:
    payload: dict = {"version": 1, "selection": dict(selection)}
    if sections is not None:
        payload["sections"] = list(sections)
    return payload


def apply(selection: dict[str, str], sections: list[str] | None = None) -> ApplyOutcome:
    """Hand the selection to the helper through pkexec and parse the result."""
    helper = paths.helper_path()
    if not Path(helper).exists():
        return ApplyOutcome(False, error=f"helper not installed at {helper}")
    if shutil.which("pkexec") is None:
        return ApplyOutcome(False, error="pkexec is not available on this system")

    directory = _payload_dir()
    handle, name = tempfile.mkstemp(dir=directory, suffix=".json", prefix="apply-")
    payload_path = Path(name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(build_payload(selection, sections), stream)
        os.chmod(payload_path, stat.S_IRUSR | stat.S_IWUSR)

        try:
            completed = subprocess.run(
                ["pkexec", helper, str(payload_path)],
                capture_output=True,
                text=True,
                timeout=APPLY_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ApplyOutcome(False, error="the helper did not finish in time")
        except OSError as exc:
            return ApplyOutcome(False, error=f"could not start pkexec: {exc}")

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
        raw=stdout,
    )


def run_user_commands(commands) -> list[tuple[str, bool, str]]:
    """Run the unprivileged half of a plan — gsettings writes the *user's* dconf.

    These deliberately never go through pkexec: run as root they would write
    root's dconf database and change nothing about the logged-in session.
    """
    results = []
    for command in commands:
        try:
            completed = subprocess.run(
                list(command.argv), capture_output=True, text=True, timeout=30, check=False
            )
            output = (completed.stdout + completed.stderr).strip()
            results.append((str(command), completed.returncode == 0, output))
        except (OSError, subprocess.SubprocessError) as exc:
            results.append((str(command), False, str(exc)))
    return results
