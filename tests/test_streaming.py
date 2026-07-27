"""The helper's progress stream — the path that made the dialog look hung.

_run_streaming takes an argv, so all of this runs against tests/fake_helper.py
with no pkexec, no privilege and nothing written outside this process.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ossgui import privileged  # noqa: E402

FAKE = str(Path(__file__).resolve().parent / "fake_helper.py")


def run(*extra: str, on_progress=None):
    return privileged._run_streaming([sys.executable, FAKE, "payload.json", *extra], on_progress)


class TestStreaming(unittest.TestCase):
    def test_every_progress_line_arrives_in_order(self) -> None:
        seen: list[str] = []
        stdout, _stderr, code = run("--lines", "5", on_progress=seen.append)
        self.assertEqual(code, 0)
        self.assertEqual(seen, [f"step {i} of 5" for i in range(1, 6)])

    def test_stdout_is_intact_json(self) -> None:
        """The bug: communicate() drained stderr while the pump thread was on it.

        Two readers on one pipe, and communicate() closing it mid-iteration.
        The visible symptom was a run that never finished.
        """
        import json

        stdout, _stderr, _code = run("--lines", "20", on_progress=lambda _t: None)
        parsed = json.loads(stdout)
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["outcomes"], {"kptr_restrict": "applied"})

    def test_progress_arrives_while_the_helper_is_still_running(self) -> None:
        """Streaming, not buffered-until-exit — the whole point of the change."""
        first_seen: list[float] = []
        started = time.monotonic()

        def note(_text: str) -> None:
            if not first_seen:
                first_seen.append(time.monotonic() - started)

        run("--lines", "6", "--delay", "0.15", on_progress=note)
        self.assertTrue(first_seen, "no progress was reported at all")
        # The helper runs for ~0.9s; the first line must not wait for the end.
        self.assertLess(first_seen[0], 0.5)

    def test_a_flood_of_stderr_does_not_deadlock(self) -> None:
        # 256 KB is past the usual 64 KB pipe buffer: anything not draining
        # stderr continuously blocks the helper forever here.
        stdout, stderr, code = run("--stderr-bytes", "262144", on_progress=lambda _t: None)
        self.assertEqual(code, 0)
        self.assertIn("kptr_restrict", stdout)
        self.assertGreater(len(stderr), 262144)

    def test_a_helper_that_says_nothing_still_finishes(self) -> None:
        stdout, _stderr, code = run("--silent", on_progress=lambda _t: None)
        self.assertEqual(code, 0)
        self.assertIn("kptr_restrict", stdout)

    def test_failure_exit_code_is_returned_not_swallowed(self) -> None:
        _stdout, _stderr, code = run("--exit", "1", on_progress=lambda _t: None)
        self.assertEqual(code, 1)

    def test_no_progress_callback_is_fine(self) -> None:
        _stdout, _stderr, code = run("--lines", "3")
        self.assertEqual(code, 0)

    def test_reader_thread_does_not_outlive_the_call(self) -> None:
        before = threading.active_count()
        run("--lines", "3", on_progress=lambda _t: None)
        time.sleep(0.2)
        self.assertLessEqual(threading.active_count(), before)

    def test_timeout_kills_the_helper(self) -> None:
        original = privileged.APPLY_TIMEOUT
        privileged.APPLY_TIMEOUT = 1
        self.addCleanup(setattr, privileged, "APPLY_TIMEOUT", original)
        with self.assertRaises(subprocess.TimeoutExpired):
            run("--lines", "50", "--delay", "0.5", on_progress=lambda _t: None)



class TestPostApplyStaysOffTheMainThread(unittest.TestCase):
    """probe.gather() is 1.2s and used to run in _finish, on the GTK thread.

    That froze the window — including the apply dialog's own elapsed clock —
    for as long as it took, which is indistinguishable from a crash. The
    dialog's worker now gathers and hands the result in, so refresh_from_system
    must accept pre-gathered facts and not re-scan.
    """

    def test_refresh_from_system_accepts_pregathered_facts(self) -> None:
        import inspect

        from ossgui.ui import window as window_module

        signature = inspect.signature(window_module.MainWindow.refresh_from_system)
        self.assertIn("facts", signature.parameters)

        source = inspect.getsource(window_module.MainWindow.refresh_from_system)
        self.assertIn("facts if facts is not None", source)

    def test_worker_gathers_before_handing_back_to_the_ui(self) -> None:
        import inspect

        from ossgui.ui import review as review_module

        source = inspect.getsource(review_module.ApplyProgressDialog._worker)
        gather_at = source.find("probe.gather")
        idle_at = source.find("GLib.idle_add(self._finish")
        self.assertGreater(gather_at, -1, "worker no longer gathers off-thread")
        self.assertGreater(idle_at, gather_at, "gather must happen before _finish")

if __name__ == "__main__":
    unittest.main()
