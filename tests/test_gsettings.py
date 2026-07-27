"""gsettings probing — the one read that talks to a daemon, not a file.

It is therefore the one that can block rather than fail, and it is called from
the privileged helper's read-back where there is no session bus at all.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ossgui import catalogue, probe  # noqa: E402


class TestReadGsettings(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        loaded = catalogue.load()
        cls.keys = [
            flag.key
            for flag in loaded.flags.values()
            if loaded.section(flag.section).syntax == "gsettings"
        ]

    def test_returns_nothing_without_a_session_bus(self) -> None:
        """pkexec hands the helper a root environment with no session bus.

        Every lookup there would read root's dconf rather than the user's, so
        it is meaningless — and each one could sit waiting on a bus that is not
        there. 27 keys at the old 10s ceiling was four and a half minutes of
        the apply doing nothing.
        """
        saved = os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)
        self.addCleanup(
            lambda: os.environ.__setitem__("DBUS_SESSION_BUS_ADDRESS", saved)
            if saved is not None
            else None
        )
        self.assertEqual(probe.read_gsettings(self.keys), {})

    def test_one_subprocess_per_schema_not_per_key(self) -> None:
        # 27 keys across 9 schemas. Per-key spawning is what made this slow
        # enough to look like a hang.
        calls: list[list[str]] = []
        real = probe._run

        def counting(argv, timeout=None):
            calls.append(list(argv))
            return real(argv, timeout)

        probe._run = counting
        self.addCleanup(setattr, probe, "_run", real)

        probe.read_gsettings(self.keys)
        schemas = {key.rpartition(" ")[0] for key in self.keys}
        self.assertLessEqual(len(calls), len(schemas))
        self.assertTrue(all("list-recursively" in c for c in calls))

    def test_uses_a_short_timeout(self) -> None:
        seen: list = []
        real = probe._run

        def capture(argv, timeout=None):
            seen.append(timeout)
            return real(argv, timeout)

        probe._run = capture
        self.addCleanup(setattr, probe, "_run", real)

        probe.read_gsettings(self.keys)
        self.assertTrue(seen)
        for timeout in seen:
            self.assertEqual(timeout, probe.GSETTINGS_TIMEOUT)
            self.assertLess(timeout, probe.TIMEOUT)

    @unittest.skipUnless(os.environ.get("DBUS_SESSION_BUS_ADDRESS"), "needs a session bus")
    def test_reads_real_values_when_a_bus_is_present(self) -> None:
        got = probe.read_gsettings(self.keys)
        self.assertTrue(got)
        for pair in got:
            self.assertIn(" ", pair)


if __name__ == "__main__":
    unittest.main()
