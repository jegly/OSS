"""core_pattern is applied successfully and then taken away by apport.

Found on a machine whose sysctl section showed drift with no explanation. The
journal told the whole story: systemd-sysctl wrote the value with no error at
18:14:24, apport started at 18:14:38, and /usr/share/apport/apport ends by writing
"core" over it. Nothing logs a failure, because nothing failed.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ossgui import probe  # noqa: E402


def _facts(apport: str | None):
    units = {"apport.service": apport} if apport is not None else {}
    return probe.SystemFacts(
        files={}, cmdline=[], modules={}, units=units, gsettings={}, vulnerabilities={}
    )


class TestApportClobber(unittest.TestCase):
    STAGED = {"core_pattern_false": "|/bin/false"}

    def test_warns_when_apport_is_enabled(self) -> None:
        note = probe.core_pattern_clobbered_by_apport(_facts("enabled"), self.STAGED)
        self.assertIsNotNone(note)
        self.assertIn("apport", note)
        self.assertIn("core_pattern", note)

    def test_silent_when_apport_is_masked(self) -> None:
        for state in ("masked", "masked-runtime", "disabled"):
            with self.subTest(state=state):
                self.assertIsNone(
                    probe.core_pattern_clobbered_by_apport(_facts(state), self.STAGED)
                )

    def test_silent_when_apport_is_not_installed(self) -> None:
        self.assertIsNone(
            probe.core_pattern_clobbered_by_apport(_facts(None), self.STAGED)
        )

    def test_silent_when_the_same_apply_masks_apport(self) -> None:
        """Staging both is the fix, so warning about it would be noise."""
        for value in ("mask", "disable"):
            with self.subTest(value=value):
                selection = dict(self.STAGED, svc_apport=value)
                self.assertIsNone(
                    probe.core_pattern_clobbered_by_apport(_facts("enabled"), selection)
                )

    def test_silent_when_core_pattern_is_not_staged(self) -> None:
        self.assertIsNone(probe.core_pattern_clobbered_by_apport(_facts("enabled"), {}))


if __name__ == "__main__":
    unittest.main()
