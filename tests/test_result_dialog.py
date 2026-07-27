"""The apply result page must build for every combination of outcomes.

A frozen dialog was traced to `self._row` in ApplyProgressDialog, which has no
such method — every other call in that class goes through ReviewDialog._row.
It only ran when a section had been skipped, so it fired on any machine missing
an optional package and on no other. GLib swallows exceptions raised inside an
idle callback, so the window simply stopped, still showing the last progress
line, with the apply already successfully finished behind it.

These construct widgets but never present a window, so nothing appears on the
screen while the suite runs.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

_HAS_DISPLAY = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


@unittest.skipUnless(_HAS_DISPLAY, "GTK widgets need a display")
class TestResultPage(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import gi

        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
        from gi.repository import Adw

        Adw.init()

        from ossgui import catalogue, privileged
        from ossgui.ui.review import ApplyProgressDialog

        cls.catalogue = catalogue.load()
        cls.ApplyProgressDialog = ApplyProgressDialog
        cls.ApplyOutcome = privileged.ApplyOutcome

    def dialog(self):
        """A dialog with just enough window behind it to build a result page."""

        class FakeWindow:
            catalogue = self.catalogue

        instance = self.ApplyProgressDialog.__new__(self.ApplyProgressDialog)
        instance.window = FakeWindow()
        return instance

    def outcome(self, **outcomes) -> "object":
        return self.ApplyOutcome(
            ok=True,
            outcomes=outcomes,
            steps=[{"kind": "write", "detail": "/etc/sysctl.d/99-oss.conf", "ok": True, "output": ""}],
        )

    def test_builds_with_skipped_flags(self) -> None:
        """The exact case that froze: a machine without openssh-server."""
        outcome = self.outcome(
            ssh_permit_root_login="skipped",
            ssh_pubkey_auth="skipped",
            kptr_restrict="applied",
        )
        self.assertIsNotNone(self.dialog()._details_view(outcome, []))

    def test_builds_with_failures(self) -> None:
        outcome = self.outcome(kptr_restrict="didnt-take", dmesg_restrict="failed")
        self.assertIsNotNone(self.dialog()._details_view(outcome, []))

    def test_builds_with_every_outcome_kind_at_once(self) -> None:
        outcome = self.outcome(
            kptr_restrict="applied",
            dmesg_restrict="didnt-take",
            ssh_permit_root_login="skipped",
            slab_nomerge="pending-reboot",
        )
        outcome.needs_reboot = ["slab_nomerge"]
        self.assertIsNotNone(self.dialog()._details_view(outcome, []))

    def test_builds_with_nothing_at_all(self) -> None:
        self.assertIsNotNone(self.dialog()._details_view(self.outcome(), []))

    def test_builds_with_failed_desktop_commands(self) -> None:
        view = self.dialog()._details_view(
            self.outcome(kptr_restrict="applied"),
            [("gsettings set org.gnome.desktop.privacy x y", False, "no such schema")],
        )
        self.assertIsNotNone(view)

    def test_every_skipped_section_resolves_a_reason(self) -> None:
        """The skipped group prints render.section_skip_reason for each section.

        A section id that does not resolve, or a reason that raises, would take
        the whole results page down with it.
        """
        from ossgui import render

        outcomes = {}
        for section in self.catalogue.sections:
            if section.flags:
                outcomes[section.flags[0].id] = "skipped"
        self.assertIsNotNone(self.dialog()._details_view(self.outcome(**outcomes), []))

        for section in self.catalogue.sections:
            self.assertIsInstance(render.section_skip_reason(section), str)


if __name__ == "__main__":
    unittest.main()
