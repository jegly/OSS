"""Flag card interaction — the switch/entry handshake on editable flags.

Skipped without a display: GTK4 widgets cannot be constructed headless, and
`debian/rules` runs this suite during the package build, which may well be in
a chroot with no session.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ossgui import catalogue  # noqa: E402

_HAS_DISPLAY = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


class TestEditableDefaults(unittest.TestCase):
    """Pure-data checks, so these still run in a headless build."""

    def test_editable_default_is_either_valid_or_deliberately_empty(self) -> None:
        # A non-empty default that fails its own pattern is a packaging bug:
        # the flag would be unstageable and the card would show a red entry
        # with no way to fix it. An *empty* default is legitimate — AllowUsers
        # has no sensible suggestion — and is why the entry has to stay
        # editable while the flag is off. See test_entry_is_usable_before_staging.
        loaded = catalogue.load()
        for flag in loaded.flags.values():
            if not flag.editable:
                continue
            if flag.value == "":
                continue
            with self.subTest(flag=flag.id):
                self.assertTrue(
                    flag.value_is_allowed(flag.value),
                    f"{flag.id} ships a default that fails its own pattern",
                )


@unittest.skipUnless(_HAS_DISPLAY, "GTK widgets need a display")
class TestEditableFlagCard(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import gi

        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
        from gi.repository import Adw

        Adw.init()
        from ossgui import probe
        from ossgui.staging import Staging
        from ossgui.ui.cards import FlagCard

        cls.FlagCard = FlagCard
        cls.Staging = Staging
        cls.catalogue = catalogue.load()
        cls.facts = probe.gather(cls.catalogue)

    def card(self, flag_id: str):
        staging = self.Staging.from_system(self.catalogue, self.facts)
        flag = self.catalogue.get(flag_id)
        section = self.catalogue.section(flag.section)
        return self.FlagCard(flag, section, staging), staging

    def test_entry_is_usable_before_staging(self) -> None:
        """The deadlock: no way to stage without a value, none to type one without staging.

        ssh_allow_users and ssh_allow_groups ship with no default, and the
        switch refuses to stage a value that fails the flag's pattern. When the
        entry was also gated on the flag being staged, both flags became
        impossible to turn on at all.
        """
        for flag_id in ("ssh_allow_users", "ssh_allow_groups"):
            with self.subTest(flag=flag_id):
                card, _ = self.card(flag_id)
                self.assertTrue(card.entry.get_sensitive())

    def test_switch_refuses_an_empty_value_then_accepts_a_typed_one(self) -> None:
        for flag_id in ("ssh_allow_users", "ssh_allow_groups"):
            with self.subTest(flag=flag_id):
                card, staging = self.card(flag_id)

                self.assertTrue(card._on_switch(card.switch, True), "empty value staged")
                self.assertFalse(staging.is_set(flag_id))

                card.entry.set_text("alice bob")
                self.assertFalse(card._on_switch(card.switch, True), "valid value vetoed")
                self.assertEqual(staging.value(flag_id), "alice bob")


if __name__ == "__main__":
    unittest.main()
