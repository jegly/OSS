"""The modprobe page builds, and its toggles route to the right place.

Skipped without a display, like test_cards.py: GTK4 widgets cannot be
constructed headless, and the package build may run in a chroot with no session.

This page is the one part of the section with no other coverage — it renders 6,900
modules and it decides, per row, whether a toggle stages a catalogue flag or a
bare module name. Getting that wrong writes to the wrong file.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ossgui import catalogue, kmod, probe, staging as staging_module  # noqa: E402

_HAS_DISPLAY = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


class _StubWindow:
    """Only what KmodPage touches."""

    def __init__(self, inventory) -> None:
        self.catalogue = catalogue.load()
        facts = probe.SystemFacts(
            files={}, cmdline=[], modules={}, units={}, gsettings={},
            vulnerabilities={}, blacklisted=dict(inventory.blacklisted),
        )
        self.staging = staging_module.Staging.from_system(self.catalogue, facts)
        self.module_blacklist: set = set()
        self.kmod_inventory = inventory
        self.current_section = "modprobe"
        self.toasts: list = []
        self.refreshed = 0

    def _show_section(self, _section_id) -> None:
        pass

    def _refresh_chrome(self) -> None:
        self.refreshed += 1

    def toast(self, message) -> None:
        self.toasts.append(message)


def _inventory() -> kmod.Inventory:
    def module(name, category, **kw):
        return kmod.Module(name=name, path=f"/lib/modules/x/kernel/{category}/{name}.ko",
                           category=category, **kw)

    return kmod.Inventory(
        release="test",
        modules={
            "appletalk": module("appletalk", "net/appletalk"),
            "e1000e": module("e1000e", "drivers/net", size_kb=300),
            "ahci": module("ahci", "drivers/ata", loaded=True),
            "usbkbd": module("usbkbd", "drivers/hid/usbhid"),
        },
        blacklisted={"usbkbd": "/etc/modprobe.d/blacklist.conf"},
    )


@unittest.skipUnless(_HAS_DISPLAY, "GTK4 needs a display")
class TestPageBuilds(unittest.TestCase):
    def setUp(self) -> None:
        import gi

        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
        from gi.repository import Adw

        Adw.init()
        from ossgui.ui.kmod_page import KmodPage

        self.KmodPage = KmodPage
        self.window = _StubWindow(_inventory())

    def test_the_page_builds_at_all(self) -> None:
        page = self.KmodPage(self.window)
        self.assertTrue(page.rows)

    def test_it_builds_with_the_real_kernel_inventory(self) -> None:
        """The 6,900-row case, which is the one that actually ships."""
        real = kmod.read_inventory()
        if not real.modules:
            self.skipTest("no /lib/modules tree for the running kernel")
        window = _StubWindow(real)
        page = self.KmodPage(window)
        self.assertGreater(len(page.rows), 1000)
        names = [r.name for r in page.rows]
        self.assertEqual(len(names), len(set(names)), "a module is rendered twice")

    def test_every_filter_builds(self) -> None:
        from ossgui.ui.kmod_page import FILTERS

        for name in FILTERS:
            with self.subTest(filter=name):
                self.window.kmod_filter = name
                self.KmodPage(self.window)

    def test_search_builds(self) -> None:
        self.window.kmod_search = "e1000"
        self.KmodPage(self.window)

    def test_opening_a_subsystem_builds_its_rows(self) -> None:
        self.window.kmod_open = {"drivers/*", "net/*"}
        self.KmodPage(self.window)

    def test_everything_starts_collapsed(self) -> None:
        """57 groups open by default buries the next heading under 6,900 rows."""
        page = self.KmodPage(self.window)
        self.assertEqual(page._open, set())

    def test_expanding_does_not_rebuild_the_page(self) -> None:
        """A rebuild resets the scroller, which threw you back to the top.

        _show_section is what rebuilds; the stub counts calls to it, and expanding
        a group must not make any.
        """
        calls = []
        self.window._show_section = lambda section_id: calls.append(section_id)
        page = self.KmodPage(self.window)
        name, rows = page.groups[0]

        class _Expander:
            expanded = True

            def get_expanded(self):
                return self.expanded

            def add_row(self, _row):
                pass

            def remove(self, _row):
                pass

        page._on_expanded(_Expander(), None, name, rows)
        self.assertEqual(calls, [], "expanding rebuilt the page")
        self.assertIn(name, page._open)
        self.assertEqual(page._group_limits[name], min(len(rows), 50))

    def test_paging_within_a_group_does_not_rebuild_either(self) -> None:
        calls = []
        self.window._show_section = lambda section_id: calls.append(section_id)
        real = kmod.read_inventory()
        if not real.modules:
            self.skipTest("no /lib/modules tree for the running kernel")
        window = _StubWindow(real)
        window._show_section = lambda section_id: calls.append(section_id)
        page = self.KmodPage(window)
        name, rows = max(page.groups, key=lambda kv: len(kv[1]))

        class _Expander:
            def get_expanded(self):
                return True

            def add_row(self, _row):
                pass

            def remove(self, _row):
                pass

        expander = _Expander()
        page._on_expanded(expander, None, name, rows)
        first = page._group_limits[name]
        page._on_show_more_group(None, expander, name, rows)
        self.assertGreater(page._group_limits[name], first)
        self.assertEqual(calls, [], "paging rebuilt the page")

    def test_a_rebuilt_page_refills_an_open_group(self) -> None:
        """Group limits are per page, or a reopened page renders empty groups."""
        self.window.kmod_open = {self.KmodPage(self.window).groups[0][0]}
        page = self.KmodPage(self.window)
        name = page.groups[0][0]
        self.assertGreater(page._group_limits.get(name, 0), 0)


@unittest.skipUnless(_HAS_DISPLAY, "GTK4 needs a display")
class TestToggleRouting(unittest.TestCase):
    """A curated row stages a flag; a bare module stages a name."""

    def setUp(self) -> None:
        import gi

        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
        from gi.repository import Adw

        Adw.init()
        from ossgui.ui.kmod_page import KmodPage

        self.window = _StubWindow(_inventory())
        self.page = KmodPage(self.window)

    def _row(self, name: str):
        return next(r for r in self.page.rows if r.name == name)

    def test_a_curated_module_stages_its_catalogue_flag(self) -> None:
        row = self._row("appletalk")
        self.assertTrue(row.curated)
        self.page._on_toggle(None, True, row)
        self.assertTrue(self.window.staging.is_set(row.flag.id))
        self.assertNotIn("appletalk", self.window.module_blacklist)

    def test_an_uncurated_module_stages_its_name(self) -> None:
        row = self._row("e1000e")
        self.assertFalse(row.curated)
        self.page._on_toggle(None, True, row)
        self.assertIn("e1000e", self.window.module_blacklist)

    def test_turning_it_off_unstages_it(self) -> None:
        curated, bare = self._row("appletalk"), self._row("e1000e")
        self.page._on_toggle(None, True, curated)
        self.page._on_toggle(None, True, bare)
        self.page._on_toggle(None, False, curated)
        self.page._on_toggle(None, False, bare)
        self.assertFalse(self.window.staging.is_set(curated.flag.id))
        self.assertNotIn("e1000e", self.window.module_blacklist)

    def test_a_loaded_module_gets_no_switch(self) -> None:
        row = self._row("ahci")
        self.assertEqual(self.page._level(row)[0], "refused")

    def test_an_already_blacklisted_module_gets_no_switch(self) -> None:
        row = self._row("usbkbd")
        self.assertEqual(self.page._level(row)[0], "blocked")
        self.assertIn("blacklist.conf", self.page._level(row)[1])

    def test_a_builtin_cannot_be_blacklisted_and_is_not_offered(self) -> None:
        """squashfs and vfat are built into Ubuntu's kernel, not loaded.

        They are curated flags marked "breaking", so a switch here promised to
        break all snaps and every FAT mount — via a blacklist line that cannot
        touch a module compiled into the image.
        """
        from ossgui.ui.kmod_page import _LOCKED

        inventory = _inventory()
        inventory.builtin = frozenset({"squashfs"})
        inventory.modules.pop("appletalk")
        window = _StubWindow(inventory)
        window.catalogue = self.window.catalogue
        page = type(self.page)(window)
        row = next(r for r in page.rows if r.name == "squashfs")
        level, why = page._level(row)
        self.assertEqual(level, "builtin")
        self.assertIn(level, _LOCKED)
        self.assertIn("blacklist cannot stop it", why)


if __name__ == "__main__":
    unittest.main()
