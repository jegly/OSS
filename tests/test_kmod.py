"""Kernel debloat: what may be blacklisted, and what the drop-in says."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ossgui import kmod  # noqa: E402


def _module(name: str, category: str, **kwargs) -> kmod.Module:
    return kmod.Module(name=name, path=f"/lib/modules/x/kernel/{category}/{name}.ko",
                       category=category, **kwargs)


class TestNames(unittest.TestCase):
    """Every name reaches a line in modprobe.d, written as root."""

    def test_refuses_anything_but_a_module_name(self) -> None:
        for bad in ("../../etc/passwd", "a; rm -rf /", "mod name", "", "a" * 65,
                    "mod-with-hyphen"):
            with self.subTest(name=bad):
                with self.assertRaises(kmod.ModuleError):
                    kmod.validate(bad)

    def test_accepts_a_real_one(self) -> None:
        for good in ("appletalk", "snd_hda_intel", "e1000e", "nf_conntrack_ftp"):
            kmod.validate(good)

    def test_payload_must_be_a_list_of_names(self) -> None:
        with self.assertRaises(kmod.ModuleError):
            kmod.from_payload("appletalk")
        with self.assertRaises(kmod.ModuleError):
            kmod.from_payload([123])
        self.assertEqual(kmod.from_payload(["comedi"]), ["comedi"])


class TestRendering(unittest.TestCase):
    def test_emits_blacklist_and_install_false(self) -> None:
        """blacklist alone still allows an explicit modprobe (§4.5)."""
        body = kmod.render_blacklist(["appletalk"])
        self.assertIn("blacklist appletalk\n", body)
        self.assertIn("install appletalk /bin/false\n", body)
        # /bin/true would report success for a module that never loaded.
        self.assertNotIn("/bin/true", body)

    def test_is_recognisable_as_ours(self) -> None:
        from ossgui import probe

        self.assertTrue(probe.is_ours(kmod.render_blacklist(["comedi"])))

    def test_deduplicates_and_sorts(self) -> None:
        body = kmod.render_blacklist(["zzz", "aaa", "aaa"])
        self.assertEqual(body.count("blacklist aaa\n"), 1)
        self.assertLess(body.index("blacklist aaa"), body.index("blacklist zzz"))

    def test_a_bad_name_stops_the_whole_render(self) -> None:
        with self.assertRaises(kmod.ModuleError):
            kmod.render_blacklist(["appletalk", "oops; reboot"])


class TestVerdict(unittest.TestCase):
    """The running system's own needs outrank any static table."""

    NONE: frozenset = frozenset()

    def test_a_loaded_module_is_refused(self) -> None:
        level, why = _module("e1000e", "drivers/net", loaded=True).verdict(self.NONE)
        self.assertEqual(level, "refused")
        self.assertIn("Loaded", why)

    def test_a_loaded_module_in_use_names_its_dependents(self) -> None:
        module = _module("libata", "drivers/ata", loaded=True, used_by=("ahci",))
        level, why = module.verdict(self.NONE)
        self.assertEqual(level, "refused")
        self.assertIn("ahci", why)

    def test_a_mounted_filesystem_is_refused_even_when_not_loaded(self) -> None:
        """It can be built in rather than loaded, and still be carrying root."""
        level, _why = _module("ext4", "fs/ext4").verdict(frozenset({"ext4"}))
        self.assertEqual(level, "refused")

    def test_critical_subsystems_are_caution_not_candidate(self) -> None:
        for name, category in (("nvme", "drivers/nvme/host"),
                               ("usbhid", "drivers/hid/usbhid"),
                               ("btrfs", "fs/btrfs")):
            with self.subTest(module=name):
                level, _why = _module(name, category).verdict(self.NONE)
                self.assertEqual(level, "caution")

    def test_known_bloat_is_a_candidate(self) -> None:
        for name, category in (("appletalk", "net/appletalk"),
                               ("comedi", "drivers/comedi"),
                               ("uvcvideo", "drivers/media/usb/uvc")):
            with self.subTest(module=name):
                level, _why = _module(name, category).verdict(self.NONE)
                self.assertEqual(level, "candidate")

    def test_an_unknown_subsystem_does_not_claim_to_be_safe(self) -> None:
        _level, why = _module("obscure", "drivers/nowhere").verdict(self.NONE)
        self.assertIn("not a guarantee", why)


class TestAlreadyBlacklisted(unittest.TestCase):
    """A module something already blocks is not a candidate to block again.

    The browser had no idea what modprobe.d said, so on a stock install it offered
    107 modules that were already blacklisted — including every one the curated
    section had just applied, and everything the distro blacklists itself.
    """

    NONE: frozenset = frozenset()
    OURS = "/etc/modprobe.d/99-oss.conf"

    def test_blacklisted_and_idle_is_blocked_not_offered(self) -> None:
        level, why = _module("appletalk", "net/appletalk").verdict(self.NONE, self.OURS)
        self.assertEqual(level, "blocked")
        self.assertIn(self.OURS, why)

    def test_the_file_that_set_it_is_named(self) -> None:
        distro = "/etc/modprobe.d/blacklist.conf"
        _level, why = _module("usbkbd", "drivers/hid/usbhid").verdict(self.NONE, distro)
        self.assertIn(distro, why)

    def test_loaded_still_outranks_the_blacklist(self) -> None:
        """Loaded means it is in the kernel now, whatever modprobe.d says."""
        level, why = _module("e1000e", "drivers/net", loaded=True).verdict(
            self.NONE, self.OURS
        )
        self.assertEqual(level, "refused")
        self.assertIn("reboot", why)

    def test_a_mounted_filesystem_outranks_it_too(self) -> None:
        level, _why = _module("ext4", "fs/ext4").verdict(frozenset({"ext4"}), self.OURS)
        self.assertEqual(level, "refused")

    def test_not_blacklisted_is_unchanged(self) -> None:
        """The default keeps every existing verdict exactly as it was."""
        level, _why = _module("appletalk", "net/appletalk").verdict(self.NONE)
        self.assertEqual(level, "candidate")

    def test_inventory_routes_the_blacklist_to_the_verdict(self) -> None:
        module = _module("appletalk", "net/appletalk")
        inventory = kmod.Inventory(
            modules={"appletalk": module}, blacklisted={"appletalk": self.OURS}
        )
        self.assertEqual(inventory.verdict_for(module)[0], "blocked")
        self.assertEqual(inventory.counts()["blocked"], 1)
        self.assertEqual(inventory.counts()["candidate"], 0)


class _Flag:
    """Enough of a catalogue Flag for the row model."""

    def __init__(self, flag_id: str, key: str, group: str) -> None:
        self.id, self.key, self.group = flag_id, key, group


class TestRowModel(unittest.TestCase):
    """One row per module.

    The curated flags and the kernel inventory were rendered as two separate
    lists on one page, so every curated module appeared twice — once as a switch
    writing to the section drop-in, once as a checkbox writing to the debloat
    drop-in.
    """

    def _inventory(self, *names: str) -> kmod.Inventory:
        return kmod.Inventory(
            modules={n: _module(n, "drivers/net") for n in names}
        )

    def test_a_curated_module_gets_exactly_one_row(self) -> None:
        inventory = self._inventory("appletalk", "e1000e")
        rows = kmod.build_rows(inventory, [_Flag("mod_appletalk", "appletalk", "g")])
        names = [r.name for r in rows]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(sorted(names), ["appletalk", "e1000e"])

    def test_the_curated_row_carries_its_flag(self) -> None:
        flag = _Flag("mod_appletalk", "appletalk", "g")
        rows = kmod.build_rows(self._inventory("appletalk"), [flag])
        self.assertIs(rows[0].flag, flag)
        self.assertTrue(rows[0].curated)

    def test_an_uncurated_module_has_no_flag(self) -> None:
        rows = kmod.build_rows(self._inventory("e1000e"), [])
        self.assertIsNone(rows[0].flag)
        self.assertFalse(rows[0].curated)

    def test_a_curated_flag_with_no_module_still_gets_a_row(self) -> None:
        """It is inert here but travels in a preset, so hiding it drops it."""
        rows = kmod.build_rows(self._inventory(), [_Flag("mod_dccp", "dccp", "g")])
        self.assertEqual([r.name for r in rows], ["dccp"])
        self.assertIsNone(rows[0].module)

    def test_curated_rows_come_first_and_in_catalogue_order(self) -> None:
        inventory = self._inventory("e1000e", "appletalk", "ax25")
        flags = [_Flag("mod_ax25", "ax25", "g"), _Flag("mod_appletalk", "appletalk", "g")]
        rows = kmod.build_rows(inventory, flags)
        self.assertEqual([r.name for r in rows[:2]], ["ax25", "appletalk"])

    def test_a_duplicate_key_in_the_catalogue_is_not_rendered_twice(self) -> None:
        flags = [_Flag("a", "appletalk", "g"), _Flag("b", "appletalk", "g")]
        rows = kmod.build_rows(self._inventory("appletalk"), flags)
        self.assertEqual([r.name for r in rows], ["appletalk"])


class TestGrouping(unittest.TestCase):
    def test_a_big_subsystem_keeps_its_own_group(self) -> None:
        big = kmod.big_groups(["drivers/media"] * 40)
        self.assertEqual(kmod.group_key("drivers/media", big), "drivers/media")

    def test_a_small_one_folds_into_its_parent(self) -> None:
        big = kmod.big_groups(["drivers/tiny"] * 3)
        self.assertEqual(kmod.group_key("drivers/tiny", big), "drivers/*")

    def test_curated_groups_lead_and_keep_catalogue_names(self) -> None:
        rows = [
            kmod.Row("appletalk", _module("appletalk", "net/appletalk"),
                     _Flag("mod_appletalk", "appletalk", "modules / network")),
            kmod.Row("e1000e", _module("e1000e", "drivers/net")),
        ]
        groups = kmod.grouped(rows)
        self.assertEqual(groups[0][0], "modules / network")
        self.assertEqual([r.name for r in groups[0][1]], ["appletalk"])

    def test_every_row_lands_in_exactly_one_group(self) -> None:
        rows = [kmod.Row(f"m{i}", _module(f"m{i}", "drivers/net")) for i in range(30)]
        groups = kmod.grouped(rows)
        self.assertEqual(sum(len(r) for _n, r in groups), len(rows))


class TestInventory(unittest.TestCase):
    def test_proc_modules_parsing(self) -> None:
        """'-' means nothing depends on it; a trailing comma is normal."""
        import unittest.mock as mock

        text = (
            "ahci 45056 2 libahci,xhci_pci\n"
            "tcp_diag 20480 0 -\n"
            "libata 303104 2 ahci,libahci,\n"
        )
        with mock.patch.object(Path, "read_text", return_value=text):
            loaded = kmod.read_lsmod()
        self.assertEqual(loaded["tcp_diag"], ())
        self.assertEqual(loaded["ahci"], ("libahci", "xhci_pci"))
        self.assertEqual(loaded["libata"], ("ahci", "libahci"))

    def test_scans_the_real_kernel_without_root(self) -> None:
        inventory = kmod.read_inventory()
        if not inventory.modules:
            self.skipTest("no /lib/modules tree for the running kernel")
        # Whatever is loaded must appear in the inventory and be refused.
        loaded = [m for m in inventory.modules.values() if m.loaded]
        self.assertTrue(loaded, "something must be loaded on a running system")
        for module in loaded[:5]:
            level, _why = module.verdict(inventory.mounted_fstypes)
            self.assertEqual(level, "refused", f"{module.name} is loaded")


if __name__ == "__main__":
    unittest.main()
