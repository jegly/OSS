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
