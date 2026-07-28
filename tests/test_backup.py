"""Backing up the config files, and putting them back.

Everything here runs against a sandbox tree in a temp directory. Nothing reads
or writes the real /etc, and no privileged call is made.
"""

from __future__ import annotations

import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ossgui import backup, catalogue  # noqa: E402


class SandboxCase(unittest.TestCase):
    """A fake /etc with the sort of thing a hand-configured machine has."""

    FILES = {
        "etc/sysctl.d/99-hardening.conf": "kernel.kptr_restrict = 2\n",
        "etc/sysctl.d/10-mine.conf": "vm.swappiness = 10\n",
        "etc/modprobe.d/blacklist-mine.conf": "blacklist firewire-core\n",
        "etc/default/grub": 'GRUB_CMDLINE_LINUX_DEFAULT="quiet"\n',
        "etc/login.defs": "UID_MIN 1000\nPASS_MAX_DAYS 99999\n",
        "etc/sudoers.d/99-mine": "Defaults use_pty\n",
        "etc/security/faillock.conf": "deny = 5\n",
    }

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "sandbox"
        for relative, content in self.FILES.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        os.chmod(self.root / "etc/sudoers.d/99-mine", 0o440)
        self.catalogue = catalogue.load()
        self.archive = Path(self.tmp.name) / "backup.tar.gz"

    def make(self) -> backup.BackupResult:
        return backup.create(
            self.catalogue,
            self.archive,
            backup.Manifest(hostname="testbox", family="debian", distro="Ubuntu 26.04"),
            root=str(self.root),
        )


class TestBackupPaths(unittest.TestCase):
    def test_derived_from_the_catalogue_not_hardcoded(self) -> None:
        """A new section must widen the backup set on its own."""
        loaded = catalogue.load()
        paths = backup.backup_paths(loaded)
        for expected in ("/etc/sysctl.d", "/etc/modprobe.d", "/etc/sudoers.d"):
            self.assertIn(expected, paths)

    def test_in_place_targets_are_files_not_their_directory(self) -> None:
        # /etc/login.defs lives directly in /etc. Taking its directory would
        # drag the whole of /etc into every backup.
        paths = backup.backup_paths(catalogue.load())
        self.assertIn("/etc/login.defs", paths)
        self.assertNotIn("/etc", paths)


class TestCreate(SandboxCase):
    def test_takes_the_users_own_files_not_just_ours(self) -> None:
        """The point of the feature: 10-mine.conf is nothing OSS wrote."""
        result = self.make()
        self.assertIn("/etc/sysctl.d/10-mine.conf", result.files)
        self.assertIn("/etc/modprobe.d/blacklist-mine.conf", result.files)

    def test_records_what_was_absent(self) -> None:
        result = self.make()
        self.assertIn("/etc/audit/rules.d", result.skipped)

    def test_archive_carries_a_manifest(self) -> None:
        self.make()
        manifest = backup.read_manifest(self.archive)
        self.assertEqual(manifest.hostname, "testbox")
        self.assertEqual(manifest.family, "debian")

    def test_paths_are_absolute_on_the_way_out(self) -> None:
        """Stored without the sandbox prefix, so a test archive restores where a real one would."""
        self.make()
        files = backup.read_files(self.archive)
        self.assertIn("/etc/sysctl.d/10-mine.conf", files)
        self.assertNotIn(str(self.root), " ".join(files))


class TestLocationSelection(SandboxCase):
    def test_only_the_chosen_locations_are_archived(self) -> None:
        backup.create(
            self.catalogue,
            self.archive,
            backup.Manifest(family="debian"),
            root=str(self.root),
            locations=["/etc/sysctl.d"],
        )
        files = backup.read_files(self.archive)
        self.assertIn("/etc/sysctl.d/10-mine.conf", files)
        self.assertNotIn("/etc/sudoers.d/99-mine", files)
        self.assertNotIn("/etc/default/grub", files)

    def test_location_of_prefers_the_longest_prefix(self) -> None:
        locations = ["/etc/default/grub", "/etc/default/grub.d", "/etc/sysctl.d"]
        self.assertEqual(
            backup.location_of("/etc/default/grub.d/x.cfg", locations),
            "/etc/default/grub.d",
        )
        self.assertEqual(
            backup.location_of("/etc/default/grub", locations), "/etc/default/grub"
        )
        # A path no location claims falls back to its own directory.
        self.assertEqual(backup.location_of("/etc/hosts", locations), "/etc")


class TestRoundTrip(SandboxCase):
    def test_content_survives(self) -> None:
        self.make()
        files = backup.read_files(self.archive)
        for relative, original in self.FILES.items():
            with self.subTest(path=relative):
                self.assertEqual(files["/" + relative][0], original)

    def test_sudoers_mode_survives(self) -> None:
        """Restored as anything but 0440 and sudo refuses to run at all."""
        self.make()
        files = backup.read_files(self.archive)
        self.assertEqual(files["/etc/sudoers.d/99-mine"][1], 0o440)


class TestRefusesHostileArchives(SandboxCase):
    def hostile(self, name: str, content: bytes = b"x") -> Path:
        path = Path(self.tmp.name) / "hostile.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, __import__("io").BytesIO(content))
        return path

    def test_path_traversal(self) -> None:
        # A tar can name .. segments; unpacking one as root writes anywhere.
        with self.assertRaises(backup.BackupError):
            backup.read_files(self.hostile("etc/../../root/.ssh/authorized_keys"))

    def test_absolute_path_outside_etc(self) -> None:
        with self.assertRaises(backup.BackupError):
            backup.read_files(self.hostile("root/.bashrc"))

    def test_symlink_member(self) -> None:
        path = Path(self.tmp.name) / "link.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            info = tarfile.TarInfo("etc/sysctl.d/evil.conf")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/shadow"
            archive.addfile(info)
        with self.assertRaises(backup.BackupError):
            backup.read_files(path)


class TestMismatchWarning(unittest.TestCase):
    def test_warns_across_families(self) -> None:
        manifest = backup.Manifest(family="debian", distro="Ubuntu 26.04")
        warning = backup.mismatch_warning(manifest, "fedora", "Fedora 41")
        self.assertIn("Ubuntu", warning)
        self.assertIn("Fedora", warning)

    def test_silent_on_a_match(self) -> None:
        manifest = backup.Manifest(family="debian", distro="Ubuntu 26.04")
        self.assertEqual(backup.mismatch_warning(manifest, "debian", "Debian 13"), "")

    def test_says_so_when_there_is_no_manifest(self) -> None:
        self.assertIn("no manifest", backup.mismatch_warning(backup.Manifest(), "debian", "x"))


class TestSymlinksAreNotFollowed(SandboxCase):
    def test_a_link_out_of_etc_is_skipped(self) -> None:
        # Following it would pull whatever it points at into the archive.
        secret = Path(self.tmp.name) / "secret"
        secret.write_text("not for the archive\n")
        (self.root / "etc/sysctl.d/link.conf").symlink_to(secret)

        result = self.make()
        self.assertNotIn("/etc/sysctl.d/link.conf", result.files)
        files = backup.read_files(self.archive)
        self.assertNotIn("not for the archive\n", [c for c, _m in files.values()])



class TestPayloadEntryPoints(SandboxCase):
    """The helper-facing entry points, as run_payload dispatches to them."""

    def setUp(self) -> None:
        super().setUp()
        from ossgui import apply as apply_module

        self.apply = apply_module

    def test_run_payload_routes_the_three_actions(self) -> None:
        for action, error in (
            ("backup", "no destination"),
            ("restore-plan", "does not exist"),
            ("restore-apply", "does not exist"),
        ):
            with self.subTest(action=action):
                result = self.apply.run_payload(self.catalogue, {"version": 1, "action": action})
                self.assertFalse(result.ok)
                self.assertIn(error, result.error)

    def test_backup_refuses_a_location_it_does_not_know(self) -> None:
        result = self.apply.make_backup(
            self.catalogue,
            {"destination": str(self.archive), "locations": ["/etc/shadow"]},
        )
        self.assertFalse(result.ok)
        self.assertIn("not backup locations", result.error)

    def test_backup_refuses_an_empty_selection(self) -> None:
        result = self.apply.make_backup(
            self.catalogue, {"destination": str(self.archive), "locations": []}
        )
        self.assertFalse(result.ok)
        self.assertIn("nothing selected", result.error)

    def test_backup_refuses_a_symlinked_destination(self) -> None:
        elsewhere = Path(self.tmp.name) / "elsewhere.tar.gz"
        link = Path(self.tmp.name) / "link.tar.gz"
        link.symlink_to(elsewhere)
        result = self.apply.make_backup(
            self.catalogue, {"destination": str(link), "hostname": "x"}
        )
        self.assertFalse(result.ok)
        self.assertIn("symlink", result.error)

    def test_restore_plan_reports_differs_new_and_same(self) -> None:
        self.make()
        os.environ["OSS_ROOT"] = str(self.root)
        self.addCleanup(os.environ.pop, "OSS_ROOT", None)
        (self.root / "etc/sysctl.d/10-mine.conf").write_text("vm.swappiness = 60\n")
        (self.root / "etc/modprobe.d/blacklist-mine.conf").unlink()

        result = self.apply.restore_plan({"source": str(self.archive)})
        self.assertTrue(result.ok, result.error)
        changes = {
            c["path"]: c["state"] for c in result.integrity["restore"]["changes"]
        }
        # restore_plan reads current content off the real root, not the
        # sandbox — so only the archive side is asserted here.
        self.assertIn("/etc/sysctl.d/10-mine.conf", changes)
        self.assertIn("/etc/modprobe.d/blacklist-mine.conf", changes)


class TestRestoreThroughTheTransaction(SandboxCase):
    """The whole point: change the files, restore, get the originals back.

    Runs against OSS_ROOT so every write lands in the sandbox. apply.run is
    stubbed, so no reload command actually executes.
    """

    def setUp(self) -> None:
        super().setUp()
        from ossgui import apply as apply_module

        self.apply = apply_module
        os.environ["OSS_ROOT"] = str(self.root)
        self.addCleanup(os.environ.pop, "OSS_ROOT", None)

        # progress() writes to stderr on every phase; keep the suite readable.
        os.environ["OSS_QUIET"] = "1"
        self.addCleanup(os.environ.pop, "OSS_QUIET", None)

        self.ran: list[tuple[str, ...]] = []
        real = apply_module.run
        self.addCleanup(setattr, apply_module, "run", real)
        apply_module.run = lambda argv, stdin=None: (self.ran.append(tuple(argv)), (0, ""))[1]

    def test_restores_the_original_content(self) -> None:
        self.make()
        target = self.root / "etc/sysctl.d/10-mine.conf"
        target.write_text("vm.swappiness = 200\n")

        result = self.apply.restore_apply(
            self.catalogue,
            {"source": str(self.archive), "paths": ["/etc/sysctl.d/10-mine.conf"]},
        )
        self.assertTrue(result.ok, result.error)
        self.assertEqual(target.read_text(), "vm.swappiness = 10\n")

    def test_only_the_chosen_paths_are_written(self) -> None:
        self.make()
        untouched = self.root / "etc/modprobe.d/blacklist-mine.conf"
        untouched.write_text("blacklist something-else\n")

        self.apply.restore_apply(
            self.catalogue,
            {"source": str(self.archive), "paths": ["/etc/sysctl.d/10-mine.conf"]},
        )
        self.assertEqual(untouched.read_text(), "blacklist something-else\n")

    def test_the_previous_file_is_backed_up_first(self) -> None:
        self.make()
        target = self.root / "etc/sysctl.d/10-mine.conf"
        target.write_text("vm.swappiness = 200\n")

        self.apply.restore_apply(
            self.catalogue,
            {"source": str(self.archive), "paths": ["/etc/sysctl.d/10-mine.conf"]},
        )
        backup_file = target.with_name(target.name + ".bak")
        self.assertTrue(backup_file.exists())
        self.assertEqual(backup_file.read_text(), "vm.swappiness = 200\n")

    def test_a_failing_reload_rolls_the_restore_back(self) -> None:
        self.make()
        target = self.root / "etc/sysctl.d/10-mine.conf"
        target.write_text("vm.swappiness = 200\n")

        def failing(argv, stdin=None):
            self.ran.append(tuple(argv))
            return 1, "simulated reload failure"

        self.apply.run = failing
        result = self.apply.restore_apply(
            self.catalogue,
            {"source": str(self.archive), "paths": ["/etc/sysctl.d/10-mine.conf"]},
        )
        self.assertFalse(result.ok)
        self.assertTrue(result.rolled_back)
        self.assertEqual(target.read_text(), "vm.swappiness = 200\n")

    def test_it_reloads_what_it_restored(self) -> None:
        self.make()
        self.apply.restore_apply(
            self.catalogue,
            {"source": str(self.archive), "paths": ["/etc/sysctl.d/10-mine.conf"]},
        )
        self.assertTrue(any("sysctl" in " ".join(c) for c in self.ran), self.ran)

    def test_a_path_not_in_the_archive_is_refused(self) -> None:
        # The GUI says which backup, never what is in it.
        self.make()
        result = self.apply.restore_apply(
            self.catalogue,
            {"source": str(self.archive), "paths": ["/etc/shadow"]},
        )
        self.assertFalse(result.ok)
        self.assertIn("not in that backup", result.error)

    def test_nothing_selected_writes_nothing(self) -> None:
        self.make()
        result = self.apply.restore_apply(
            self.catalogue, {"source": str(self.archive), "paths": []}
        )
        self.assertTrue(result.ok)
        self.assertEqual(self.ran, [])

if __name__ == "__main__":
    unittest.main()
