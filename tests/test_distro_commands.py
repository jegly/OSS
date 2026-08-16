"""Per-family reload commands and section availability.

These are the differences that were silently wrong before: the ssh unit is
named ssh.service only on Debian, and update-grub / update-initramfs are Debian
wrapper scripts that do not exist anywhere else.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ossgui import catalogue, distro, render  # noqa: E402

SSH_RELOAD = ("/usr/bin/systemctl", "try-reload-or-restart", "ssh.service")


class TestResolveCommand(unittest.TestCase):
    def test_debian_is_unchanged(self) -> None:
        # The catalogue is written in Debian terms, so this must be identity.
        for argv in (("/usr/sbin/update-grub",),
                     ("/usr/sbin/update-initramfs", "-u"),
                     SSH_RELOAD):
            with self.subTest(argv=argv):
                self.assertEqual(distro.resolve_command(argv, "debian"), argv)

    def test_grub(self) -> None:
        self.assertEqual(
            distro.resolve_command(("/usr/sbin/update-grub",), "arch"),
            ("/usr/bin/grub-mkconfig", "-o", "/boot/grub/grub.cfg"),
        )
        for family in ("fedora", "suse"):
            with self.subTest(family=family):
                self.assertEqual(
                    distro.resolve_command(("/usr/sbin/update-grub",), family),
                    ("/usr/sbin/grub2-mkconfig", "-o", "/boot/grub2/grub.cfg"),
                )

    def test_initramfs(self) -> None:
        argv = ("/usr/sbin/update-initramfs", "-u")
        self.assertEqual(
            distro.resolve_command(argv, "arch"), ("/usr/bin/mkinitcpio", "-P")
        )
        self.assertEqual(
            distro.resolve_command(argv, "fedora"),
            ("/usr/bin/dracut", "--force", "--regenerate-all"),
        )

    def test_ssh_unit_is_renamed_not_the_rest_of_the_argv(self) -> None:
        for family in ("arch", "fedora", "suse"):
            with self.subTest(family=family):
                self.assertEqual(
                    distro.resolve_command(SSH_RELOAD, family),
                    ("/usr/bin/systemctl", "try-reload-or-restart", "sshd.service"),
                )

    def test_unknown_family_leaves_commands_alone(self) -> None:
        # Better to run the catalogue's own wording and fail loudly than to
        # guess at a distro nobody has thought about.
        self.assertEqual(distro.resolve_command(SSH_RELOAD, "unknown"), SSH_RELOAD)

    def test_every_substitution_is_on_the_helper_allowlist(self) -> None:
        # The helper compiles its allowlist from render.ALLOWED_COMMANDS, so a
        # substitution missing from it would be refused at apply time on that
        # family only — the worst possible place to find out.
        for by_family in distro._COMMANDS.values():
            for family, argv in by_family.items():
                with self.subTest(family=family, argv=argv):
                    self.assertIn(argv[0], render.ALLOWED_COMMANDS)


class TestSectionSupport(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalogue = catalogue.load()

    def test_updates_is_debian_only(self) -> None:
        # apt.conf.d has no equivalent elsewhere: Fedora schedules through
        # dnf-automatic and Arch has nothing at all.
        section = self.catalogue.section("updates")
        self.assertTrue(distro.section_supported(section, "debian"))
        for family in ("arch", "fedora", "suse"):
            with self.subTest(family=family):
                self.assertFalse(distro.section_supported(section, family))

    def test_portable_sections_apply_everywhere(self) -> None:
        # grub is on this list because the section edits /etc/default/grub in
        # place. It was Debian-only while it wrote a /etc/default/grub.d drop-in,
        # which only Debian's grub-mkconfig sources.
        for section_id in ("sysctl", "ssh", "sudo", "auditd", "logging", "grub"):
            for family in ("debian", "arch", "fedora", "suse"):
                with self.subTest(section=section_id, family=family):
                    section = self.catalogue.section(section_id)
                    self.assertTrue(distro.section_supported(section, family))

    def test_unknown_family_gets_everything(self) -> None:
        # An unrecognised derivative should degrade to "try and report
        # honestly", not to a mostly-empty application.
        section = self.catalogue.section("grub")
        self.assertTrue(distro.section_supported(section, "unknown"))

    def test_plan_skips_unsupported_sections(self) -> None:
        """The real guard: an unsupported section must reach no plan at all.

        Writing the file and running a reload that succeeds would report a
        change that had no effect, which is the failure this app exists to
        surface rather than produce.
        """
        import os

        updates = self.catalogue.section("updates")
        selection = {flag.id: flag.value for flag in updates.flags[:3]}

        os.environ["OSS_DISTRO_FAMILY"] = "fedora"
        self.addCleanup(os.environ.pop, "OSS_DISTRO_FAMILY", None)
        from ossgui import probe

        probe.detect_family.cache_clear()
        self.addCleanup(probe.detect_family.cache_clear)

        plan = render.render(self.catalogue, selection)
        self.assertEqual(
            [w.path for w in plan.writes if "apt.conf" in w.path], []
        )


class TestServiceUnitsPerFamily(unittest.TestCase):
    """Two separate problems, easy to conflate.

    Some units do not exist off Ubuntu at all (whoopsie, apt-news) and the flag
    should not apply. Others exist under a different name (Debian's smbd is
    everyone else's smb) and the flag *should* apply, resolved. Getting the
    second wrong is the dangerous one: masking a unit name that does not exist
    succeeds silently, so Samba keeps answering while the app calls it masked.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.catalogue = catalogue.load()

    def units_for(self, family: str) -> list[str]:
        import os

        from ossgui import probe

        os.environ["OSS_DISTRO_FAMILY"] = family
        probe.detect_family.cache_clear()
        try:
            services = self.catalogue.section("services")
            selection = {flag.id: "mask" for flag in services.flags}
            plan = render.render_section(services, selection, {})
            return [command.argv[-1] for command in plan.commands]
        finally:
            os.environ.pop("OSS_DISTRO_FAMILY", None)
            probe.detect_family.cache_clear()

    def test_renamed_units_resolve(self) -> None:
        debian = self.units_for("debian")
        self.assertIn("smbd.service", debian)
        self.assertIn("rsync.service", debian)

        for family in ("fedora", "arch", "suse"):
            with self.subTest(family=family):
                units = self.units_for(family)
                self.assertIn("smb.service", units)
                self.assertIn("nmb.service", units)
                self.assertIn("rsyncd.service", units)
                self.assertNotIn("smbd.service", units)
                self.assertNotIn("rsync.service", units)

    def test_ubuntu_only_units_are_dropped_elsewhere(self) -> None:
        ubuntu_only = {
            "whoopsie.service",
            "apport.service",
            "apt-news.service",
            "esm-cache.service",
        }
        self.assertTrue(ubuntu_only.issubset(set(self.units_for("debian"))))
        for family in ("fedora", "arch", "suse"):
            with self.subTest(family=family):
                self.assertFalse(ubuntu_only & set(self.units_for(family)))

    def test_dropping_is_not_the_same_as_renaming(self) -> None:
        # A renamed unit must still be acted on, not quietly skipped — the
        # count difference between families should be exactly the units that
        # genuinely do not exist.
        self.assertEqual(
            len(self.units_for("debian")) - len(self.units_for("fedora")), 4
        )


if __name__ == "__main__":
    unittest.main()
