"""Distro family detection from os-release.

Sample os-release contents are the real ones from each distribution, trimmed to
the fields that matter, because the whole point is that a derivative nobody
anticipated still resolves to the right family through ID_LIKE.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ossgui import probe  # noqa: E402


def family(text: str) -> str:
    return probe.family_from_os_release(probe.parse_os_release(text))


class TestParseOsRelease(unittest.TestCase):
    def test_strips_both_quote_styles(self) -> None:
        parsed = probe.parse_os_release('ID=fedora\nNAME="Fedora Linux"\nX=\'q\'\n')
        self.assertEqual(parsed["ID"], "fedora")
        self.assertEqual(parsed["NAME"], "Fedora Linux")
        self.assertEqual(parsed["X"], "q")

    def test_skips_comments_and_junk_without_raising(self) -> None:
        parsed = probe.parse_os_release("# a comment\n\ngarbage\nID=arch\n")
        self.assertEqual(parsed, {"ID": "arch"})


class TestFamilyDetection(unittest.TestCase):
    def test_roots(self) -> None:
        self.assertEqual(family('ID=debian\n'), "debian")
        self.assertEqual(family('ID=arch\n'), "arch")
        self.assertEqual(family('ID=fedora\n'), "fedora")
        self.assertEqual(family('ID="opensuse-tumbleweed"\n'), "suse")

    def test_ubuntu(self) -> None:
        self.assertEqual(family('ID=ubuntu\nID_LIKE=debian\n'), "debian")

    def test_derivatives_resolve_through_id_like(self) -> None:
        # None of these IDs are in the table; each has to come back through
        # ID_LIKE, which is the whole reason for not enumerating distros.
        cases = {
            'ID=linuxmint\nID_LIKE="ubuntu debian"\n': "debian",
            'ID=pop\nID_LIKE="ubuntu debian"\n': "debian",
            'ID=manjaro\nID_LIKE=arch\n': "arch",
            'ID=endeavouros\nID_LIKE=arch\n': "arch",
            'ID=cachyos\nID_LIKE=arch\n': "arch",
            'ID=nobara\nID_LIKE=fedora\n': "fedora",
            'ID=rocky\nID_LIKE="rhel centos fedora"\n': "fedora",
            'ID=almalinux\nID_LIKE="rhel centos fedora"\n': "fedora",
            'ID=tumbleweed\nID_LIKE="opensuse suse"\n': "suse",
        }
        for text, expected in cases.items():
            with self.subTest(text=text.replace("\n", " ")):
                self.assertEqual(family(text), expected)

    def test_id_wins_over_id_like(self) -> None:
        # Ubuntu says ID_LIKE=debian, and for our purposes that is the same
        # answer — but the ordering has to be deliberate, not incidental.
        self.assertEqual(family('ID=fedora\nID_LIKE=debian\n'), "fedora")

    def test_unknown_when_nothing_matches(self) -> None:
        self.assertEqual(family('ID=plan9\n'), "unknown")
        self.assertEqual(family(""), "unknown")

    def test_id_like_order_is_the_distributions_not_ours(self) -> None:
        # ID_LIKE is ordered closest-first by convention. A distro claiming to
        # be like arch before fedora should come back arch.
        self.assertEqual(family('ID=weird\nID_LIKE="arch fedora"\n'), "arch")


class TestDetectFamily(unittest.TestCase):
    def setUp(self) -> None:
        probe.detect_family.cache_clear()
        self.addCleanup(probe.detect_family.cache_clear)

    def test_env_override_wins(self) -> None:
        import os

        os.environ["OSS_DISTRO_FAMILY"] = "fedora"
        self.addCleanup(os.environ.pop, "OSS_DISTRO_FAMILY", None)
        self.assertEqual(probe.detect_family(), "fedora")

    def test_override_must_be_a_known_family(self) -> None:
        import os

        os.environ["OSS_DISTRO_FAMILY"] = "notadistro"
        self.addCleanup(os.environ.pop, "OSS_DISTRO_FAMILY", None)
        # Falls through to real detection rather than trusting the value.
        self.assertIn(probe.detect_family(), probe.FAMILIES + ("unknown",))

    def test_detects_this_machine(self) -> None:
        self.assertIn(probe.detect_family(), probe.FAMILIES + ("unknown",))


if __name__ == "__main__":
    unittest.main()
