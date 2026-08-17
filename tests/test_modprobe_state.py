"""Blacklists: the file is the state, not whether the module happens to be loaded.

v1.0.0 and both releases before it read "module not loaded" as "module
blacklisted". A stock kernel ships around 6,900 modules and boots on about 130,
so on a fresh install 159 of the 170 modules in the curated section reported as
already blocked when nothing was blocking any of them — and because a flag that
reads as in-effect cannot be switched off, they could not be selected either.
Both halves of that are what these tests pin.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ossgui import branding, catalogue, probe  # noqa: E402


def _facts(blacklisted: dict, modules: dict | None = None, files: dict | None = None):
    return probe.SystemFacts(
        files=files or {}, cmdline=[], modules=modules or {}, units={},
        gsettings={}, vulnerabilities={}, blacklisted=blacklisted,
    )


def _state(facts, flag_id="mod_cramfs"):
    cat = catalogue.load()
    flag = cat.get(flag_id)
    return probe.flag_state(cat.section(flag.section), flag, facts, None)


class TestNotLoadedIsNotBlacklisted(unittest.TestCase):

    def test_idle_module_with_no_blacklist_is_not_set(self) -> None:
        """The regression itself: nothing blacklists cramfs, nothing has loaded it."""
        state = _state(_facts({}))
        self.assertIs(state.state, probe.State.NOT_SET)

    def test_a_whole_stock_section_reads_as_unset(self) -> None:
        """No blacklists anywhere means no flag in the section is in effect."""
        cat = catalogue.load()
        section = cat.section("modprobe")
        facts = _facts({})
        in_effect = [
            flag.key
            for flag in section.flags
            if probe.flag_state(section, flag, facts, None).state
            in (probe.State.APPLIED, probe.State.PENDING_REBOOT)
        ]
        self.assertEqual(in_effect, [])

    def test_blacklisted_and_idle_is_applied(self) -> None:
        state = _state(_facts({"cramfs": "/etc/modprobe.d/99-oss.conf"}))
        self.assertIs(state.state, probe.State.APPLIED)

    def test_blacklisted_but_still_loaded_needs_a_reboot(self) -> None:
        state = _state(
            _facts({"cramfs": "/etc/modprobe.d/99-oss.conf"}, modules={"cramfs": 2})
        )
        self.assertIs(state.state, probe.State.PENDING_REBOOT)
        self.assertIn("refcount 2", state.note)

    def test_loaded_and_not_blacklisted_is_still_not_set(self) -> None:
        """Loaded says nothing either way — only the absent blacklist decides."""
        state = _state(_facts({}, modules={"cramfs": 1}))
        self.assertIs(state.state, probe.State.NOT_SET)


class TestAttribution(unittest.TestCase):
    """In effect is not the same as *you* set it."""

    def test_a_distro_blacklist_names_the_file_that_set_it(self) -> None:
        state = _state(_facts({"cramfs": "/etc/modprobe.d/blacklist.conf"}))
        self.assertIs(state.state, probe.State.APPLIED)
        self.assertIn("/etc/modprobe.d/blacklist.conf", state.note)
        self.assertIn("this app did not write", state.note)

    def test_our_own_drop_in_is_not_reported_as_someone_elses(self) -> None:
        cat = catalogue.load()
        flag = cat.get("mod_cramfs")
        section = cat.section(flag.section)
        target = section.target_for(flag)
        facts = _facts(
            {"cramfs": target},
            files={target: branding.DROPIN + "blacklist cramfs\n"},
        )
        state = probe.flag_state(section, flag, facts, None)
        self.assertIs(state.state, probe.State.APPLIED)
        self.assertEqual(state.note, "")


class TestReadBlacklists(unittest.TestCase):
    """What counts as a blacklist line, across every directory modprobe reads."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self._real_dirs = probe.MODPROBE_DIRS
        probe.MODPROBE_DIRS = (str(self.dir),)
        self.addCleanup(setattr, probe, "MODPROBE_DIRS", self._real_dirs)

    def _write(self, name: str, body: str) -> None:
        (self.dir / name).write_text(body, encoding="utf-8")

    def test_hyphens_and_underscores_are_the_same_module(self) -> None:
        """modprobe treats them as one name, so a hyphenated line must still match."""
        self._write("distro.conf", "blacklist snd-aw2\n")
        self.assertIn("snd_aw2", probe.read_blacklists())

    def test_install_bin_false_counts_as_a_block(self) -> None:
        self._write("ours.conf", "install cramfs /bin/false\n")
        self.assertIn("cramfs", probe.read_blacklists())

    def test_an_ordinary_install_line_is_not_a_block(self) -> None:
        """alsa-base.conf sequences its own loads this way; that blocks nothing."""
        self._write("alsa-base.conf", "install snd-pcm /sbin/modprobe --ignore-install snd-pcm\n")
        self.assertEqual(probe.read_blacklists(), {})

    def test_commented_out_lines_are_not_a_block(self) -> None:
        self._write("distro.conf", "# blacklist cramfs\n")
        self.assertEqual(probe.read_blacklists(), {})

    def test_files_not_ending_in_conf_are_ignored(self) -> None:
        """modprobe only reads *.conf, so neither do we — .dpkg-old, .bak and friends."""
        self._write("blacklist.conf.dpkg-old", "blacklist cramfs\n")
        self.assertEqual(probe.read_blacklists(), {})

    def test_our_own_file_wins_the_attribution(self) -> None:
        self._write("10-distro.conf", "blacklist cramfs\n")
        self._write("99-oss.conf", branding.DROPIN + "blacklist cramfs\n")
        self.assertIn("99-oss.conf", probe.read_blacklists()["cramfs"])


if __name__ == "__main__":
    unittest.main()
