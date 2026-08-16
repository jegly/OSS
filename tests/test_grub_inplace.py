"""The grub section edits /etc/default/grub in place.

It used to write a /etc/default/grub.d drop-in. That works on Debian and splits
the truth across two files: the GRUB_CMDLINE_LINUX_DEFAULT you read in
/etc/default/grub is not the one that boots. These tests pin the merge rules,
because getting them wrong writes a broken kernel command line.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ossgui import branding, catalogue, probe, render  # noqa: E402

STOCK = """\
# If you change this file or any /etc/default/grub.d/*.cfg file,
# run 'update-grub' afterwards to update /boot/grub/grub.cfg.

GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR=`( . /etc/os-release && echo ${NAME} )`
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX=""
"""

TARGET = "/etc/default/grub"


class GrubCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalogue = catalogue.load()

    def merge(self, selection: dict, current: str = STOCK) -> str:
        section = self.catalogue.section("grub")
        plan = render.render_section(section, selection, current={TARGET: current})
        self.assertEqual(
            [w.path for w in plan.writes], [TARGET],
            "the grub section must write /etc/default/grub and nothing else",
        )
        return plan.writes[0].content

    def cmdline(self, content: str) -> list[str]:
        for line in content.splitlines():
            if line.startswith("GRUB_CMDLINE_LINUX_DEFAULT="):
                return render._split_cmdline(line.partition("=")[2])
        return []


class TestTarget(GrubCase):
    def test_the_section_targets_the_real_file(self) -> None:
        section = self.catalogue.section("grub")
        self.assertEqual(section.target, TARGET)
        self.assertTrue(section.in_place, "editing a distro file needs a .bak")

    def test_the_write_is_marked_in_place(self) -> None:
        section = self.catalogue.section("grub")
        plan = render.render_section(
            section, {"slab_nomerge": ""}, current={TARGET: STOCK}
        )
        self.assertTrue(plan.writes[0].in_place)


class TestMerge(GrubCase):
    def test_unmanaged_tokens_survive(self) -> None:
        """quiet and splash are the user's, not ours."""
        tokens = self.cmdline(self.merge({"slab_nomerge": ""}))
        self.assertIn("quiet", tokens)
        self.assertIn("splash", tokens)

    def test_the_selected_flag_is_added(self) -> None:
        tokens = self.cmdline(self.merge({"slab_nomerge": "", "pti_on": "on"}))
        self.assertIn("slab_nomerge", tokens)
        self.assertIn("pti=on", tokens)

    def test_unticking_removes_the_token(self) -> None:
        first = self.merge({"slab_nomerge": "", "pti_on": "on"})
        second = self.merge({"pti_on": "on"}, current=first)
        tokens = self.cmdline(second)
        self.assertIn("pti=on", tokens)
        self.assertNotIn("slab_nomerge", tokens)

    def test_a_hand_set_duplicate_collapses(self) -> None:
        """A hand-edited file routinely sets the same key twice."""
        messy = STOCK.replace(
            'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"',
            'GRUB_CMDLINE_LINUX_DEFAULT="quiet pti=off splash pti=auto"',
        )
        tokens = self.cmdline(self.merge({"pti_on": "on"}, current=messy))
        self.assertEqual([t for t in tokens if t.startswith("pti=")], ["pti=on"])

    def test_a_grub_variable_is_rewritten_in_place(self) -> None:
        content = self.merge({"grub_timeout_zero": "0"})
        self.assertIn("GRUB_TIMEOUT=0\n", content)
        self.assertNotIn("GRUB_TIMEOUT=5\n", content)
        # and only once
        self.assertEqual(content.count("GRUB_TIMEOUT="), 1)

    def test_lines_we_do_not_manage_are_untouched(self) -> None:
        """GRUB_DISTRIBUTOR is a command substitution — reparsing it breaks it."""
        content = self.merge({"slab_nomerge": ""})
        self.assertIn(
            "GRUB_DISTRIBUTOR=`( . /etc/os-release && echo ${NAME} )`\n", content
        )
        self.assertIn('GRUB_CMDLINE_LINUX=""\n', content)
        self.assertIn("# If you change this file", content)

    def test_a_missing_cmdline_line_is_appended(self) -> None:
        bare = "GRUB_TIMEOUT=5\n"
        tokens = self.cmdline(self.merge({"slab_nomerge": ""}, current=bare))
        self.assertEqual(tokens, ["slab_nomerge"])


class TestIdempotence(GrubCase):
    def test_applying_twice_proposes_nothing_the_second_time(self) -> None:
        selection = {"slab_nomerge": "", "pti_on": "on"}
        once = self.merge(selection)
        section = self.catalogue.section("grub")
        plan = render.render_section(section, selection, current={TARGET: once})
        self.assertEqual(plan.writes, [], "a settled file must not be rewritten")

    def test_the_banner_does_not_accumulate(self) -> None:
        content = self.merge({"slab_nomerge": ""})
        self.assertEqual(content.count(branding.MARKER), 1)
        again = self.merge({"slab_nomerge": "", "pti_on": "on"}, current=content)
        self.assertEqual(content.count(branding.MARKER), 1)
        self.assertEqual(again.count(branding.MARKER), 1)

    def test_the_file_is_recognised_as_ours_afterwards(self) -> None:
        self.assertTrue(probe.is_ours(self.merge({"slab_nomerge": ""})))


class TestRestraint(GrubCase):
    def test_nothing_staged_leaves_a_file_we_have_never_written(self) -> None:
        section = self.catalogue.section("grub")
        plan = render.render_section(section, {}, current={TARGET: STOCK})
        self.assertEqual(plan.writes, [])
        self.assertEqual(
            [r.path for r in plan.removes if r.path == TARGET], [],
            "/etc/default/grub belongs to the distribution — never delete it",
        )

    def test_nothing_staged_strips_our_tokens_from_our_own_file(self) -> None:
        ours = self.merge({"slab_nomerge": "", "pti_on": "on"})
        section = self.catalogue.section("grub")
        plan = render.render_section(section, {}, current={TARGET: ours})
        tokens = self.cmdline(plan.writes[0].content)
        self.assertNotIn("slab_nomerge", tokens)
        self.assertNotIn("pti=on", tokens)
        self.assertIn("quiet", tokens)


class TestCmdlineSplitting(unittest.TestCase):
    def test_a_quoted_value_splits_into_tokens(self) -> None:
        """shlex would return the whole quoted string as one token."""
        self.assertEqual(
            render._split_cmdline('"quiet splash pti=on"'),
            ["quiet", "splash", "pti=on"],
        )

    def test_an_unquoted_value_still_splits(self) -> None:
        self.assertEqual(render._split_cmdline("quiet splash"), ["quiet", "splash"])

    def test_an_unbalanced_quote_does_not_raise(self) -> None:
        self.assertEqual(render._split_cmdline('"quiet splash'), ['"quiet', "splash"])

    def test_empty(self) -> None:
        self.assertEqual(render._split_cmdline('""'), [])


if __name__ == "__main__":
    unittest.main()
