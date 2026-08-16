"""CPU mitigations: a cmdline parameter is a request, sysfs is the answer."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

class TestMitigationContradiction(unittest.TestCase):
    """A cmdline parameter is a request; sysfs is the answer.

    The app used to report spec_store_bypass_disable as applied purely because
    the token was on the command line, on a machine whose kernel reported
    "Vulnerable" — confidently wrong about a security control, which is the one
    failure this app exists to prevent.
    """

    def _facts(self, cmdline: list, vulns: dict):
        from ossgui import probe

        return probe.SystemFacts(
            files={}, cmdline=cmdline, modules=set(), units={},
            gsettings={}, vulnerabilities=vulns,
        )

    def _state(self, cmdline, vulns, flag_id="spec_store_bypass_disable"):
        from ossgui import catalogue, probe

        cat = catalogue.load()
        flag = cat.get(flag_id)
        section = cat.section(flag.section)
        return probe.flag_state(section, flag, self._facts(cmdline, vulns), flag.value)

    def test_present_and_working_is_applied(self) -> None:
        from ossgui import probe

        state = self._state(
            ["spec_store_bypass_disable=on"],
            {"spec_store_bypass": "Mitigation: Speculative Store Bypass disabled"},
        )
        self.assertIs(state.state, probe.State.APPLIED)

    def test_present_but_vulnerable_is_drift_not_applied(self) -> None:
        from ossgui import probe

        state = self._state(
            ["spec_store_bypass_disable=on"], {"spec_store_bypass": "Vulnerable"}
        )
        self.assertIs(state.state, probe.State.DIFFERS)
        self.assertIn("did not take effect", state.note)

    def test_the_negating_parameter_is_named(self) -> None:
        state = self._state(
            ["spec_store_bypass_disable=on", "nospec_store_bypass_disable=0"],
            {"spec_store_bypass": "Vulnerable"},
        )
        self.assertIn("nospec_store_bypass_disable", state.note)
        self.assertIn("overrides it", state.note)

    def test_missing_microcode_is_explained_as_unfixable(self) -> None:
        state = self._state(
            ["spec_store_bypass_disable=on"],
            {"spec_store_bypass": "Vulnerable: No microcode"},
        )
        self.assertIn("microcode", state.note)

    def test_mitigations_off_counts_as_a_negation(self) -> None:
        from ossgui import probe

        found = probe._negating_tokens(["mitigations=off"], "spec_store_bypass")
        self.assertEqual(found, ["mitigations=off"])

    def test_a_positive_value_is_not_a_negation(self) -> None:
        from ossgui import probe

        self.assertEqual(probe._negating_tokens(["mds=full,nosmt"], "mds"), [])
        self.assertEqual(probe._negating_tokens(["mds=off"], "mds"), ["mds=off"])

    def test_a_non_cpu_flag_is_never_contradicted(self) -> None:
        from ossgui import catalogue, probe

        cat = catalogue.load()
        flag = cat.get("slab_nomerge")
        self.assertEqual(
            probe._mitigation_contradiction(flag, self._facts([], {})), ""
        )


if __name__ == "__main__":
    unittest.main()
