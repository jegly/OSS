"""Firewall model tests — rule validation, status parsing and command planning."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from hardeninggui import ufw  # noqa: E402


class TestRuleValidation(unittest.TestCase):
    def test_accepts_a_plain_port_rule(self) -> None:
        rule = ufw.Rule("deny", "in", "3389", "tcp")
        self.assertEqual(rule.to_argv(), ["/usr/sbin/ufw", "deny", "in", "3389/tcp"])

    def test_accepts_a_subnet_rule(self) -> None:
        rule = ufw.Rule("allow", "in", "22", "tcp", from_addr="192.168.1.0/24")
        self.assertEqual(
            rule.to_argv(),
            ["/usr/sbin/ufw", "allow", "in", "from", "192.168.1.0/24",
             "to", "any", "port", "22", "proto", "tcp"],
        )

    def test_delete_form_drops_the_comment(self) -> None:
        rule = ufw.Rule("deny", "in", "23", "tcp", comment="Telnet")
        self.assertNotIn("comment", rule.to_argv(delete=True))
        self.assertIn("delete", rule.to_argv(delete=True))

    def test_rejects_shell_metacharacters_in_a_port(self) -> None:
        with self.assertRaises(ufw.UfwError):
            ufw.Rule("deny", "in", "22; rm -rf /", "tcp").validate()

    def test_rejects_command_substitution_in_an_address(self) -> None:
        with self.assertRaises(ufw.UfwError):
            ufw.Rule("deny", "in", "22", "tcp", from_addr="$(whoami)").validate()

    def test_rejects_backticks_in_a_comment(self) -> None:
        with self.assertRaises(ufw.UfwError):
            ufw.Rule("deny", "in", "22", "tcp", comment="hi `id`").validate()

    def test_rejects_out_of_range_port(self) -> None:
        with self.assertRaises(ufw.UfwError):
            ufw.Rule("deny", "in", "99999", "tcp").validate()

    def test_rejects_unknown_action(self) -> None:
        with self.assertRaises(ufw.UfwError):
            ufw.Rule("drop-table", "in", "22", "tcp").validate()

    def test_rejects_a_range_without_a_protocol(self) -> None:
        """ufw itself refuses a port range with no protocol."""
        with self.assertRaises(ufw.UfwError):
            ufw.Rule("deny", "in", "6000:6010", "any").validate()

    def test_rejects_a_rule_with_neither_port_nor_address(self) -> None:
        with self.assertRaises(ufw.UfwError):
            ufw.Rule("deny", "in", "", "any").validate()


class TestPolicyParsing(unittest.TestCase):
    def test_iptables_targets_map_to_ufw_words(self) -> None:
        """/etc/default/ufw stores DROP/ACCEPT/REJECT, not deny/allow/reject.

        Reading them literally reports the wrong policy — a machine with DROP
        outgoing would show as "allow", which is the opposite of the truth.
        """
        self.assertEqual(ufw._TARGET_TO_POLICY["drop"], "deny")
        self.assertEqual(ufw._TARGET_TO_POLICY["accept"], "allow")
        self.assertEqual(ufw._TARGET_TO_POLICY["reject"], "reject")


class TestStatusParsing(unittest.TestCase):
    SAMPLE = """Status: active
Logging: on (low)
Default: deny (incoming), deny (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     DENY IN     Anywhere
3389/tcp                   DENY IN     Anywhere                   # RDP
53                         ALLOW OUT   Anywhere                   # DNS
443/tcp                    ALLOW OUT   Anywhere
22/tcp (v6)                DENY IN     Anywhere (v6)
192.168.1.0/24 22/tcp      ALLOW IN    Anywhere
"""

    def test_parses_rules(self) -> None:
        rules = ufw.parse_status(self.SAMPLE)
        self.assertGreaterEqual(len(rules), 5)
        first = rules[0]
        self.assertEqual((first.action, first.direction, first.port, first.proto),
                         ("deny", "in", "22", "tcp"))

    def test_keeps_comments(self) -> None:
        rules = ufw.parse_status(self.SAMPLE)
        rdp = next(r for r in rules if r.port == "3389")
        self.assertEqual(rdp.comment, "RDP")

    def test_marks_v6_rules(self) -> None:
        rules = ufw.parse_status(self.SAMPLE)
        self.assertTrue(any(r.v6 for r in rules))

    def test_skips_the_header(self) -> None:
        rules = ufw.parse_status(self.SAMPLE)
        self.assertFalse(any(r.port == "Status:" for r in rules))


class TestPlanning(unittest.TestCase):
    def test_policy_change_emits_one_command(self) -> None:
        current = ufw.State(default_incoming="allow")
        wanted = current.copy()
        wanted.default_incoming = "deny"
        commands = ufw.plan_commands(current, wanted)
        self.assertEqual(commands[0][0], ["/usr/sbin/ufw", "default", "deny", "incoming"])

    def test_no_change_emits_nothing(self) -> None:
        state = ufw.State(rules_loaded=True)
        self.assertEqual(ufw.plan_commands(state, state.copy()), [])

    def test_enable_comes_last(self) -> None:
        """The policy has to be in place before the firewall comes up."""
        current = ufw.State(enabled=False, default_incoming="allow")
        wanted = current.copy()
        wanted.enabled = True
        wanted.default_incoming = "deny"
        commands = ufw.plan_commands(current, wanted)
        self.assertIn("enable", commands[-1][0])

    def test_added_and_removed_rules(self) -> None:
        current = ufw.State(rules_loaded=True, rules=[ufw.Rule("deny", "in", "22", "tcp")])
        wanted = current.copy()
        wanted.rules = [ufw.Rule("deny", "in", "23", "tcp")]
        commands = [" ".join(argv) for argv, _why in ufw.plan_commands(current, wanted)]
        self.assertTrue(any("delete" in c and "22/tcp" in c for c in commands))
        self.assertTrue(any("delete" not in c and "23/tcp" in c for c in commands))

    def test_never_emits_a_reset(self) -> None:
        """A reset would drop rules the app was never told about."""
        current = ufw.State(rules_loaded=True, rules=[ufw.Rule("deny", "in", "22", "tcp")])
        wanted = ufw.State(rules_loaded=True, rules=[])
        commands = [" ".join(argv) for argv, _why in ufw.plan_commands(current, wanted)]
        self.assertFalse(any("reset" in c for c in commands))

    def test_rules_are_not_touched_until_they_have_been_read(self) -> None:
        """Without a privileged read we do not know the rules — so change nothing."""
        current = ufw.State(rules_loaded=False)
        wanted = current.copy()
        wanted.rules = [ufw.Rule("deny", "in", "22", "tcp")]
        self.assertEqual(ufw.plan_commands(current, wanted), [])


class TestHygiene(unittest.TestCase):
    def test_redundant_rules_are_identified(self) -> None:
        state = ufw.State(
            default_incoming="deny",
            rules=[
                ufw.Rule("deny", "in", "445", "tcp"),
                ufw.Rule("allow", "in", "22", "tcp"),
            ],
        )
        redundant = state.redundant_rules()
        self.assertEqual([r.port for r in redundant], ["445"])

    def test_missing_outbound_allowances_only_matter_under_deny(self) -> None:
        self.assertEqual(ufw.State(default_outgoing="allow").missing_recommended(), [])
        missing = ufw.State(default_outgoing="deny").missing_recommended()
        self.assertIn("123", [rule.port for rule, _why in missing])

    def test_payload_round_trip(self) -> None:
        state = ufw.State(
            enabled=True,
            default_outgoing="deny",
            rules=[ufw.Rule("allow", "out", "123", "udp", comment="NTP")],
            rules_loaded=True,
        )
        restored = ufw.from_payload(ufw.to_payload(state))
        self.assertEqual(restored.rules[0].key(), state.rules[0].key())
        self.assertEqual(restored.default_outgoing, "deny")

    def test_payload_rejects_an_invalid_rule(self) -> None:
        payload = ufw.to_payload(ufw.State())
        payload["rules"] = [{"action": "allow", "direction": "in", "port": "22; id"}]
        with self.assertRaises(ufw.UfwError):
            ufw.from_payload(payload)


if __name__ == "__main__":
    unittest.main()
