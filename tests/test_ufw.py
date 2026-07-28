"""Firewall model tests — rule validation, status parsing and command planning."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ossgui import ufw  # noqa: E402


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


class TestApplicationProfileRules(unittest.TestCase):
    """`ufw allow CUPS` prints a profile name where a port would be.

    That name used to land in to_addr, which made the Rule fail its own
    validate() as "not an address or subnet: 'CUPS'". Every consequence was
    bad: the privileged read of the rule list failed outright, so the firewall
    page could never show rules on a machine with an app-profile rule; and if a
    payload got past that, plan_commands raised UfwError out of the middle of an
    apply — a ValueError, which apply_plan did not catch — with the files
    already written and no rollback.
    """

    SAMPLE = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
CUPS                       ALLOW IN    Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
"""

    def test_profile_name_is_not_read_as_an_address(self) -> None:
        rules = ufw.parse_status(self.SAMPLE)
        cups = next(r for r in rules if r.app)
        self.assertEqual(cups.app, "CUPS")
        self.assertEqual(cups.to_addr, "any")
        self.assertFalse(cups.managed)

    def test_every_parsed_rule_passes_its_own_validation(self) -> None:
        # The invariant that was broken: a parser must not emit model objects
        # that its own validate() rejects.
        for rule in ufw.parse_status(self.SAMPLE):
            with self.subTest(rule=rule.summary):
                rule.validate()

    def test_payload_round_trip_survives_a_profile_rule(self) -> None:
        state = ufw.State(rules_loaded=True, rules=ufw.parse_status(self.SAMPLE))
        rebuilt = ufw.from_payload(ufw.to_payload(state))
        self.assertEqual([r.key() for r in rebuilt.rules],
                         [r.key() for r in state.rules])

    def test_no_command_is_built_for_a_profile_rule(self) -> None:
        """Neither added nor deleted — the ports behind the name are not ours."""
        current = ufw.State(rules_loaded=True, rules=ufw.parse_status(self.SAMPLE))
        wanted = current.copy()
        wanted.rules = [r for r in current.rules if not r.app]
        self.assertEqual(ufw.plan_commands(current, wanted), [])

    def test_other_changes_still_plan_alongside_a_profile_rule(self) -> None:
        current = ufw.State(rules_loaded=True, rules=ufw.parse_status(self.SAMPLE))
        wanted = current.copy()
        wanted.rules = list(current.rules) + [ufw.Rule("deny", "in", "23", "tcp")]
        commands = [" ".join(argv) for argv, _why in ufw.plan_commands(current, wanted)]
        self.assertTrue(any("23/tcp" in c for c in commands))
        self.assertFalse(any("CUPS" in c for c in commands))

    def test_to_argv_refuses_rather_than_guessing(self) -> None:
        with self.assertRaises(ufw.UfwError):
            ufw.Rule("allow", "in", app="CUPS").to_argv()

    def test_a_real_address_is_still_an_address(self) -> None:
        output = (
            "To                         Action      From\n"
            "--                         ------      ----\n"
            "192.168.1.5                ALLOW IN    Anywhere\n"
        )
        rule = ufw.parse_status(output)[0]
        self.assertEqual(rule.to_addr, "192.168.1.5")
        self.assertEqual(rule.app, "")
        self.assertTrue(rule.managed)


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


class TestUnits(unittest.TestCase):
    """Arbitrary systemd units — the half the flag catalogue cannot express."""

    def test_builds_a_mask_command(self) -> None:
        from ossgui import units
        self.assertEqual(
            units.to_argv("cups.service", "mask"),
            ["/usr/bin/systemctl", "mask", "--now", "cups.service"],
        )

    def test_refuses_to_mask_a_unit_the_system_needs(self) -> None:
        from ossgui import units
        for name in ("dbus.service", "systemd-logind.service", "sysinit.target"):
            with self.assertRaises(units.UnitError, msg=name):
                units.to_argv(name, "mask")

    def test_refuses_to_disable_a_unit_the_system_needs(self) -> None:
        """`disable --now` stops the unit too, so the guard cannot be mask-only.

        Refusing the mask but allowing the disable left the same outcome —
        logind or dbus stopped underneath a live session — one action away.
        """
        from ossgui import units
        for name in ("dbus.service", "systemd-logind.service", "systemd-journald.service"):
            with self.assertRaises(units.UnitError, msg=name):
                units.to_argv(name, "disable")

    def test_an_ordinary_unit_can_still_be_disabled(self) -> None:
        from ossgui import units
        argv = units.to_argv("cups.service", "disable")
        self.assertIn("--now", argv)
        self.assertIn("cups.service", argv)

    def test_rejects_shell_metacharacters_in_a_unit_name(self) -> None:
        from ossgui import units
        for name in ("foo; rm -rf /", "../../etc/passwd", "a b.service", "$(id).service"):
            with self.assertRaises(units.UnitError, msg=name):
                units.to_argv(name, "disable")

    def test_rejects_an_unknown_action(self) -> None:
        from ossgui import units
        with self.assertRaises(units.UnitError):
            units.to_argv("cups.service", "destroy")

    def test_rejects_a_name_without_a_known_suffix(self) -> None:
        from ossgui import units
        with self.assertRaises(units.UnitError):
            units.to_argv("cups", "disable")

    def test_payload_validates_every_entry(self) -> None:
        from ossgui import units
        good = units.from_payload({"cups.service": "disable"})
        self.assertEqual(good, {"cups.service": "disable"})
        with self.assertRaises(units.UnitError):
            units.from_payload({"dbus.service": "mask"})

    def test_loopback_sockets_are_not_public(self) -> None:
        from ossgui import units
        self.assertFalse(units.Socket("tcp", "127.0.0.1", 631).public)
        self.assertFalse(units.Socket("tcp", "::1", 631).public)
        self.assertTrue(units.Socket("tcp", "0.0.0.0", 631).public)


class TestSnap(unittest.TestCase):
    """Snap interface permissions — the plug reference reaches an argv."""

    def test_builds_a_disconnect(self) -> None:
        from ossgui import snapd
        self.assertEqual(
            snapd.to_argv("firefox:home", "disconnect"),
            ["/usr/bin/snap", "disconnect", "firefox:home"],
        )

    def test_rejects_a_bare_snap_name(self) -> None:
        """`snap disconnect firefox` would disconnect everything it has."""
        from ossgui import snapd
        with self.assertRaises(snapd.SnapError):
            snapd.to_argv("firefox", "disconnect")

    def test_rejects_injection_in_a_plug_reference(self) -> None:
        from ossgui import snapd
        for bad in ("firefox:home; rm -rf /", "$(id):home", "firefox:", ":home",
                    "FIREFOX:home", "firefox:home extra"):
            with self.assertRaises(snapd.SnapError, msg=bad):
                snapd.to_argv(bad, "disconnect")

    def test_rejects_unknown_action(self) -> None:
        from ossgui import snapd
        with self.assertRaises(snapd.SnapError):
            snapd.to_argv("firefox:home", "revoke")

    def test_parses_connections_output(self) -> None:
        from ossgui import snapd
        sample = (
            "Interface            Plug                    Slot              Notes\n"
            "camera               firefox:camera          :camera           -\n"
            "alsa                 firefox:alsa            -                 -\n"
            "dbus                 -                       firefox:dbus      -\n"
            "content[gpu-2404]    firefox:gpu-2404        mesa-2404:gpu     -\n"
        )
        rows = snapd.parse_connections(sample)
        self.assertEqual(len(rows), 4)

        camera = next(r for r in rows if r.interface == "camera")
        self.assertTrue(camera.connected)
        self.assertEqual(camera.snap, "firefox")

        alsa = next(r for r in rows if r.interface == "alsa")
        self.assertFalse(alsa.connected, "a '-' slot means not connected")

        provided = next(r for r in rows if r.interface == "dbus")
        self.assertEqual(provided.plug, "", "a '-' plug is absent, not a name")

        content = next(r for r in rows if r.interface.startswith("content"))
        self.assertEqual(content.base_interface, "content")

    def test_essential_and_sensitive_are_flagged(self) -> None:
        from ossgui import snapd
        essential = snapd.Connection("browser-support", "firefox:browser-sandbox", ":x")
        self.assertTrue(essential.essential)
        sensitive = snapd.Connection("camera", "firefox:camera", ":camera")
        self.assertTrue(sensitive.sensitive)
        self.assertFalse(sensitive.essential)
        plain = snapd.Connection("audio-playback", "firefox:audio-playback", ":x")
        self.assertEqual(plain.describe, "")

    def test_payload_validates_every_entry(self) -> None:
        from ossgui import snapd
        self.assertEqual(
            snapd.from_payload({"firefox:camera": "disconnect"}),
            {"firefox:camera": "disconnect"},
        )
        with self.assertRaises(snapd.SnapError):
            snapd.from_payload({"firefox": "disconnect"})


class TestPackages(unittest.TestCase):
    """Package removal — the cascade is the safety mechanism."""

    def test_rejects_injection_in_a_package_name(self) -> None:
        from ossgui import packages
        for bad in ("foo; rm -rf /", "$(id)", "Foo", "../etc/passwd", "foo bar"):
            with self.assertRaises(packages.PackageError, msg=bad):
                packages.validate(bad)

    def test_accepts_real_package_names(self) -> None:
        from ossgui import packages
        for good in ("libgtk-3-0t64", "python3.14", "g++", "libc6:amd64", "gcc-14"):
            packages.validate(good)

    def test_essential_and_required_are_not_removable(self) -> None:
        from ossgui import packages
        essential = packages.Package("dpkg", "1.0", essential=True)
        self.assertFalse(essential.removable)
        self.assertIn("Essential", essential.refusal)

        required = packages.Package("libc6", "1.0", priority="required")
        self.assertFalse(required.removable)
        self.assertIn("required", required.refusal)

        ordinary = packages.Package("cowsay", "1.0")
        self.assertTrue(ordinary.removable)
        self.assertEqual(ordinary.refusal, "")

    def test_removal_command_is_non_interactive_and_unforced(self) -> None:
        from ossgui import packages
        argv = packages.to_argv(["cowsay"])
        self.assertIn("--yes", argv)
        self.assertNotIn("--force-yes", argv)
        self.assertNotIn("--allow-remove-essential", argv)
        self.assertEqual(argv[-1], "cowsay")

    def test_removal_command_does_not_disable_removing(self) -> None:
        """--no-remove aborts every removal, including the requested one.

        It reads like a cascade guard but means "abort if anything would be
        removed", so apt answered `E: Packages need to be removed but remove is
        disabled.` and the section could never remove anything. The actual
        cascade guard is from_payload's re-simulation as root.
        """
        from ossgui import packages
        self.assertNotIn("--no-remove", packages.to_argv(["cowsay"]))
        self.assertNotIn("--no-remove", packages.to_argv(["cowsay"], purge=True))
        argv, _why = packages.plan_commands(["cowsay"])[0]
        self.assertNotIn("--no-remove", argv)

    def test_refuses_an_empty_removal(self) -> None:
        from ossgui import packages
        with self.assertRaises(packages.PackageError):
            packages.to_argv([])

    def test_cascade_separates_what_you_asked_for(self) -> None:
        from ossgui import packages
        cascade = packages.Cascade(
            requested=["wallpapers"], removing=["wallpapers", "gdm3", "gnome-shell"]
        )
        self.assertEqual(cascade.collateral, ["gdm3", "gnome-shell"])

    def test_cascade_flags_protected_packages_caught_in_it(self) -> None:
        from ossgui import packages
        installed = {
            "cowsay": packages.Package("cowsay", "1.0"),
            "dpkg": packages.Package("dpkg", "1.0", essential=True),
        }
        cascade = packages.Cascade(requested=["cowsay"], removing=["cowsay", "dpkg"])
        self.assertEqual(cascade.blocked_by(installed), ["dpkg"])

    def test_apt_note_is_not_mistaken_for_an_error(self) -> None:
        """`NOTE: This is only a simulation!` contains "E:".

        A substring check for "E:" matched apt's own note, bailed out early, and
        returned an empty cascade — so a 64-package removal read as touching
        nothing. Errors are lines that *start* with E:.
        """
        from ossgui import packages
        sample = (
            "NOTE: This is only a simulation!\n"
            "Reading package lists...\n"
            "Remv cowsay [3.03]\n"
            "Remv fortune [1.0]\n"
        )
        # Exercise the parsing path directly, without invoking apt.
        found = [
            m.group("name")
            for m in (packages._REMV.match(l.strip()) for l in sample.splitlines())
            if m
        ]
        self.assertEqual(found, ["cowsay", "fortune"])
        self.assertFalse([l for l in sample.splitlines() if l.startswith("E:")])


class TestFileMode(unittest.TestCase):
    """Arbitrary path mode changes."""

    def test_refuses_paths_that_would_leave_no_way_back(self) -> None:
        from ossgui import filemode
        for path in ("/usr/bin/dpkg", "/bin/sh", "/usr/bin/pkexec", "/usr/bin/sudo",
                     "/usr/bin/chmod", "/usr/lib/systemd/systemd"):
            with self.assertRaises(filemode.ModeError, msg=path):
                filemode.check_allowed(path, 0o000)

    def test_refuses_system_directories(self) -> None:
        from ossgui import filemode
        for path in ("/", "/usr", "/etc", "/var"):
            with self.assertRaises(filemode.ModeError, msg=path):
                filemode.check_allowed(path, 0o700)

    def test_rejects_traversal_and_relative_paths(self) -> None:
        from ossgui import filemode
        for path in ("../etc/shadow", "/etc/../etc/shadow", "relative/path", ""):
            with self.assertRaises(filemode.ModeError, msg=path):
                filemode.validate_path(path)

    def test_rejects_an_out_of_range_mode(self) -> None:
        from ossgui import filemode
        for mode in (-1, 0o10000, 99999):
            with self.assertRaises(filemode.ModeError):
                filemode.validate_mode(mode)

    def test_allows_an_ordinary_binary(self) -> None:
        from ossgui import filemode
        filemode.check_allowed("/usr/bin/ssh", 0o644)

    def test_statoverride_applies_now_as_well_as_later(self) -> None:
        """--update is what makes it take effect immediately, not at next unpack."""
        from ossgui import filemode
        argv = filemode.statoverride_argv("/usr/bin/ssh", 0o644)
        self.assertIn("--update", argv)
        self.assertIn("--add", argv)
        self.assertEqual(argv[-2:], ["0644", "/usr/bin/ssh"])

    def test_owner_names_are_validated(self) -> None:
        from ossgui import filemode
        with self.assertRaises(filemode.ModeError):
            filemode.statoverride_argv("/usr/bin/ssh", 0o644, owner="root; id")


class TestOrphanOwnership(unittest.TestCase):
    """A file whose uid has no passwd entry must not break the whole apply.

    inspect() used to store the bare number as if it were a user name. The
    mode dialog staged it, and the payload validator then rejected it — which
    aborts the *entire* transaction, not just that one row, over a file the
    user only wanted to chmod.
    """

    def target(self, uid: int | None, gid: int | None = None):
        from ossgui import filemode
        return filemode.Target(
            path="/srv/thing", exists=True, mode=0o644,
            owner="" if uid is not None else "root",
            group="" if gid is not None else "root",
            orphan_uid=uid, orphan_gid=gid,
        )

    def test_an_orphan_uid_is_shown_as_a_number_not_a_name(self) -> None:
        target = self.target(1001, 1001)
        self.assertIn("1001", target.owner_label)
        self.assertIn("no such user", target.owner_label)
        self.assertIn("no such group", target.group_label)

    def test_ownership_is_preserved_rather_than_defaulted_to_root(self) -> None:
        # Chowning to root would silently change who owns the file while the
        # user was only adjusting its mode.
        target = self.target(1001, 2002)
        self.assertEqual(target.owner_spec, "#1001")
        self.assertEqual(target.group_spec, "#2002")

    def test_a_named_owner_is_unchanged(self) -> None:
        from ossgui import filemode
        target = filemode.Target(path="/srv/thing", owner="alice", group="alice")
        self.assertEqual(target.owner_spec, "alice")
        self.assertEqual(target.group_spec, "alice")

    def test_the_numeric_form_survives_validation_and_reaches_dpkg(self) -> None:
        from ossgui import filemode
        argv = filemode.statoverride_argv("/srv/thing", 0o644, owner="#1001", group="#1001")
        self.assertIn("#1001", argv)

    def test_a_payload_with_an_orphan_id_is_accepted(self) -> None:
        from ossgui import filemode
        changes = filemode.from_payload({
            "/srv/thing": {"mode": 0o644, "owner": "#1001", "group": "#1001"}
        })
        self.assertEqual(changes[0].owner, "#1001")

    def test_a_bare_number_is_still_refused(self) -> None:
        """Only the '#' form means "an id"; a bare number is a malformed name."""
        from ossgui import filemode
        with self.assertRaises(filemode.ModeError):
            filemode.validate_owner("1001")

    def test_injection_through_the_numeric_form_is_refused(self) -> None:
        from ossgui import filemode
        for bad in ("#1001; id", "#", "#abc", "#12345678901234567890"):
            with self.assertRaises(filemode.ModeError, msg=bad):
                filemode.validate_owner(bad)

    def test_directory_meanings_differ_from_files(self) -> None:
        """Execute on a directory is traversal, not 'run'. Getting this wrong is
        the most common permissions mistake there is."""
        from ossgui import filemode
        as_file = filemode.describe_mode(0o700, is_dir=False)
        as_dir = filemode.describe_mode(0o700, is_dir=True)
        self.assertIn("run it", as_file)
        self.assertIn("enter it", as_dir)
        self.assertNotEqual(as_file, as_dir)

    def test_no_access_is_described_as_such(self) -> None:
        from ossgui import filemode
        self.assertIn("no access at all", filemode.describe_mode(0o000))

    def test_readable_but_not_executable_is_flagged_as_copyable(self) -> None:
        """0644 on a binary does not stop anyone copying it and running the copy."""
        from ossgui import filemode
        target = filemode.Target(
            path="/usr/bin/ssh", exists=True, mode=0o755, owner="root", group="root"
        )
        notes = " ".join(filemode.consequences(0o644, target))
        self.assertIn("copy", notes)

    def test_packaged_paths_warn_about_upgrades(self) -> None:
        from ossgui import filemode
        target = filemode.Target(
            path="/usr/bin/ssh", exists=True, mode=0o755, package="openssh-client"
        )
        self.assertIn("upgraded", " ".join(filemode.consequences(0o644, target)))

    def test_payload_validates_every_entry(self) -> None:
        from ossgui import filemode
        changes = filemode.from_payload(
            {"/usr/bin/ssh": {"mode": 0o644, "durable": True}}
        )
        self.assertEqual(changes[0].mode, 0o644)
        self.assertTrue(changes[0].durable)
        with self.assertRaises(filemode.ModeError):
            filemode.from_payload({"/usr/bin/dpkg": {"mode": 0}})
