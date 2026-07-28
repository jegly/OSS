"""Rollback correctness for commands that are not reloads.

A reload is safe to re-run during rollback: it reads the files, which have just
been restored. A mutation is not — `systemctl mask --now` has no file behind it
and is not self-inverse, so replaying it during rollback applies it a second
time while the report claims the transaction was reverted.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ossgui import apply as apply_module  # noqa: E402
from ossgui import render  # noqa: E402
from ossgui.render import Command, Plan  # noqa: E402

SYSTEMCTL = "/usr/bin/systemctl"


class RollbackCase(unittest.TestCase):
    """Captures every command rollback issues, without running any of them."""

    def setUp(self) -> None:
        self.executed: list[tuple[str, ...]] = []
        self._real_run = apply_module.run
        apply_module.run = self._fake_run
        self.addCleanup(setattr, apply_module, "run", self._real_run)

    def _fake_run(self, argv, stdin=None):
        self.executed.append(tuple(argv))
        return 0, ""

    def rollback(self, commands, prior):
        plan = Plan()
        plan.commands = list(commands)
        apply_module._rollback([], plan, apply_module.Result(), prior)
        return self.executed


class TestMutationsAreNotReplayed(RollbackCase):
    def test_mask_is_not_re_run(self) -> None:
        # The bug: rollback iterated every command and re-ran it, so a failed
        # transaction masked and stopped the service a second time.
        executed = self.rollback(
            [Command((SYSTEMCTL, "mask", "--now", "cups-browsed.service"),
                     "mask", mutates=True)],
            {"cups-browsed.service": "enabled"},
        )
        self.assertNotIn(
            (SYSTEMCTL, "mask", "--now", "cups-browsed.service"), executed
        )

    def test_mask_is_inverted_to_unmask(self) -> None:
        executed = self.rollback(
            [Command((SYSTEMCTL, "mask", "--now", "cups-browsed.service"),
                     "mask", mutates=True)],
            {"cups-browsed.service": "enabled"},
        )
        self.assertEqual(executed, [(SYSTEMCTL, "unmask", "cups-browsed.service")])

    def test_disable_is_inverted_to_enable(self) -> None:
        executed = self.rollback(
            [Command((SYSTEMCTL, "disable", "--now", "colord.service"),
                     "disable", mutates=True)],
            {"colord.service": "enabled"},
        )
        self.assertEqual(executed, [(SYSTEMCTL, "enable", "colord.service")])

    def test_reloads_are_still_re_run(self) -> None:
        # These have to run: a restored or deleted drop-in changes nothing live
        # until the tool that reads it is told to look again.
        executed = self.rollback(
            [Command(("/usr/sbin/sysctl", "--system"), "reload sysctl")], {}
        )
        self.assertEqual(executed, [("/usr/sbin/sysctl", "--system")])


class TestInverseRespectsPriorState(RollbackCase):
    def test_already_masked_stays_masked(self) -> None:
        # Unmasking here would enable something the user masked themselves long
        # before this transaction — a worse outcome than the failure being
        # recovered from.
        executed = self.rollback(
            [Command((SYSTEMCTL, "mask", "--now", "telnet.socket"),
                     "mask", mutates=True)],
            {"telnet.socket": "masked"},
        )
        self.assertEqual(executed, [])

    def test_already_disabled_is_left_alone(self) -> None:
        executed = self.rollback(
            [Command((SYSTEMCTL, "disable", "--now", "colord.service"),
                     "disable", mutates=True)],
            {"colord.service": "disabled"},
        )
        self.assertEqual(executed, [])

    def test_unknown_unit_is_not_guessed_at(self) -> None:
        executed = self.rollback(
            [Command((SYSTEMCTL, "mask", "--now", "ghost.service"),
                     "mask", mutates=True)],
            {},
        )
        self.assertEqual(executed, [])


class TestUnitInverse(unittest.TestCase):
    def test_ignores_commands_that_are_not_systemctl(self) -> None:
        self.assertIsNone(
            apply_module.unit_inverse(("/usr/sbin/sysctl", "--system"), {})
        )

    def test_ignores_unknown_systemctl_actions(self) -> None:
        self.assertIsNone(
            apply_module.unit_inverse(
                (SYSTEMCTL, "restart", "sshd.service"), {"sshd.service": "enabled"}
            )
        )


class TestCatalogueMarksMutations(unittest.TestCase):
    def test_service_commands_are_marked(self) -> None:
        """The marking has to come from the renderer, not from a hand-written list.

        A services flag added later would otherwise default to being replayed
        on rollback, which is the original bug returning quietly.
        """
        from ossgui import catalogue as catalogue_module

        loaded = catalogue_module.load()
        services = loaded.section("services")
        selection = {flag.id: "mask" for flag in services.flags[:5]}
        plan = render.render_section(services, selection, {})

        self.assertTrue(plan.commands, "expected the services section to plan commands")
        for command in plan.commands:
            with self.subTest(command=str(command)):
                self.assertTrue(command.mutates)


class TestExtrasAreRolledBack(unittest.TestCase):
    """Files written by the extras have to reach the rollback list.

    fstab, usbguard, the bootloader password script and the systemd sandbox
    drop-ins all take a backup, but their paths used to live only inside their
    own function — so a failure in any later stage restored nothing and still
    reported rolled_back. fstab is the one that costs you the next boot.
    """

    ORIGINAL = "UUID=abc / ext4 defaults 0 1\nUUID=def /home ext4 defaults 0 2\n"

    def setUp(self) -> None:
        import os
        import tempfile

        from ossgui import catalogue as catalogue_module

        self.sandbox = tempfile.TemporaryDirectory()
        self.addCleanup(self.sandbox.cleanup)
        os.environ["OSS_ROOT"] = self.sandbox.name
        self.addCleanup(os.environ.pop, "OSS_ROOT", None)

        self.fstab = Path(self.sandbox.name) / "etc/fstab"
        self.fstab.parent.mkdir(parents=True, exist_ok=True)
        self.fstab.write_text(self.ORIGINAL)

        self.catalogue = catalogue_module.load()
        self._real_run = apply_module.run
        self.addCleanup(setattr, apply_module, "run", self._real_run)

    def test_fstab_is_restored_when_a_later_stage_fails(self) -> None:
        def run(argv, stdin=None):
            # The remount validation passes; the stage after fstab does not.
            if argv[0] == "/usr/bin/snap":
                return 1, "simulated failure after fstab was written"
            return 0, ""

        apply_module.run = run

        plan = Plan()
        plan.commands = [Command(("/usr/bin/snap", "x"), "boom")]
        result = apply_module.apply_plan(
            self.catalogue, plan, {}, extras={"fstab": {"/home": {"nodev", "nosuid"}}}
        )

        self.assertFalse(result.ok)
        self.assertTrue(result.rolled_back)
        self.assertEqual(self.fstab.read_text(), self.ORIGINAL)


class TestUnexpectedFailuresStillRollBack(unittest.TestCase):
    """An exception apply_plan did not anticipate must not escape it.

    apply_plan used to catch only ApplyError and OSError. Every sub-planner
    raises its own ValueError subclass, and apply_permissions resolved owner
    names with pwd.getpwnam, which raises KeyError — so a bad name escaped the
    transaction entirely. That was the worst available outcome: _rollback never
    ran, so files already written stayed written, and the helper died printing a
    traceback to stderr with no JSON on stdout, leaving the GUI unable to say
    what had happened.
    """

    def setUp(self) -> None:
        import os
        import tempfile

        from ossgui import catalogue as catalogue_module

        self.sandbox = tempfile.TemporaryDirectory()
        self.addCleanup(self.sandbox.cleanup)
        os.environ["OSS_ROOT"] = self.sandbox.name
        os.environ["OSS_QUIET"] = "1"
        self.addCleanup(os.environ.pop, "OSS_ROOT", None)
        self.addCleanup(os.environ.pop, "OSS_QUIET", None)
        self.catalogue = catalogue_module.load()

        self.dropin = Path(self.sandbox.name) / "etc/sysctl.d/99-oss.conf"
        self.target = Path(self.sandbox.name) / "var/log/auth.log"
        self.target.parent.mkdir(parents=True, exist_ok=True)
        self.target.write_text("boot\n")

    def _plan(self) -> Plan:
        plan = Plan()
        plan.writes.append(
            render.FileWrite(
                path="/etc/sysctl.d/99-oss.conf",
                content="# oss\nkernel.kptr_restrict = 2\n",
                mode=0o644,
                section="sysctl",
            )
        )
        return plan

    def test_an_unknown_owner_rolls_back_instead_of_escaping(self) -> None:
        from ossgui import permissions

        changes = [
            permissions.Change(path="/var/log/auth.log", mode=0o640,
                               owner="oss-no-such-user", group="")
        ]
        result = apply_module.apply_plan(
            self.catalogue, self._plan(), {}, extras={"permissions": changes}
        )

        self.assertFalse(result.ok)
        self.assertTrue(result.rolled_back)
        self.assertIn("oss-no-such-user", result.error)
        # The write that had already landed is gone again.
        self.assertFalse(self.dropin.exists())

    def test_any_unexpected_exception_is_reported_as_a_result(self) -> None:
        def boom(_changes, _result) -> None:
            raise RuntimeError("something nobody predicted")

        real = apply_module.apply_permissions
        apply_module.apply_permissions = boom
        self.addCleanup(setattr, apply_module, "apply_permissions", real)

        result = apply_module.apply_plan(
            self.catalogue, self._plan(), {}, extras={"permissions": []}
        )

        self.assertFalse(result.ok)
        self.assertTrue(result.rolled_back)
        self.assertIn("something nobody predicted", result.error)
        self.assertFalse(self.dropin.exists())


class TestOwnershipIsRefusedBeforeAnyWrite(unittest.TestCase):
    """Better than rolling back: never start.

    Half the recommended permission table names an owner or group that only
    some distributions ship. `syslog` comes with rsyslog, so a journald-only
    machine has no such account, and neither Fedora nor Arch has a `shadow`
    group — and this app ships packaging for both.
    """

    def test_payload_refuses_an_account_this_machine_lacks(self) -> None:
        from ossgui import permissions

        with self.assertRaises(permissions.PermissionError_) as caught:
            permissions.from_payload(
                {"/etc/shadow": {"mode": 0o640, "group": "oss-no-such-group"}}
            )
        self.assertIn("oss-no-such-group", str(caught.exception))

    def test_root_is_always_resolvable(self) -> None:
        from ossgui import permissions

        self.assertEqual(permissions.resolve_ownership("root", "root"), (0, 0))

    def test_an_omitted_name_means_leave_it_alone(self) -> None:
        from ossgui import permissions

        self.assertEqual(permissions.resolve_ownership("", ""), (-1, -1))

    def test_the_table_stops_proposing_an_account_that_is_missing(self) -> None:
        """The mode fix must survive a chown this machine cannot perform."""
        from ossgui import permissions

        row = permissions.Row("/etc/shadow", 0o640, group="oss-no-such-group")
        permissions.inspect([row])
        self.assertEqual(row.group, "")
        self.assertIn("oss-no-such-group", row.note)
        # Still a usable change: the mode is the point of the row.
        self.assertEqual(row.target_mode, 0o640)
        permissions.from_payload(
            {row.path: {"mode": row.target_mode, "owner": row.owner,
                        "group": row.group}}
        )


if __name__ == "__main__":
    unittest.main()
