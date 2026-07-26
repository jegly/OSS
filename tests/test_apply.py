"""Transaction tests — writes, backups and rollback, against a sandbox root.

Run with:  HARDENING_GUI_ROOT=<tmpdir> python3 -m unittest discover tests
The sandbox root is honoured only when not running as root (see apply.target_path),
so these tests can never touch the real system files.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from hardeninggui import apply, catalogue, probe, render  # noqa: E402


class SandboxCase(unittest.TestCase):
    def setUp(self) -> None:
        self.sandbox = tempfile.TemporaryDirectory()
        os.environ["HARDENING_GUI_ROOT"] = self.sandbox.name
        self.addCleanup(self.sandbox.cleanup)
        self.addCleanup(os.environ.pop, "HARDENING_GUI_ROOT", None)
        self.catalogue = catalogue.load()

    def sandboxed(self, path: str) -> Path:
        return Path(self.sandbox.name) / path.lstrip("/")


class TestWriteAndBackup(SandboxCase):
    def test_write_creates_file_with_mode(self) -> None:
        target = self.sandboxed("/etc/sysctl.d/99-hardening-gui.conf")
        apply.write_atomic(target, "kernel.kptr_restrict = 2\n", 0o644)
        self.assertEqual(target.read_text(), "kernel.kptr_restrict = 2\n")
        self.assertEqual(target.stat().st_mode & 0o777, 0o644)

    def test_sudoers_write_is_0440(self) -> None:
        target = self.sandboxed("/etc/sudoers.d/99-hardening-gui")
        apply.write_atomic(target, "Defaults use_pty\n", 0o440)
        self.assertEqual(target.stat().st_mode & 0o777, 0o440)

    def test_backup_then_restore_round_trips(self) -> None:
        target = self.sandboxed("/etc/login.defs")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("UMASK\t022\n")

        apply.backup(target)
        apply.write_atomic(target, "UMASK\t077\n", 0o644)
        self.assertEqual(target.read_text(), "UMASK\t077\n")

        apply.restore(target)
        self.assertEqual(target.read_text(), "UMASK\t022\n")

    def test_restore_removes_a_file_that_did_not_exist_before(self) -> None:
        target = self.sandboxed("/etc/sysctl.d/99-hardening-gui.conf")
        apply.write_atomic(target, "x = 1\n", 0o644)
        apply.restore(target)
        self.assertFalse(target.exists())

    def test_refuses_to_write_through_a_symlink(self) -> None:
        target = self.sandboxed("/etc/sysctl.d/99-hardening-gui.conf")
        target.parent.mkdir(parents=True, exist_ok=True)
        elsewhere = self.sandboxed("/etc/passwd")
        elsewhere.parent.mkdir(parents=True, exist_ok=True)
        elsewhere.write_text("root:x:0:0::/root:/bin/bash\n")
        target.symlink_to(elsewhere)

        with self.assertRaises(apply.ApplyError):
            apply.write_atomic(target, "pwned\n", 0o644)
        self.assertEqual(elsewhere.read_text(), "root:x:0:0::/root:/bin/bash\n")


class TestPayloadValidation(SandboxCase):
    def test_rejects_unknown_flag(self) -> None:
        with self.assertRaises(apply.ApplyError):
            apply.validate_payload(self.catalogue, {"version": 1, "selection": {"x": "1"}})

    def test_rejects_value_outside_the_allowlist(self) -> None:
        with self.assertRaises(apply.ApplyError):
            apply.validate_payload(
                self.catalogue, {"version": 1, "selection": {"kptr_restrict": "9"}}
            )

    def test_rejects_shell_metacharacters_in_an_editable_value(self) -> None:
        with self.assertRaises(apply.ApplyError):
            apply.validate_payload(
                self.catalogue,
                {"version": 1, "selection": {"ssh_allow_users": "root; rm -rf /"}},
            )

    def test_rejects_a_section_this_build_cannot_apply(self) -> None:
        """A section marked unimplemented must not be applicable.

        Every shipped section is implemented now, so this marks one as not-built
        to check the guard itself rather than asserting on which sections happen
        to be finished.
        """
        section = self.catalogue.section("sysctl")
        section.implemented = False
        self.addCleanup(setattr, section, "implemented", True)

        with self.assertRaises(apply.ApplyError):
            apply.validate_payload(
                self.catalogue, {"version": 1, "selection": {"kptr_restrict": "2"}}
            )

    def test_accepts_a_well_formed_selection(self) -> None:
        selection = apply.validate_payload(
            self.catalogue,
            {"version": 1, "selection": {"kptr_restrict": "2", "ssh_port": "2222"}},
        )
        self.assertEqual(selection, {"kptr_restrict": "2", "ssh_port": "2222"})


class TestRollback(SandboxCase):
    def test_a_failing_command_restores_every_file(self) -> None:
        target = self.sandboxed("/etc/sysctl.d/99-hardening-gui.conf")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("# original\n")

        plan = render.Plan(
            writes=[
                render.FileWrite(
                    path="/etc/sysctl.d/99-hardening-gui.conf",
                    content="kernel.kptr_restrict = 2\n",
                    section="sysctl",
                )
            ],
            # `sysctl` is on the allowlist, and -p on a missing file exits 1.
            # (An unrecognised *option* exits 0, so it would not exercise this.)
            commands=[render.Command(("/usr/sbin/sysctl", "-p", "/nonexistent/nope.conf"))],
        )
        result = apply.apply_plan(self.catalogue, plan, {"kptr_restrict": "2"})

        self.assertFalse(result.ok)
        self.assertTrue(result.rolled_back)
        self.assertEqual(target.read_text(), "# original\n")

    def test_a_command_outside_the_allowlist_is_refused(self) -> None:
        plan = render.Plan(commands=[render.Command(("/bin/sh", "-c", "echo pwned"))])
        result = apply.apply_plan(self.catalogue, plan, {})
        self.assertFalse(result.ok)
        self.assertIn("not allowed", result.error)


class TestRenderIdempotence(SandboxCase):
    def test_reapplying_an_unchanged_selection_is_a_no_op(self) -> None:
        selection = {"kptr_restrict": "2", "dmesg_restrict": "1"}
        first = render.render(self.catalogue, selection, current={})
        writes = {w.path: w.content for w in first.writes}
        self.assertIn("/etc/sysctl.d/99-hardening-gui.conf", writes)

        second = render.render(self.catalogue, selection, current=writes)
        self.assertEqual(second.writes, [])
        self.assertEqual(second.commands, [], "an unchanged section must not reload")

    def test_deselecting_everything_removes_the_dropin(self) -> None:
        target = "/etc/sysctl.d/99-hardening-gui.conf"
        plan = render.render(self.catalogue, {}, current={target: "kernel.x = 1\n"})
        self.assertIn(target, [r.path for r in plan.removes])

    def test_never_removes_a_dropin_that_was_never_written(self) -> None:
        plan = render.render(self.catalogue, {}, current={})
        self.assertEqual(plan.removes, [])
        self.assertEqual(plan.commands, [])

    def test_modules_disabled_is_the_last_line(self) -> None:
        plan = render.render(
            self.catalogue,
            {"modules_disabled": "1", "kptr_restrict": "2", "dmesg_restrict": "1"},
            current={},
        )
        body = next(w.content for w in plan.writes if "sysctl.d" in w.path)
        self.assertTrue(body.rstrip().endswith("kernel.modules_disabled = 1"))

    def test_audit_immutable_rule_is_the_last_line(self) -> None:
        # Rendered directly: the auditd section is skipped by render() on a host
        # without auditd installed, and the ordering is what is under test here.
        section = self.catalogue.section("auditd")
        plan = render.render_section(
            section, {"audit_immutable": "1", "audit_modules": "1"}, current={}
        )
        body = next(w.content for w in plan.writes if "audit" in w.path)
        self.assertTrue(body.rstrip().endswith("-e 2"))


class TestOptionalPackages(SandboxCase):
    def test_section_is_skipped_when_its_package_is_missing(self) -> None:
        """Writing a config whose tool is absent would fail the reload and roll back."""
        section = self.catalogue.section("auditd")
        self.assertEqual(section.requires_pkg, "auditd")

        plan = render.render(self.catalogue, {"audit_modules": "1"}, current={})
        wrote_audit = any("audit" in w.path for w in plan.writes)
        self.assertEqual(wrote_audit, probe.package_present("auditd"))

    def test_package_present_finds_something_that_definitely_exists(self) -> None:
        self.assertTrue(probe.package_present("systemctl"))
        self.assertFalse(probe.package_present("definitely-not-installed-xyz"))

    def test_modprobe_uses_bin_false_not_bin_true(self) -> None:
        plan = render.render(self.catalogue, {"mod_cramfs": "1"}, current={})
        body = next(w.content for w in plan.writes if "modprobe" in w.path)
        self.assertIn("install cramfs /bin/false", body)
        self.assertNotIn("/bin/true", body)


if __name__ == "__main__":
    unittest.main()
