"""Transaction tests — writes, backups and rollback, against a sandbox root.

Run with:  OSS_ROOT=<tmpdir> python3 -m unittest discover tests
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

from ossgui import apply, catalogue, probe, render  # noqa: E402


class SandboxCase(unittest.TestCase):
    def setUp(self) -> None:
        self.sandbox = tempfile.TemporaryDirectory()
        os.environ["OSS_ROOT"] = self.sandbox.name
        self.addCleanup(self.sandbox.cleanup)
        self.addCleanup(os.environ.pop, "OSS_ROOT", None)
        self.catalogue = catalogue.load()

    def sandboxed(self, path: str) -> Path:
        return Path(self.sandbox.name) / path.lstrip("/")


class TestWriteAndBackup(SandboxCase):
    def test_write_creates_file_with_mode(self) -> None:
        target = self.sandboxed("/etc/sysctl.d/99-oss.conf")
        apply.write_atomic(target, "kernel.kptr_restrict = 2\n", 0o644)
        self.assertEqual(target.read_text(), "kernel.kptr_restrict = 2\n")
        self.assertEqual(target.stat().st_mode & 0o777, 0o644)

    def test_sudoers_write_is_0440(self) -> None:
        target = self.sandboxed("/etc/sudoers.d/99-oss")
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
        target = self.sandboxed("/etc/sysctl.d/99-oss.conf")
        apply.write_atomic(target, "x = 1\n", 0o644)
        apply.restore(target)
        self.assertFalse(target.exists())

    def test_refuses_to_write_through_a_symlink(self) -> None:
        target = self.sandboxed("/etc/sysctl.d/99-oss.conf")
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
        target = self.sandboxed("/etc/sysctl.d/99-oss.conf")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("# original\n")

        plan = render.Plan(
            writes=[
                render.FileWrite(
                    path="/etc/sysctl.d/99-oss.conf",
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


#: What `sysctl --system` prints on a hand-hardened machine where a
#: pre-existing file names an interface that is currently down. Exit code 1.
FOREIGN_FAILURE = """\
* Applying /usr/lib/sysctl.d/50-default.conf ...
kernel.core_pattern = core
* Applying /etc/sysctl.d/55-network-security.conf ...
sysctl: cannot stat /proc/sys/net/ipv4/conf/wg-entry/rp_filter: No such file or directory
sysctl: permission denied on key 'net.ipv4.conf.wg-exit.accept_ra_pinfo'
* Applying /etc/sysctl.d/99-oss.conf ...
net.ipv6.conf.all.disable_ipv6 = 1
* Applying /etc/sysctl.conf ...
"""


class TestSysctlReloadTolerance(SandboxCase):
    """`sysctl --system` re-applies files this app never wrote; a failure in
    one of *those* must not fail the transaction (bug: one toggle on a
    hand-hardened machine threw "Apply failed" over the machine's own config).
    """

    def plan(self, key: str = "kernel.kptr_restrict") -> render.Plan:
        return render.Plan(
            writes=[
                render.FileWrite(
                    path="/etc/sysctl.d/99-oss.conf",
                    content=f"{key} = 2\n",
                    section="sysctl",
                )
            ],
            commands=[render.Command(("/usr/sbin/sysctl", "--system"))],
        )

    def test_error_lines_are_separated_from_the_applied_echo(self) -> None:
        lines = apply._sysctl_error_lines(FOREIGN_FAILURE)
        self.assertEqual(len(lines), 2)
        self.assertTrue(all(line.startswith("sysctl:") for line in lines))

    def test_the_failing_key_is_read_from_either_error_shape(self) -> None:
        self.assertEqual(
            apply._sysctl_error_key(
                "sysctl: cannot stat /proc/sys/net/ipv4/conf/wg-entry/rp_filter: No such file"
            ),
            "net.ipv4.conf.wg-entry.rp_filter",
        )
        self.assertEqual(
            apply._sysctl_error_key(
                "sysctl: permission denied on key 'net.ipv4.conf.wg-exit.accept_ra_pinfo'"
            ),
            "net.ipv4.conf.wg-exit.accept_ra_pinfo",
        )
        self.assertIsNone(apply._sysctl_error_key("simulated reload failure"))

    def test_foreign_key_failures_do_not_fail_the_transaction(self) -> None:
        ours, detail = apply._sysctl_reload_verdict(self.plan(), FOREIGN_FAILURE)
        self.assertFalse(ours)
        self.assertIn("did not write", detail)

    def test_a_failure_naming_our_key_still_fails(self) -> None:
        output = FOREIGN_FAILURE + "sysctl: permission denied on key 'kernel.kptr_restrict'\n"
        ours, detail = apply._sysctl_reload_verdict(self.plan(), output)
        self.assertTrue(ours)
        # The detail is the error lines, not the hundreds of applied-key echoes.
        self.assertNotIn("* Applying", detail)
        self.assertIn("kernel.kptr_restrict", detail)

    def test_an_unattributable_failure_still_fails(self) -> None:
        ours, _detail = apply._sysctl_reload_verdict(self.plan(), "simulated reload failure")
        self.assertTrue(ours)
        ours, _detail = apply._sysctl_reload_verdict(self.plan(), "")
        self.assertTrue(ours)

    def test_the_transaction_survives_a_foreign_sysctl_failure(self) -> None:
        target = self.sandboxed("/etc/sysctl.d/99-oss.conf")
        target.parent.mkdir(parents=True, exist_ok=True)

        real_run = apply.run

        def fake_run(argv, stdin=None):
            if "--system" in argv:
                return 1, FOREIGN_FAILURE
            return real_run(argv, stdin)

        apply.run = fake_run
        self.addCleanup(setattr, apply, "run", real_run)

        result = apply.apply_plan(self.catalogue, self.plan(), {"kptr_restrict": "2"})
        self.assertTrue(result.ok, result.error)
        self.assertFalse(result.rolled_back)
        self.assertEqual(target.read_text(), "kernel.kptr_restrict = 2\n")
        # The tolerated failure is still on the record for the results screen.
        command_steps = [s for s in result.steps if s.kind == "command"]
        self.assertTrue(any("did not write" in s.output for s in command_steps))


class TestRenderIdempotence(SandboxCase):
    def test_reapplying_an_unchanged_selection_is_a_no_op(self) -> None:
        selection = {"kptr_restrict": "2", "dmesg_restrict": "1"}
        first = render.render(self.catalogue, selection, current={})
        writes = {w.path: w.content for w in first.writes}
        self.assertIn("/etc/sysctl.d/99-oss.conf", writes)

        second = render.render(self.catalogue, selection, current=writes)
        self.assertEqual(second.writes, [])
        self.assertEqual(second.commands, [], "an unchanged section must not reload")

    def test_deselecting_everything_removes_the_dropin(self) -> None:
        target = "/etc/sysctl.d/99-oss.conf"
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


class TestIncludeMechanisms(SandboxCase):
    """A drop-in directory nothing includes is a file that is silently ignored.

    That is the exact failure this app exists to catch, so it must not be a
    failure the app itself can commit.
    """

    def test_unreadable_source_is_not_reported_as_broken(self) -> None:
        """/etc/sudoers is mode 0440, so an unprivileged check cannot tell."""
        status, detail = probe.include_check("/etc/sudoers.d")
        self.assertIn(status, ("ok", "unreadable"))
        if status == "unreadable":
            self.assertIn("root", detail)

    def test_a_directory_with_no_mechanism_is_fine(self) -> None:
        self.assertEqual(probe.include_check("/etc/sysctl.d"), ("ok", ""))

    def test_missing_include_is_detected(self) -> None:
        source, _markers, _remedy = probe.INCLUDE_MECHANISMS["/etc/sudoers.d"]
        original = probe.INCLUDE_MECHANISMS["/etc/sudoers.d"]

        # Point the check at a file we control that lacks the include line.
        decoy = self.sandboxed("/etc/sudoers-without-includedir")
        decoy.parent.mkdir(parents=True, exist_ok=True)
        decoy.write_text("Defaults env_reset\n")
        probe.INCLUDE_MECHANISMS["/etc/sudoers.d"] = (
            str(decoy), ("@includedir /etc/sudoers.d",), "@includedir /etc/sudoers.d",
        )
        self.addCleanup(
            probe.INCLUDE_MECHANISMS.__setitem__, "/etc/sudoers.d", original
        )

        status, detail = probe.include_check("/etc/sudoers.d")
        self.assertEqual(status, "missing")
        self.assertIn("would be ignored", f"a file written there {detail}")

    def test_apply_refuses_to_write_into_an_unincluded_dropin(self) -> None:
        original = probe.INCLUDE_MECHANISMS.get("/etc/sysctl.d")
        decoy = self.sandboxed("/etc/decoy-source")
        decoy.parent.mkdir(parents=True, exist_ok=True)
        decoy.write_text("nothing useful here\n")
        probe.INCLUDE_MECHANISMS["/etc/sysctl.d"] = (
            str(decoy), ("some-marker-that-is-absent",), "add the include line",
        )
        self.addCleanup(probe.INCLUDE_MECHANISMS.pop, "/etc/sysctl.d", None)
        if original is not None:
            self.addCleanup(
                probe.INCLUDE_MECHANISMS.__setitem__, "/etc/sysctl.d", original
            )

        plan = render.Plan(
            writes=[
                render.FileWrite(
                    path="/etc/sysctl.d/99-oss.conf",
                    content="kernel.kptr_restrict = 2\n",
                    section="sysctl",
                )
            ]
        )
        result = apply.apply_plan(self.catalogue, plan, {"kptr_restrict": "2"})
        self.assertFalse(result.ok)
        self.assertIn("would be ignored", result.error)
        self.assertFalse(self.sandboxed("/etc/sysctl.d/99-oss.conf").exists())


class TestDirectoryMode(SandboxCase):
    def test_created_directories_are_not_world_writable(self) -> None:
        """The mode is set explicitly rather than left to an inherited umask."""
        old_umask = os.umask(0)
        self.addCleanup(os.umask, old_umask)

        target = self.sandboxed("/etc/security/pwquality.conf.d/99-oss.conf")
        apply.write_atomic(target, "minlen = 14\n", 0o644)
        mode = target.parent.stat().st_mode & 0o777
        self.assertEqual(mode, 0o755, f"directory created {mode:04o}")


class TestStagingIsMinimal(SandboxCase):
    """One toggle must propose one change, not adopt the whole machine.

    Seeding the staged selection from everything currently in effect looked
    helpful and was a trap: on a hand-hardened machine that is hundreds of
    settings living in the user's own files, so the first toggle of anything
    dragged them all into our drop-in and wrote several files nobody asked to
    touch.
    """

    def _staging(self, files: dict | None = None):
        """Staging built from *supplied* facts, never from the host.

        These used to call probe.gather() and probe.read_target_files(), which
        read the real /etc — OSS_ROOT only relocates writes, not reads. So on any
        machine that already had an /etc/sysctl.d/99-oss.conf the app adopted its
        values and both tests failed, for a reason that had nothing to do with
        the code under test. The invariant is about a pristine machine, so the
        test supplies one.
        """
        from ossgui.staging import Staging

        facts = probe.SystemFacts(
            files=files or {}, cmdline=[], modules=set(), units={},
            gsettings={}, vulnerabilities={},
        )
        return Staging.from_system(self.catalogue, facts), facts

    def test_nothing_staged_means_an_empty_plan(self) -> None:
        staging, _facts = self._staging()
        self.assertEqual(staging.changed_count, 0)
        plan = render.render(self.catalogue, staging.selection, current={})
        self.assertTrue(plan.is_empty, "a freshly opened app must propose nothing")

    def test_one_toggle_touches_one_file(self) -> None:
        staging, _facts = self._staging()
        staging.set("printk_quiet", "3 3 3 3")
        self.assertEqual(staging.changed_ids(), ["printk_quiet"])

        plan = render.render(self.catalogue, staging.selection, current={})
        self.assertEqual([w.path for w in plan.writes], ["/etc/sysctl.d/99-oss.conf"])
        body = [l for l in plan.writes[0].content.splitlines() if l and not l.startswith("#")]
        self.assertEqual(body, ["kernel.printk = 3 3 3 3"])


class TestInPlaceFilesAreNotOurs(SandboxCase):
    """A system file is not a drop-in, and must not be treated as one."""

    def test_never_proposes_deleting_a_system_file(self) -> None:
        """faillock.conf ships with pam. With nothing selected, leave it alone."""
        plan = render.render(
            self.catalogue,
            {},
            current={"/etc/security/faillock.conf": "# stock pam file\ndeny = 3\n"},
        )
        removed = [r.path for r in plan.removes]
        self.assertNotIn("/etc/security/faillock.conf", removed)

    def test_still_removes_a_dropin_we_own(self) -> None:
        plan = render.render(
            self.catalogue, {}, current={"/etc/sysctl.d/99-oss.conf": "kernel.x = 1\n"}
        )
        self.assertIn("/etc/sysctl.d/99-oss.conf", [r.path for r in plan.removes])

    def test_logindefs_flags_are_in_place_by_syntax(self) -> None:
        """Derived from the syntax, so the data cannot forget to say so."""
        section = self.catalogue.section("pam")
        logindefs = [f for f in section.flags if section.syntax_for(f) == "logindefs"]
        self.assertTrue(logindefs)
        for flag in logindefs:
            self.assertTrue(flag.in_place, f"{flag.id} should be in-place")

    def test_a_system_files_own_values_are_not_adopted(self) -> None:
        """Reading a value out of login.defs says nothing about who set it."""
        section = self.catalogue.section("pam")
        flag = next(f for f in section.flags if f.key == "PASS_MAX_DAYS")
        facts = probe.SystemFacts(
            files={"/etc/login.defs": "PASS_MAX_DAYS\t99999\n"},
            cmdline=[], modules={}, units={}, gsettings={}, vulnerabilities={},
        )
        self.assertIsNone(probe.on_disk_value(section, flag, facts))

    def test_our_own_in_place_edit_is_recognised(self) -> None:
        """Once we have written it, the banner is how we know it is ours."""
        from ossgui import branding

        section = self.catalogue.section("pam")
        flag = next(f for f in section.flags if f.key == "PASS_MAX_DAYS")
        facts = probe.SystemFacts(
            files={"/etc/login.defs": branding.IN_PLACE + "PASS_MAX_DAYS\t365\n"},
            cmdline=[], modules={}, units={}, gsettings={}, vulnerabilities={},
        )
        self.assertEqual(probe.on_disk_value(section, flag, facts), "365")

    def test_matching_logindefs_value_is_not_rewritten(self) -> None:
        """A whitespace-only diff would claim the file is changing when it is not.

        The managed line must survive byte for byte: rewriting `UMASK 077` as
        `UMASK\t077` is a diff that changes nothing and makes review claim the
        file is being modified when it is not.

        The banner is a different matter and is expected to be added. It is what
        probe.is_ours() reads, and without it on_disk_value() refuses to read an
        in-place file back — so a flag staged against a value the distribution
        already happened to set was written and then still reported as "not set
        by us", forever. Adopting the file is the real change here; the line
        staying identical is what this test is guarding.
        """
        from ossgui import branding

        current = {"/etc/login.defs": "UMASK 077\n"}
        section = self.catalogue.section("pam")
        flag = next(f for f in section.flags if f.key == "UMASK")
        plan = render.render_section(section, {flag.id: "077"}, current=current)

        self.assertEqual(len(plan.writes), 1)
        body = plan.writes[0].content[len(branding.IN_PLACE):]
        self.assertEqual(body, "UMASK 077\n", "the managed line must not be rewritten")

    def test_the_marker_is_actually_in_the_banner(self) -> None:
        """The recogniser and the banner must not drift apart.

        They did once: changing the banner to ASCII art removed the phrase the
        recogniser was looking for, so it silently matched nothing and the app
        could not identify its own in-place edits.
        """
        from ossgui import branding

        for banner in (branding.DROPIN, branding.IN_PLACE):
            self.assertTrue(
                probe.is_ours(banner),
                "a file carrying this banner must be recognised as ours",
            )
        self.assertFalse(probe.is_ours("# just some other config file\n"))
