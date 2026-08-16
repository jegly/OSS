"""Properties the catalogue must hold, checked against the running system.

These exist because the same bug kept appearing in different sections: a setting
that looks applied and does nothing. A read-only sysctl, an audit watch on a
path that is not there, a kernel parameter for another architecture. Each one
was found by hand; each one is an invariant now.
"""

from __future__ import annotations

import os
import re
import sys
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ossgui import catalogue as catalogue_module, probe  # noqa: E402

CATALOGUE = catalogue_module.load()

#: `-w /path -p wa -k key`
_WATCH = re.compile(r"-w\s+(\S+)")


def _available(flag) -> bool:
    """Whether this machine offers the flag at all."""
    return all(probe.has_capability(token) for token in flag.needs)


class TestAuditWatches(unittest.TestCase):
    """An auditctl rule file is loaded as a set.

    One `-w` on a path that does not exist fails *every* rule in the file, not
    just that line. So a watch on anything that can be absent has to be gated,
    or enabling it silently takes down the whole audit configuration.
    """

    def test_a_watch_on_a_missing_path_is_gated(self) -> None:
        offenders = []
        for flag in CATALOGUE.section("auditd").flags:
            for line in (flag.key, *flag.extra):
                match = _WATCH.search(line)
                if match and not os.path.exists(match.group(1)) and _available(flag):
                    offenders.append(f"{flag.id} watches {match.group(1)}")
        self.assertEqual(offenders, [], "ungated watch on a path this machine lacks")

    def test_a_path_gate_names_a_path_the_flag_watches(self) -> None:
        """A gate on the wrong path protects nothing and hides the flag."""
        for flag in CATALOGUE.section("auditd").flags:
            watched = {
                match.group(1).rstrip("/")
                for line in (flag.key, *flag.extra)
                if (match := _WATCH.search(line))
            }
            for token in flag.needs:
                if not token.startswith("path:"):
                    continue
                with self.subTest(flag=flag.id, gate=token):
                    self.assertIn(token[len("path:"):].rstrip("/"), watched)

    def test_the_immutable_rule_stays_last(self) -> None:
        """`-e 2` locks the rule set; anything after it is rejected."""
        flags = [f for f in CATALOGUE.section("auditd").flags if f.key.strip() == "-e 2"]
        self.assertEqual(len(flags), 1)
        self.assertTrue(flags[0].apply_last)


class TestSysctlKeys(unittest.TestCase):
    def test_every_key_exists_on_this_kernel(self) -> None:
        missing = [
            f"{flag.id} ({flag.key})"
            for flag in CATALOGUE.section("sysctl").flags
            if not os.path.exists("/proc/sys/" + flag.key.replace(".", "/"))
        ]
        self.assertEqual(missing, [], "sysctl key absent on this kernel")

    def test_no_key_is_read_only(self) -> None:
        """A 0444 entry under /proc/sys is a status file, not a setting.

        net.ipv4.conf.all.mc_forwarding was offered as settable and shipped in
        every preset; `sysctl -w` on it returns EPERM even as root, so it could
        only ever be written to the drop-in and then fail on every reload.
        """
        read_only = []
        for flag in CATALOGUE.section("sysctl").flags:
            path = "/proc/sys/" + flag.key.replace(".", "/")
            try:
                mode = os.stat(path).st_mode
            except OSError:
                continue
            if not mode & 0o200:
                read_only.append(f"{flag.id} ({flag.key})")
        self.assertEqual(read_only, [], "read-only sysctl offered as settable")


class TestGrubParameters(unittest.TestCase):
    def test_architecture_specific_parameters_are_gated(self) -> None:
        """An unknown parameter is not rejected — the kernel hands it to
        userspace and carries on, so it sits there looking applied.

        `ssbd=` is arm64-only and was offered on x86, where the running kernel
        listed it under "Unknown kernel command line parameters".
        """
        flag = CATALOGUE.get("ssbd_force")
        self.assertIn("arch:aarch64", flag.needs)
        if os.uname().machine != "aarch64":
            self.assertFalse(_available(flag))

    def test_cpu_mitigations_say_what_hardware_they_apply_to(self) -> None:
        """Read before applying a preset on a different machine."""
        for flag_id in probe.MITIGATION_FLAGS:
            flag = CATALOGUE.get(flag_id)
            if flag is None or flag.section != "grub":
                continue
            with self.subTest(flag=flag_id):
                self.assertTrue(flag.affects, f"{flag_id} needs an affects line")


class TestNoDuplicates(unittest.TestCase):
    def test_no_two_flags_write_the_same_key_to_the_same_file(self) -> None:
        for section in CATALOGUE.sections:
            if not section.flags:
                continue
            counts = Counter(
                (flag.target or section.target, flag.key) for flag in section.flags
            )
            dupes = [key for key, n in counts.items() if n > 1]
            with self.subTest(section=section.id):
                self.assertEqual(dupes, [])

    def test_flag_ids_are_unique_across_the_catalogue(self) -> None:
        ids = [flag.id for section in CATALOGUE.sections for flag in section.flags]
        dupes = [i for i, n in Counter(ids).items() if n > 1]
        self.assertEqual(dupes, [])


class TestPresets(unittest.TestCase):
    def test_every_preset_entry_names_a_real_flag(self) -> None:
        import tomllib

        for path in sorted(Path("data/presets").glob("*.toml")):
            with open(path, "rb") as handle:
                raw = tomllib.load(handle)
            unknown = [
                entry["id"]
                for entry in raw.get("set", ())
                if entry.get("id") not in CATALOGUE.flags
            ]
            with self.subTest(preset=path.name):
                self.assertEqual(unknown, [], "preset references a removed flag")


class TestSections(unittest.TestCase):
    def test_every_section_is_reachable(self) -> None:
        """A section with no flags needs its own page, or it is a dead entry."""
        dedicated = {
            "ufw", "packages", "snap", "apparmor", "accounts", "integrity",
            "services", "systemd", "bootloader", "permissions", "fstab", "usb",
            "tpm", "debloat",
        }
        orphans = [
            s.id for s in CATALOGUE.sections if not s.flags and s.id not in dedicated
        ]
        self.assertEqual(orphans, [], "section has neither flags nor a page")


if __name__ == "__main__":
    unittest.main()
