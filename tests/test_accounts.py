"""Account name validation, planning order, and per-item preview.

Nothing here touches a real account: every test drives the pure planning
functions with an injected view of passwd/group, so the only thing exercised
is the decision about what *would* be run.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ossgui import accounts  # noqa: E402


def user(name: str, uid: int, gid: int | None = None, groups: tuple = ()) -> accounts.User:
    return accounts.User(name=name, uid=uid, gid=uid if gid is None else gid, groups=groups)


def group(name: str, gid: int, members: tuple = ()) -> accounts.Group:
    return accounts.Group(name=name, gid=gid, members=members)


class TestValidateName(unittest.TestCase):
    def test_accepts_names_distro_packages_actually_create(self) -> None:
        # Debian's exim4 and snmpd packages create these with
        # `adduser --force-badname`; useradd's own NAME_REGEX rejects them.
        # Refusing them would exclude exactly the orphaned system accounts
        # this module exists to remove.
        for name in ("Debian-exim", "Debian-snmp", "systemd-network", "_apt", "sshd$"):
            with self.subTest(name=name):
                accounts.validate_name(name)

    def test_refuses_leading_dash(self) -> None:
        # userdel would read this as an option bundle rather than a name.
        with self.assertRaises(accounts.AccountError):
            accounts.validate_name("-rf")

    def test_refuses_field_and_line_separators(self) -> None:
        for name in ("ro:ot", "root\nx", "a/b", "a b", "a\tb"):
            with self.subTest(name=name):
                with self.assertRaises(accounts.AccountError):
                    accounts.validate_name(name)

    def test_refuses_empty_and_overlong(self) -> None:
        with self.assertRaises(accounts.AccountError):
            accounts.validate_name("")
        with self.assertRaises(accounts.AccountError):
            accounts.validate_name("a" * 33)


class TestDeletionGuards(unittest.TestCase):
    def test_refuses_uid_zero(self) -> None:
        users = {"root": user("root", 0)}
        with self.assertRaises(accounts.AccountError):
            accounts.guard_user_deletion("root", users)

    def test_refuses_gid_zero(self) -> None:
        groups = {"root": group("root", 0)}
        with self.assertRaises(accounts.AccountError):
            accounts.guard_group_deletion("root", groups, [])

    def test_refuses_unknown_account(self) -> None:
        with self.assertRaises(accounts.AccountError):
            accounts.guard_user_deletion("ghost", {})

    def test_refuses_group_that_is_still_a_primary_group(self) -> None:
        groups = {"staff": group("staff", 50)}
        users = [user("alice", 1000, gid=50)]
        with self.assertRaises(accounts.AccountError) as caught:
            accounts.guard_group_deletion("staff", groups, users)
        self.assertIn("alice", str(caught.exception))

    def test_allows_primary_group_when_its_holder_goes_too(self) -> None:
        # groupdel would fail on its own, but the user is deleted first in the
        # same batch, so by the time it runs the group is unreferenced.
        groups = {"staff": group("staff", 50)}
        users = [user("alice", 1000, gid=50)]
        accounts.guard_group_deletion("staff", groups, users, frozenset({"alice"}))


class TestRemoveMember(unittest.TestCase):
    def test_refuses_when_membership_already_gone(self) -> None:
        # gpasswd -d exits non-zero here, and every command shares one
        # transaction — so left unchecked this rolls back the whole apply
        # instead of being the no-op the user would expect.
        users = {"alice": user("alice", 1000)}
        groups = {"sudo": group("sudo", 27, members=())}
        with self.assertRaises(accounts.AccountError):
            accounts.plan_remove_member("alice", "sudo", users, groups)

    def test_plans_when_membership_is_current(self) -> None:
        users = {"alice": user("alice", 1000)}
        groups = {"sudo": group("sudo", 27, members=("alice",))}
        argv, why = accounts.plan_remove_member("alice", "sudo", users, groups)
        self.assertEqual(argv, [accounts.GPASSWD, "-d", "alice", "sudo"])
        self.assertIn("sudo", why)


class TestPreview(unittest.TestCase):
    def test_one_bad_entry_does_not_hide_the_others(self) -> None:
        # from_payload() is all-or-nothing because the helper must refuse a
        # batch it cannot fully validate; the review dialog needs the opposite,
        # or a single refusal blanks the list of everything else being applied.
        rows = accounts.preview({"delete_users": ["ghost"], "delete_groups": []})
        self.assertEqual(len(rows), 1)
        self.assertIn("refused", rows[0][1].lower())

    def test_rejects_malformed_payload_shape(self) -> None:
        with self.assertRaises(accounts.AccountError):
            accounts.from_payload({"delete_users": "alice"})
        with self.assertRaises(accounts.AccountError):
            accounts.from_payload({"remove_member": []})


class TestUidMin(unittest.TestCase):
    def test_is_cached(self) -> None:
        # Backs User.is_system, which the accounts page evaluates per row on
        # every keystroke in either search box.
        accounts.uid_min.cache_clear()
        accounts.uid_min()
        accounts.uid_min()
        self.assertEqual(accounts.uid_min.cache_info().misses, 1)


if __name__ == "__main__":
    unittest.main()
