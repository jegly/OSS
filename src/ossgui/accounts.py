"""User and group accounts — list, group membership, and deletion.

Package removal does not clean up the system accounts a package created:
Debian policy deliberately avoids this on purge, because the UID could still
own files elsewhere on disk, and a future package reusing that UID would
silently inherit access to them. So an account that outlives its package
never gets removed by anything else — only here, by hand.

This is also the one section where deleting *any* account, not just unused
system ones, was a deliberate choice. Unlike a config toggle, deleting the
wrong account cannot be undone by restoring a file. Two things are refused
outright regardless of what is asked: the account currently running this
apply, and any account with UID/GID 0. Everything else is offered, with group
memberships, home directory and logged-in status shown before it is confirmed.
"""

from __future__ import annotations

import os
import pwd
import subprocess
from dataclasses import dataclass
from functools import lru_cache

GETENT = "/usr/bin/getent"
WHO = "/usr/bin/who"
USERDEL = "/usr/sbin/userdel"
GROUPDEL = "/usr/sbin/groupdel"
GPASSWD = "/usr/bin/gpasswd"

#: Characters that cannot appear in a name we are willing to act on: the field
#: separator and the line terminators of passwd/group, plus the path separator
#: and whitespace. Everything else is left to the tools themselves.
_FORBIDDEN = frozenset(":\n\r\0/\t ")

#: The longest name useradd(8) will create.
_MAX_NAME = 32

DEFAULT_UID_MIN = 1000
#: nobody / nogroup.
_NOBODY = (65534, 65533)


class AccountError(ValueError):
    """A user, group or action we refuse to act on."""


@dataclass(frozen=True)
class User:
    """One row of `getent passwd`, with group membership resolved."""

    name: str
    uid: int
    gid: int
    gecos: str = ""
    home: str = ""
    shell: str = ""
    #: Every group this user belongs to, primary group included.
    groups: tuple[str, ...] = ()
    logged_in: bool = False

    @property
    def is_system(self) -> bool:
        return self.uid < uid_min() or self.uid in _NOBODY

    @property
    def is_root(self) -> bool:
        return self.uid == 0

    @property
    def has_login(self) -> bool:
        return not self.shell.endswith(("/nologin", "/false"))


@dataclass(frozen=True)
class Group:
    """One row of `getent group`."""

    name: str
    gid: int
    members: tuple[str, ...] = ()

    @property
    def is_system(self) -> bool:
        return self.gid < uid_min() or self.gid in _NOBODY


def _run(argv: list[str], timeout: int = 20) -> str | None:
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


@lru_cache(maxsize=1)
def uid_min() -> int:
    """The UID new real accounts start at — everything below is a system account.

    Cached: this backs ``User.is_system`` and ``Group.is_system``, which the
    accounts page evaluates for every row it filters, on every keystroke in
    either search box. Uncached that is a fresh open-and-parse of
    /etc/login.defs per row per keypress.
    """
    try:
        with open("/etc/login.defs", encoding="utf-8") as handle:
            for line in handle:
                # A trailing comment is legal here, and OSS's own pam section
                # edits this file in place, so match on the first two fields
                # rather than requiring the line to have exactly two.
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "UID_MIN":
                    return int(parts[1])
    except (OSError, ValueError):
        pass
    return DEFAULT_UID_MIN


def logged_in_names() -> set[str]:
    output = _run([WHO]) or ""
    return {line.split()[0] for line in output.splitlines() if line.split()}


def read_groups() -> dict[str, Group]:
    """Every group, unprivileged."""
    output = _run([GETENT, "group"]) or ""
    out: dict[str, Group] = {}
    for line in output.splitlines():
        parts = line.split(":")
        if len(parts) < 4:
            continue
        name, _passwd, gid, members = parts[0], parts[1], parts[2], parts[3]
        try:
            gid_int = int(gid)
        except ValueError:
            continue
        out[name] = Group(
            name=name,
            gid=gid_int,
            members=tuple(m for m in members.split(",") if m),
        )
    return out


def read_users() -> list[User]:
    """Every user, with resolved group membership. Unprivileged."""
    output = _run([GETENT, "passwd"]) or ""
    groups = read_groups()
    primary_name_by_gid: dict[int, str] = {}
    for group in groups.values():
        primary_name_by_gid.setdefault(group.gid, group.name)
    logged_in = logged_in_names()

    out: list[User] = []
    for line in output.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name, _passwd, uid, gid, gecos, home, shell = parts[:7]
        try:
            uid_int, gid_int = int(uid), int(gid)
        except ValueError:
            continue
        member_of = {g.name for g in groups.values() if name in g.members}
        if gid_int in primary_name_by_gid:
            member_of.add(primary_name_by_gid[gid_int])
        out.append(
            User(
                name=name,
                uid=uid_int,
                gid=gid_int,
                gecos=gecos,
                home=home,
                shell=shell,
                groups=tuple(sorted(member_of)),
                logged_in=name in logged_in,
            )
        )
    return out


# --------------------------------------------------------------------------- #
#  Guards
# --------------------------------------------------------------------------- #


def validate_name(name: str) -> None:
    """Reject a name we cannot safely hand to userdel/groupdel/gpasswd.

    This is deliberately looser than useradd(8)'s NAME_REGEX. That pattern
    describes what useradd is willing to *create*, and distro packages
    routinely create accounts outside it — Debian ships ``Debian-exim`` and
    ``Debian-snmp``, made with ``adduser --force-badname``. Validating against
    NAME_REGEX would refuse to remove precisely the orphaned system accounts
    this module exists to clean up, and would do it at apply time, after the
    user had already staged and reviewed the deletion.

    The names never reach a shell — every caller builds an argv — so the real
    hazards are narrow and are what is checked here: an empty name, a name
    long enough to have been truncated somewhere, a leading ``-`` that the
    tools would parse as an option, and the characters that terminate a field
    or a line in ``/etc/passwd``.
    """
    if not name:
        raise AccountError("empty account name")
    if len(name) > _MAX_NAME:
        raise AccountError(f"account name is longer than {_MAX_NAME} characters: {name!r}")
    if name.startswith("-"):
        raise AccountError(f"account name starts with '-', which userdel reads as an option: {name!r}")
    bad = sorted(_FORBIDDEN.intersection(name))
    if bad:
        raise AccountError(f"account name contains {''.join(bad)!r}: {name!r}")
    if any(not character.isprintable() for character in name):
        raise AccountError(f"account name contains a control character: {name!r}")


def current_invoking_user() -> str | None:
    """The account that ran pkexec, if this is running inside the helper.

    pkexec sets PKEXEC_UID to the calling user's uid — the process itself is
    root by the time this runs, so this is the only way left to tell who asked.
    """
    raw_uid = os.environ.get("PKEXEC_UID")
    if raw_uid is None:
        return None
    try:
        return pwd.getpwuid(int(raw_uid)).pw_name
    except (ValueError, KeyError):
        return None


def guard_user_deletion(name: str, users: dict[str, User]) -> None:
    validate_name(name)
    user = users.get(name)
    if user is None:
        raise AccountError(f"{name} does not exist")
    if user.is_root:
        raise AccountError("refusing to delete a UID 0 account")
    invoking = current_invoking_user()
    if invoking is not None and name == invoking:
        raise AccountError("refusing to delete the account running this apply")


def guard_group_deletion(
    name: str,
    groups: dict[str, Group],
    users: list[User],
    deleting_users: frozenset[str] = frozenset(),
) -> None:
    validate_name(name)
    group = groups.get(name)
    if group is None:
        raise AccountError(f"{name} does not exist")
    if group.gid == 0:
        raise AccountError("refusing to delete a GID 0 group")
    # A group that is still someone's primary group cannot be deleted by
    # groupdel anyway — unless that someone is being deleted in this same
    # batch, in which case they will be gone before this rule runs.
    primary_for = [
        u.name for u in users if u.gid == group.gid and u.name not in deleting_users
    ]
    if primary_for:
        raise AccountError(
            f"{name} is the primary group of {', '.join(sorted(primary_for))} — "
            "remove or reassign those accounts first"
        )


# --------------------------------------------------------------------------- #
#  Changes
# --------------------------------------------------------------------------- #


def plan_user_delete(
    name: str, remove_home: bool, users: dict[str, User]
) -> tuple[list[str], str]:
    guard_user_deletion(name, users)
    argv = [USERDEL]
    if remove_home:
        argv.append("-r")
    argv.append(name)
    suffix = " and its home directory" if remove_home else ""
    return argv, f"delete user {name}{suffix}"


def plan_group_delete(
    name: str,
    groups: dict[str, Group],
    users: list[User],
    deleting_users: frozenset[str] = frozenset(),
) -> tuple[list[str], str]:
    guard_group_deletion(name, groups, users, deleting_users)
    return [GROUPDEL, name], f"delete group {name}"


def plan_remove_member(
    user: str,
    group: str,
    users: dict[str, User] | None = None,
    groups: dict[str, Group] | None = None,
) -> tuple[list[str], str]:
    """The gpasswd call that drops *user* from *group*.

    Checked against current state when it is given, because ``gpasswd -d`` on
    an account that is not a member exits non-zero, and every command here runs
    inside the one transaction — so a membership that went away between staging
    and applying would roll back the entire apply rather than being the no-op
    the user would expect.
    """
    validate_name(user)
    validate_name(group)
    if users is not None and user not in users:
        raise AccountError(f"{user} no longer exists")
    if groups is not None:
        existing = groups.get(group)
        if existing is None:
            raise AccountError(f"group {group} no longer exists")
        if users is not None and user not in existing.members:
            raise AccountError(f"{user} is no longer a member of {group}")
    return [GPASSWD, "-d", user, group], f"remove {user} from {group}"


def _planners(data: dict):
    """Yield a no-argument planner per staged change, in the order they must run.

    Membership removals first, then user deletions, then group deletions — a
    group can only go once the account it was primary for is gone.

    Payload *shape* is validated here and raises immediately; whether any
    individual change is allowed is left to the planner it yields, so a caller
    can decide per item (:func:`preview`) or all-or-nothing (:func:`from_payload`).
    """
    if not isinstance(data, dict):
        raise AccountError("accounts payload is not an object")

    users_list = read_users()
    users_by_name = {u.name: u for u in users_list}
    groups_by_name = read_groups()

    remove_member = data.get("remove_member", {})
    if not isinstance(remove_member, dict):
        raise AccountError("remove_member must be an object")
    for user, group_list in remove_member.items():
        if not isinstance(user, str) or not isinstance(group_list, list):
            raise AccountError("remove_member must map a username to a list of groups")
        for group in group_list:
            if not isinstance(group, str):
                raise AccountError("group names must be strings")
            yield (
                f"remove {user} from {group}",
                lambda u=user, g=group: plan_remove_member(
                    u, g, users_by_name, groups_by_name
                ),
            )

    delete_users = data.get("delete_users", [])
    if not isinstance(delete_users, list):
        raise AccountError("delete_users must be a list")
    if not all(isinstance(n, str) for n in delete_users):
        raise AccountError("user names must be strings")
    remove_home = bool(data.get("remove_home", False))
    for name in delete_users:
        yield (
            f"delete user {name}",
            lambda n=name: plan_user_delete(n, remove_home, users_by_name),
        )

    deleting_users = frozenset(delete_users)
    delete_groups = data.get("delete_groups", [])
    if not isinstance(delete_groups, list):
        raise AccountError("delete_groups must be a list")
    if not all(isinstance(n, str) for n in delete_groups):
        raise AccountError("group names must be strings")
    for name in delete_groups:
        yield (
            f"delete group {name}",
            lambda n=name: plan_group_delete(
                n, groups_by_name, users_list, deleting_users
            ),
        )


def from_payload(data: dict) -> list[tuple[list[str], str]]:
    """Validate an accounts payload from the GUI into an ordered command list.

    All-or-nothing, because this is what the helper runs: a batch containing
    one change that cannot be validated is refused whole rather than
    part-applied.
    """
    return [planner() for _label, planner in _planners(data)]


def preview(data: dict) -> list[tuple[str, str]]:
    """``(what, detail)`` per staged change, for the review dialog.

    Unlike :func:`from_payload` this never raises on an individual change; a
    refusal becomes that row's detail. The dialog's job is to show the user
    everything they have staged, and an early raise would replace the whole
    list with a single error — hiding the other changes they are about to
    make behind one they cannot.
    """
    out: list[tuple[str, str]] = []
    try:
        planners = list(_planners(data))
    except AccountError as exc:
        return [("This would be refused", str(exc))]
    for label, planner in planners:
        try:
            argv, why = planner()
        except AccountError as exc:
            out.append((label, f"Would be refused — {exc}"))
        else:
            out.append((why, " ".join(argv)))
    return out


def plan_commands(changes: list[tuple[list[str], str]]) -> list[tuple[list[str], str]]:
    """Pass-through for symmetry with the other ad-hoc domains (packages, snap)."""
    return changes
