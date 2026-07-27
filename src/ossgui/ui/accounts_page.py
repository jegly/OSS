"""Users and groups — list, group membership, and deletion.

Removing a package never removes the system account it created, so accounts
accumulate forever unless something else cleans them up — this page is that
something else. It is also the one section where deleting *any* account, not
just an unused system one, is offered: the account currently running this
session and anything with UID/GID 0 are refused outright (enforced again,
independently, by the helper), everything else is a deliberate, reviewable
choice.
"""

from __future__ import annotations

import getpass

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from .. import accounts as accounts_module  # noqa: E402

SHOW_LIMIT = 60


def _current_user() -> str:
    try:
        return getpass.getuser()
    except OSError:
        return ""


class AccountsPage(Gtk.Box):
    """Two lists — users and groups — each searchable, each with a delete path."""

    __gtype_name__ = "OssAccountsPage"

    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.window = window
        if not hasattr(window, "accounts_users"):
            window.accounts_users = accounts_module.read_users()
        if not hasattr(window, "accounts_groups"):
            window.accounts_groups = accounts_module.read_groups()
        self.current_user = _current_user()
        self.append(self._build())

    def _rebuild(self) -> None:
        self.window._show_section(self.window.current_section)

    # _rebuild() replaces this whole widget with a fresh AccountsPage instance
    # (see MainWindow._show_section), so any UI state that needs to survive an
    # interaction — search text, the system-accounts toggle — has to live on
    # the long-lived window, not on self, or it silently resets on every click.
    @property
    def user_search(self) -> str:
        return getattr(self.window, "accounts_user_search", "")

    @user_search.setter
    def user_search(self, value: str) -> None:
        self.window.accounts_user_search = value

    @property
    def group_search(self) -> str:
        return getattr(self.window, "accounts_group_search", "")

    @group_search.setter
    def group_search(self, value: str) -> None:
        self.window.accounts_group_search = value

    @property
    def show_system(self) -> bool:
        return getattr(self.window, "accounts_show_system", False)

    @show_system.setter
    def show_system(self, value: bool) -> None:
        self.window.accounts_show_system = value

    @property
    def users(self) -> list[accounts_module.User]:
        return self.window.accounts_users

    @property
    def groups(self) -> dict[str, accounts_module.Group]:
        return self.window.accounts_groups

    def _refresh_data(self) -> None:
        self.window.accounts_users = accounts_module.read_users()
        self.window.accounts_groups = accounts_module.read_groups()

    # ------------------------------------------------------------------ #

    def _build(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_margin_bottom(14)
        box.append(self._summary_group())
        box.append(self._users_group())
        box.append(self._groups_group())
        return box

    def _summary_group(self) -> Adw.PreferencesGroup:
        users = self.users
        real = [u for u in users if not u.is_system]
        group = Adw.PreferencesGroup(
            title="Accounts",
            description=(
                f"{len(users)} users ({len(real)} real, {len(users) - len(real)} "
                f"system accounts) and {len(self.groups)} groups. Most system "
                f"accounts belong to an installed package and exist so its daemon "
                f"does not run as root — that is normal, not clutter. Purging the "
                f"package will not remove the account behind it; this page is the "
                f"only thing that will."
            ),
        )
        if self.window.account_delete_users or self.window.account_delete_groups:
            staged = self._row(
                f"{len(self.window.account_delete_users)} user(s), "
                f"{len(self.window.account_delete_groups)} group(s) staged for deletion",
                "Nothing happens until you Apply. Review shows the exact commands.",
            )
            group.add(staged)
        leaves = sum(len(g) for g in self.window.account_remove_member.values())
        if leaves:
            group.add(self._row(
                f"{leaves} group membership(s) staged to leave",
                "Leaving a group is reversible by adding the account back to it.",
            ))
        return group

    #: What the system-accounts toggle is called in each list.
    _TOGGLE_LABEL = {"users": "Show system accounts", "groups": "Show system groups"}

    def _count_text(self, kind: str, total: int, overall: int, search: str) -> str:
        """The list header's count, naming whatever is being left out.

        A bare "1 shown." directly under a summary that says there are 77 of
        them reads as a broken list rather than a filtered one.
        """
        if total >= overall:
            return f"All {overall} shown."
        hidden = overall - total
        if not search:
            return f"{total} of {overall} shown — {hidden} system {kind} hidden."
        return f"{total} of {overall} shown — {hidden} filtered out."

    def _empty_hint(self, kind: str) -> tuple[str, str]:
        """Title and subtitle for an empty list, saying *why* it is empty.

        Usually the reason is not "no such account" but "that one is a system
        account, and those are hidden" — most of the machine lives below
        UID_MIN. A search box that comes back empty because of a toggle
        elsewhere is precisely the sort of unexplained state this application
        exists to surface, so it is not one to reproduce.
        """
        if not self.show_system:
            return (
                f"No {kind} match what is shown",
                f"System {kind} are hidden. Turn on "
                f"“{self._TOGGLE_LABEL[kind]}” to search all of them.",
            )
        return (f"No {kind} match", "Nothing here matches the current filter.")

    # -- users ------------------------------------------------------------ #

    def _visible_users(self) -> tuple[list, int]:
        users = self.users
        if not self.show_system:
            users = [u for u in users if not u.is_system or u.name in self.window.account_delete_users]
        if self.user_search:
            users = [
                u for u in users
                if self.user_search in u.name.lower() or self.user_search in u.gecos.lower()
            ]
        total = len(users)
        selected = [u for u in users if u.name in self.window.account_delete_users]
        rest = sorted(
            (u for u in users if u.name not in self.window.account_delete_users),
            key=lambda u: u.uid,
        )
        return (selected + rest)[:SHOW_LIMIT], total

    def _users_group(self) -> Adw.PreferencesGroup:
        shown, total = self._visible_users()
        group = Adw.PreferencesGroup(
            title="Users",
            description=self._count_text("users", total, len(self.users), self.user_search),
        )

        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        controls.set_margin_top(4)
        controls.set_margin_bottom(4)
        entry = Gtk.SearchEntry(placeholder_text="Filter by name", hexpand=True)
        entry.set_text(self.user_search)
        entry.connect("search-changed", self._on_user_search)
        controls.append(entry)
        toggle = Gtk.ToggleButton(label="Show system accounts")
        toggle.set_active(self.show_system)
        toggle.set_tooltip_text(
            "Hidden by default — almost all of these belong to an installed "
            "package's background service and are not meant to be logged into."
        )
        toggle.connect("toggled", self._on_show_system)
        controls.append(toggle)
        holder = Adw.PreferencesRow(activatable=False, selectable=False)
        holder.set_child(controls)
        group.add(holder)

        if self.window.account_delete_users:
            home_row = Adw.ActionRow(
                title="Also delete home directories",
                subtitle="Applies to every user selected below. Off leaves their files in place.",
            )
            home_switch = Gtk.Switch(valign=Gtk.Align.CENTER)
            home_switch.set_active(self.window.account_remove_home)
            home_switch.connect("state-set", self._on_remove_home)
            home_row.add_suffix(home_switch)
            group.add(home_row)

        if not shown:
            group.add(self._row(*self._empty_hint("users")))
            return group

        for user in shown:
            group.add(self._user_row(user))
        if total > len(shown):
            group.add(self._row(f"{total - len(shown)} more not shown", "Narrow the filter."))
        return group

    #: Groups whose loss is worth flagging for the account running this app —
    #: not blocked, since that would contradict "any user or group", just called
    #: out so leaving one isn't an accident.
    _NOTABLE_GROUPS = {"sudo", "admin", "wheel", "root"}

    def _group_gid(self, name: str) -> int | None:
        group = self.groups.get(name)
        return group.gid if group is not None else None

    def _user_row(self, user: accounts_module.User) -> Adw.PreferencesRow:
        selected = user.name in self.window.account_delete_users
        subtitle_bits = [f"uid {user.uid}"]
        if user.gecos:
            subtitle_bits.append(user.gecos)
        if user.groups:
            subtitle_bits.append("groups: " + ", ".join(user.groups))
        subtitle = GLib.markup_escape_text(" · ".join(subtitle_bits))
        title = GLib.markup_escape_text(user.name)

        # A user's primary group (the one their gid points at) cannot be left
        # with gpasswd -d — leaving it isn't a real operation, so it is never
        # offered, only the groups they additionally belong to.
        leavable = sorted(g for g in user.groups if self._group_gid(g) != user.gid)

        row: Adw.PreferencesRow
        if leavable:
            row = Adw.ExpanderRow(title=title, subtitle=subtitle)
            row.set_subtitle_lines(3)
            for group_name in leavable:
                row.add_row(self._membership_row(user, group_name))
        else:
            row = Adw.ActionRow(title=title, subtitle=subtitle)
            row.set_subtitle_lines(3)

        if user.logged_in:
            badge = Gtk.Label(label="logged in now")
            badge.add_css_class("caption")
            badge.add_css_class("status-differs")
            row.add_suffix(badge)

        refusal = self._user_refusal(user)
        if refusal:
            row.set_tooltip_text(refusal)
            check = Gtk.CheckButton(sensitive=False)
            row.add_suffix(check)
            badge = Gtk.Label(label="protected")
            badge.add_css_class("caption")
            badge.add_css_class("dim-label")
            row.add_suffix(badge)
            return row

        check = Gtk.CheckButton(active=selected, valign=Gtk.Align.CENTER)
        check.set_tooltip_text("Select for deletion")
        check.connect("toggled", self._on_select_user, user.name)
        row.add_suffix(check)
        return row

    def _membership_row(self, user: accounts_module.User, group_name: str) -> Adw.ActionRow:
        staged_groups = self.window.account_remove_member.get(user.name, set())
        staged = group_name in staged_groups

        row = Adw.ActionRow(title=GLib.markup_escape_text(group_name))
        if group_name in self._NOTABLE_GROUPS and user.name == self.current_user:
            row.set_subtitle(
                "This is how you have admin rights on this machine — leaving "
                "it may remove your own ability to run this application again."
            )
            row.set_subtitle_lines(2)
            icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
            icon.add_css_class("status-pending-reboot")
            row.add_prefix(icon)

        button = Gtk.ToggleButton(label="Staged to leave" if staged else "Leave")
        button.set_valign(Gtk.Align.CENTER)
        button.set_active(staged)
        if staged:
            button.add_css_class("destructive-action")
        button.connect("toggled", self._on_leave_group, user.name, group_name)
        row.add_suffix(button)
        return row

    def _user_refusal(self, user: accounts_module.User) -> str:
        if user.is_root:
            return "UID 0 — refusing to offer this account for deletion."
        if self.current_user and user.name == self.current_user:
            return "This is the account running this application."
        return ""

    # -- groups ------------------------------------------------------------ #

    def _visible_groups(self) -> tuple[list, int]:
        groups = list(self.groups.values())
        if not self.show_system:
            groups = [
                g for g in groups
                if not g.is_system or g.name in self.window.account_delete_groups
            ]
        if self.group_search:
            groups = [g for g in groups if self.group_search in g.name.lower()]
        total = len(groups)
        selected = [g for g in groups if g.name in self.window.account_delete_groups]
        rest = sorted(
            (g for g in groups if g.name not in self.window.account_delete_groups),
            key=lambda g: g.gid,
        )
        return (selected + rest)[:SHOW_LIMIT], total

    def _groups_group(self) -> Adw.PreferencesGroup:
        shown, total = self._visible_groups()
        group = Adw.PreferencesGroup(
            title="Groups",
            description=self._count_text(
                "groups", total, len(self.groups), self.group_search
            ),
        )

        # The same toggle as the Users list, and deliberately the same state:
        # it is one "show me the plumbing" decision, not two. It is repeated
        # here because it gates this list too, and a control that silently
        # empties a list from another section of the page is indistinguishable
        # from the list being broken.
        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        controls.set_margin_top(4)
        controls.set_margin_bottom(4)
        entry = Gtk.SearchEntry(placeholder_text="Filter by name", hexpand=True)
        entry.set_text(self.group_search)
        entry.connect("search-changed", self._on_group_search)
        controls.append(entry)
        toggle = Gtk.ToggleButton(label="Show system groups")
        toggle.set_active(self.show_system)
        toggle.set_tooltip_text(
            "Hidden by default, and shared with the Users list above — almost "
            "all of these back an installed package's service account."
        )
        toggle.connect("toggled", self._on_show_system)
        controls.append(toggle)
        holder = Adw.PreferencesRow(activatable=False, selectable=False)
        holder.set_child(controls)
        group.add(holder)

        if not shown:
            group.add(self._row(*self._empty_hint("groups")))
            return group

        primary_holders = self._primary_holders()
        for grp in shown:
            group.add(self._group_row(grp, primary_holders.get(grp.gid, [])))
        if total > len(shown):
            group.add(self._row(f"{total - len(shown)} more not shown", "Narrow the filter."))
        return group

    def _primary_holders(self) -> dict[int, list[str]]:
        out: dict[int, list[str]] = {}
        for user in self.users:
            out.setdefault(user.gid, []).append(user.name)
        return out

    def _group_row(self, grp: accounts_module.Group, primary_for: list[str]) -> Adw.ActionRow:
        selected = grp.name in self.window.account_delete_groups
        subtitle_bits = [f"gid {grp.gid}"]
        if grp.members:
            subtitle_bits.append("members: " + ", ".join(grp.members))
        row = Adw.ActionRow(
            title=GLib.markup_escape_text(grp.name),
            subtitle=GLib.markup_escape_text(" · ".join(subtitle_bits)),
        )
        row.set_subtitle_lines(3)

        refusal = self._group_refusal(grp, primary_for)
        if refusal:
            row.set_tooltip_text(refusal)
            check = Gtk.CheckButton(sensitive=False)
            row.add_suffix(check)
            badge = Gtk.Label(label="protected")
            badge.add_css_class("caption")
            badge.add_css_class("dim-label")
            row.add_suffix(badge)
            return row

        check = Gtk.CheckButton(active=selected, valign=Gtk.Align.CENTER)
        check.set_tooltip_text("Select for deletion")
        check.connect("toggled", self._on_select_group, grp.name)
        row.add_suffix(check)
        return row

    def _group_refusal(self, grp: accounts_module.Group, primary_for: list[str]) -> str:
        if grp.gid == 0:
            return "GID 0 — refusing to offer this group for deletion."
        remaining = [n for n in primary_for if n not in self.window.account_delete_users]
        if remaining:
            return (
                f"Primary group of {', '.join(remaining)} — remove or reassign "
                f"those accounts first."
            )
        return ""

    # -- handlers ----------------------------------------------------------- #

    def _on_user_search(self, entry: Gtk.SearchEntry) -> None:
        self.user_search = entry.get_text().strip().lower()
        self._rebuild()

    def _on_group_search(self, entry: Gtk.SearchEntry) -> None:
        self.group_search = entry.get_text().strip().lower()
        self._rebuild()

    def _on_show_system(self, button: Gtk.ToggleButton) -> None:
        self.show_system = button.get_active()
        self._rebuild()

    def _on_select_user(self, check: Gtk.CheckButton, name: str) -> None:
        if check.get_active():
            self.window.account_delete_users.add(name)
        else:
            self.window.account_delete_users.discard(name)
        self.window._refresh_chrome()
        self._rebuild()

    def _on_select_group(self, check: Gtk.CheckButton, name: str) -> None:
        if check.get_active():
            self.window.account_delete_groups.add(name)
        else:
            self.window.account_delete_groups.discard(name)
        self.window._refresh_chrome()
        self._rebuild()

    def _on_remove_home(self, _switch: Gtk.Switch, active: bool) -> bool:
        self.window.account_remove_home = active
        self.window._refresh_chrome()
        return False

    def _on_leave_group(
        self, button: Gtk.ToggleButton, user_name: str, group_name: str
    ) -> None:
        staged = self.window.account_remove_member.setdefault(user_name, set())
        if button.get_active():
            staged.add(group_name)
        else:
            staged.discard(group_name)
            if not staged:
                self.window.account_remove_member.pop(user_name, None)
        self.window._refresh_chrome()
        self._rebuild()

    @staticmethod
    def _row(title: str, subtitle: str) -> Adw.ActionRow:
        row = Adw.ActionRow(title=GLib.markup_escape_text(title))
        if subtitle:
            row.set_subtitle(GLib.markup_escape_text(subtitle))
        row.set_title_lines(2)
        row.set_subtitle_lines(4)
        return row
