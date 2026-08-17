"""The modprobe section — every loadable module on this kernel, one toggle each.

There used to be two pages: a curated grid of 170 flags, and a separate browser
over the other ~6,700 modules under its own sidebar entry. That split is what made
the section look like 170 was all you could blacklist, and stacking the two on one
page instead put 170 modules on screen twice with two different controls writing
to two different files. This is one list.

One row per module. Curated modules keep their catalogue text and stage to the
section's own drop-in, so presets still carry them; everything else stages to the
debloat drop-in. Both go through the same review and apply.

Modules are grouped by kernel subsystem, and a subsystem's rows are built only
when it is opened — a description comes from modinfo at about 6ms a module, so
building all 6,947 up front would cost most of a minute.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from .. import kmod as kmod_module  # noqa: E402

#: Rows per page inside an opened subsystem, and per page of search results.
PAGE_LIMIT = 50

VERDICT_STYLE = {
    "refused": ("status-differs", "In use"),
    "blocked": ("status-applied", "Already blacklisted"),
    "caution": ("status-pending-reboot", "Risky"),
    "candidate": ("status-not-set", "Candidate"),
    "builtin": ("status-invalid", "Built into the kernel"),
    "absent": ("status-unknown", "Not on this kernel"),
}

#: Levels with nothing to stage. A switch on any of these is a switch that lies:
#: loaded means it is already in the kernel, blocked means a file already stops
#: it, and builtin means no blacklist can ever apply.
_LOCKED = ("refused", "blocked", "builtin")

FILTERS = ("everything", "not blacklisted", "already blacklisted", "in use")


class KmodPage(Gtk.Box):
    """The whole modprobe section: search, group, toggle."""

    __gtype_name__ = "OssKmodPage"

    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.window = window
        self._updating = False
        #: Rows built per group, and the "show more" row at the end of each.
        #: Per page instance, not per window: a real rebuild (a search, a filter
        #: change) makes new expanders, and carrying the old counts over would let
        #: a group think it was already filled and render empty.
        self._group_limits: dict = {}
        self._more_rows: dict = {}
        if not hasattr(window, "kmod_inventory"):
            window.kmod_inventory = kmod_module.read_inventory()
        self.inventory = window.kmod_inventory
        section = window.catalogue.section("modprobe")
        self.rows = kmod_module.build_rows(self.inventory, section.flags)
        self.groups = kmod_module.grouped(self.rows)
        self.append(self._build())

    def _rebuild(self) -> None:
        self.window._show_section(self.window.current_section)

    # ------------------------------------------------------------------ #
    #  Window-held view state, so a rebuild does not lose your place
    # ------------------------------------------------------------------ #

    @property
    def _search(self) -> str:
        return getattr(self.window, "kmod_search", "")

    @property
    def _filter(self) -> str:
        return getattr(self.window, "kmod_filter", "everything")

    @property
    def _open(self) -> set:
        """Which groups are expanded. Everything starts collapsed.

        Opening the eight curated groups by default put hundreds of rows between
        the top of the page and the next heading, and "some sections are open and
        some are not" is not a distinction anyone can see a reason for.
        """
        if not hasattr(self.window, "kmod_open"):
            self.window.kmod_open = set()
        return self.window.kmod_open


    @property
    def _limit(self) -> int:
        return getattr(self.window, "kmod_limit", PAGE_LIMIT)

    def _build(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_margin_bottom(14)
        box.append(self._summary_group())
        box.append(self._controls_group())
        if self._search:
            box.append(self._search_group())
        else:
            for name, rows in self.groups:
                box.append(self._group(name, rows))
        box.append(self._deletion_group())
        return box

    # -- state per row --------------------------------------------------- #

    def _level(self, row) -> tuple[str, str]:
        if row.module is not None:
            return self.inventory.verdict_for(row.module)
        if row.name in self.inventory.builtin:
            # Compiled into the kernel image, so there is no module to refuse to
            # load and a blacklist line cannot touch it. On this kernel that is
            # true of fat, vfat, squashfs, cdrom, sr_mod and ppp_generic — three of
            # which are the section's "breaking" flags, offered with a switch that
            # could never have done what its warning said it would.
            return (
                "builtin",
                "Built into this kernel rather than loaded as a module, so a "
                "blacklist cannot stop it. Only a kernel built without it can.",
            )
        where = self.inventory.blacklisted.get(row.name)
        if where:
            return ("blocked", f"Already blacklisted in {where}.")
        return (
            "absent",
            "No module of this name on this kernel, so blacklisting it does "
            "nothing here — but the setting travels in a preset and does apply on "
            "a machine that has it.",
        )

    def _blacklisted_by(self, row) -> str | None:
        return self.inventory.blacklisted.get(row.name)

    def _ours(self, row) -> bool:
        where = self._blacklisted_by(row) or ""
        return "99-oss.conf" in where or kmod_module.TARGET in where

    def _staged(self, row) -> bool:
        if row.curated:
            return self.window.staging.is_set(row.flag.id)
        return row.name in self.window.module_blacklist

    # -- summary and controls -------------------------------------------- #

    def _summary_group(self) -> Adw.PreferencesGroup:
        counts = self.inventory.counts()
        staged = len(self.window.module_blacklist) + self.window.staging.changed_in_section(
            "modprobe"
        )
        group = Adw.PreferencesGroup(
            title="Kernel modules",
            description=(
                f"{len(self.rows)} modules, grouped by subsystem. This kernel "
                f"({self.inventory.release}) is using "
                f"{self.inventory.loaded_count} of them right now, plus "
                f"{len(self.inventory.builtin)} compiled in. Every other module is "
                f"code the kernel will load automatically if something asks for it "
                f"— a device appearing, an image being mounted, a packet arriving "
                f"for a protocol nobody uses. That autoload path is what "
                f"blacklisting closes."
            ),
        )
        group.add(
            self._row(
                f"{counts.get('candidate', 0) + counts.get('caution', 0)} available",
                "Not loaded and not blacklisted by anything. These are the ones a "
                "toggle here will act on.",
            )
        )
        group.add(
            self._row(
                f"{counts.get('blocked', 0)} already blacklisted",
                "Stopped from loading by a file on this system already — this "
                "app's drop-ins, the distro's, or one you wrote. Each row names "
                "the file.",
            )
        )
        group.add(
            self._row(
                f"{counts.get('refused', 0)} in use",
                "Loaded right now, so not offered: blacklisting a loaded module "
                "changes nothing until it stops being used.",
            )
        )
        if staged:
            row = self._row(
                f"{staged} staged in this section",
                f"Curated modules are written to the section's drop-in; the rest "
                f"to {kmod_module.TARGET}. Both on the next apply.",
            )
            clear = Gtk.Button(label="Clear browser picks", valign=Gtk.Align.CENTER)
            clear.add_css_class("destructive-action")
            clear.connect("clicked", self._on_clear)
            row.add_suffix(clear)
            group.add(row)
        return group

    def _controls_group(self) -> Adw.PreferencesGroup:
        group = Adw.PreferencesGroup()
        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        controls.set_margin_top(4)
        controls.set_margin_bottom(4)

        entry = Gtk.SearchEntry(
            placeholder_text="Search all 6,900 modules by name or subsystem",
            hexpand=True,
        )
        entry.set_text(self._search)
        entry.connect("search-changed", self._on_search)
        controls.append(entry)

        drop = Gtk.DropDown.new_from_strings(list(FILTERS))
        drop.set_selected(FILTERS.index(self._filter) if self._filter in FILTERS else 0)
        drop.set_valign(Gtk.Align.CENTER)
        drop.connect("notify::selected", self._on_filter)
        controls.append(drop)

        holder = Adw.PreferencesRow(activatable=False, selectable=False)
        holder.set_child(controls)
        group.add(holder)
        return group

    # -- filtering ------------------------------------------------------- #

    def _passes(self, row) -> bool:
        level, _why = self._level(row)
        wanted = self._filter
        if wanted == "not blacklisted" and level in ("blocked", "refused"):
            return False
        if wanted == "already blacklisted" and level != "blocked":
            return False
        if wanted == "in use" and level != "refused":
            return False
        search = self._search
        if search:
            haystack = f"{row.name} {row.category}".lower()
            if search not in haystack:
                return False
        return True

    # -- groups ---------------------------------------------------------- #

    def _group(self, name: str, rows: list) -> Gtk.Widget:
        visible = [r for r in rows if self._passes(r)]
        blocked = sum(1 for r in rows if self._level(r)[0] == "blocked")
        loaded = sum(1 for r in rows if r.module is not None and r.module.loaded)

        group = Adw.PreferencesGroup()
        expander = Adw.ExpanderRow(
            title=GLib.markup_escape_text(name),
            subtitle=(
                f"{len(visible)} shown of {len(rows)}  ·  {blocked} already "
                f"blacklisted  ·  {loaded} in use"
            ),
        )
        if not visible:
            expander.set_subtitle(f"{len(rows)} modules, none match this filter")
            group.add(expander)
            return group

        is_open = name in self._open
        self._updating = True
        expander.set_expanded(is_open)
        self._updating = False
        expander.connect("notify::expanded", self._on_expanded, name, visible)

        if is_open:
            self._fill(expander, name, visible)
        group.add(expander)
        return group

    def _fill(self, expander: Adw.ExpanderRow, name: str, visible: list) -> None:
        """Add this group's rows to the expander, in place.

        In place is the whole point. Opening a group used to call _rebuild(),
        which tears the page down and builds it again from the top — so the
        scroller lost its position and every expand threw you back to the start of
        6,900 rows. Nothing outside this expander changes when a group opens, so
        nothing outside it is rebuilt.
        """
        built = self._group_limits.get(name, 0)
        if built:  # already populated on a previous expand
            return
        limit = min(PAGE_LIMIT, len(visible))
        for row in visible[:limit]:
            expander.add_row(self._toggle_row(row))
        self._group_limits[name] = limit
        self._more_row(expander, name, visible)

    def _more_row(self, expander: Adw.ExpanderRow, name: str, visible: list) -> None:
        """The 'show more' row at the end of an opened group, if there is more."""
        built = self._group_limits.get(name, 0)
        remaining = len(visible) - built
        holder = self._more_rows
        previous = holder.pop(name, None)
        if previous is not None:
            expander.remove(previous)
        if remaining <= 0:
            return
        row = self._row(
            f"{remaining} more in {name}",
            "Each row runs modinfo, so they come in pages.",
        )
        button = Gtk.Button(
            label=f"Show {min(PAGE_LIMIT, remaining)} more", valign=Gtk.Align.CENTER
        )
        button.connect("clicked", self._on_show_more_group, expander, name, visible)
        row.add_suffix(button)
        expander.add_row(row)
        holder[name] = row

    def _search_group(self) -> Adw.PreferencesGroup:
        matches = [r for r in self.rows if self._passes(r)]
        group = Adw.PreferencesGroup(
            title="Search results",
            description=f"{len(matches)} module(s) match “{self._search}”.",
        )
        if not matches:
            group.add(self._row("Nothing matches", "Try a different name."))
            return group
        for row in matches[: self._limit]:
            group.add(self._toggle_row(row))
        remaining = len(matches) - min(len(matches), self._limit)
        if remaining > 0:
            more = self._row(f"{remaining} more match", "")
            button = Gtk.Button(
                label=f"Show {min(PAGE_LIMIT, remaining)} more", valign=Gtk.Align.CENTER
            )
            button.connect("clicked", self._on_show_more)
            more.add_suffix(button)
            group.add(more)
        return group

    # -- the row --------------------------------------------------------- #

    def _toggle_row(self, row) -> Adw.ActionRow:
        level, why = self._level(row)
        css, label = VERDICT_STYLE.get(level, ("status-unknown", level))

        bits = []
        if row.curated:
            # The catalogue already says what this is and what it breaks, which is
            # better than modinfo and costs nothing.
            bits.append(row.flag.desc or row.flag.title)
            if row.flag.breaks:
                bits.append(f"Breaks: {row.flag.breaks}")
        elif row.module is not None:
            description = kmod_module.describe(row.module)
            bits.append(f"{row.module.category}  ·  {row.module.size_kb} KB")
            if description:
                bits.append(description)
        subtitle = "  ·  ".join(b for b in bits if b)
        subtitle = f"{subtitle}\n{why}" if subtitle else why

        action = Adw.ActionRow(
            title=GLib.markup_escape_text(row.name),
            subtitle=GLib.markup_escape_text(subtitle),
        )
        action.set_subtitle_lines(4)

        icon = Gtk.Image.new_from_icon_name(
            "dialog-error-symbolic" if level == "refused"
            else "object-select-symbolic" if level == "blocked"
            else "system-lock-screen-symbolic" if level == "builtin"
            else "dialog-warning-symbolic" if level == "caution"
            else "package-x-generic-symbolic"
        )
        icon.add_css_class(css)
        action.add_prefix(icon)

        if level in _LOCKED and not self._ours(row):
            # Nothing to stage: it is loaded, or a file this app does not own
            # already blocks it. Saying so beats a switch that does nothing.
            action.set_sensitive(False)
            badge = Gtk.Label(label=label)
            badge.add_css_class("caption")
            badge.add_css_class("dim-label")
            badge.set_valign(Gtk.Align.CENTER)
            action.add_suffix(badge)
            return action

        switch = Gtk.Switch(valign=Gtk.Align.CENTER)
        self._updating = True
        switch.set_active(self._staged(row) or self._blacklisted_by(row) is not None)
        self._updating = False
        switch.set_tooltip_text(
            "Blacklist this module — written on the next apply"
            if row.curated
            else f"Blacklist this module, via {kmod_module.TARGET}"
        )
        switch.connect("state-set", self._on_toggle, row)
        action.add_suffix(switch)
        return action

    # -- handlers -------------------------------------------------------- #

    def _on_toggle(self, _switch: Gtk.Switch, active: bool, row) -> bool:
        if self._updating:
            return False
        if row.curated:
            self.window.staging.set(row.flag.id, row.flag.value if active else None)
        elif active:
            try:
                kmod_module.validate(row.name)
            except kmod_module.ModuleError as exc:
                self.window.toast(str(exc))
                return True
            self.window.module_blacklist.add(row.name)
        else:
            self.window.module_blacklist.discard(row.name)
        self.window._refresh_chrome()
        return False

    def _on_expanded(
        self, expander: Adw.ExpanderRow, _param, name: str, visible: list
    ) -> None:
        """Remember the group's state and fill it — without rebuilding the page."""
        if self._updating:
            return
        if expander.get_expanded():
            self._open.add(name)
            self._fill(expander, name, visible)
        else:
            self._open.discard(name)

    def _on_show_more_group(
        self, _button: Gtk.Button, expander: Adw.ExpanderRow, name: str, visible: list
    ) -> None:
        """Append the next page to this group, leaving the rest of the page alone."""
        built = self._group_limits.get(name, 0)
        for row in visible[built : built + PAGE_LIMIT]:
            expander.add_row(self._toggle_row(row))
        self._group_limits[name] = min(built + PAGE_LIMIT, len(visible))
        self._more_row(expander, name, visible)

    def _on_search(self, entry: Gtk.SearchEntry) -> None:
        self.window.kmod_search = entry.get_text().strip().lower()
        self.window.kmod_limit = PAGE_LIMIT
        self._rebuild()

    def _on_filter(self, drop: Gtk.DropDown, _param) -> None:
        index = drop.get_selected()
        if 0 <= index < len(FILTERS):
            self.window.kmod_filter = FILTERS[index]
            self.window.kmod_limit = PAGE_LIMIT
            self._rebuild()

    def _on_show_more(self, _button: Gtk.Button) -> None:
        self.window.kmod_limit = self._limit + PAGE_LIMIT
        self._rebuild()

    def _on_clear(self, _button: Gtk.Button) -> None:
        self.window.module_blacklist.clear()
        self.window._refresh_chrome()
        self._rebuild()

    # -- the standing answer to "can I just delete them?" ----------------- #

    def _deletion_group(self) -> Adw.PreferencesGroup:
        group = Adw.PreferencesGroup(title="Can I delete them instead?")
        expander = Adw.ExpanderRow(
            title="Deleting the .ko files is not offered here",
            subtitle="Tap for why blacklisting is the same win at none of the cost.",
        )
        body = self._row(kmod_module.DELETION_ANSWER, "")
        body.set_title_lines(20)
        expander.add_row(body)
        group.add(expander)
        return group

    @staticmethod
    def _row(title: str, subtitle: str) -> Adw.ActionRow:
        row = Adw.ActionRow(title=GLib.markup_escape_text(title))
        if subtitle:
            row.set_subtitle(GLib.markup_escape_text(subtitle))
        row.set_title_lines(3)
        row.set_subtitle_lines(4)
        return row
