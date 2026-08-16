"""Kernel debloat — browse every module on this kernel and blacklist the spare.

The curated modprobe section is the list worth blacklisting on any machine.
This is the other ~6,800: searchable, classified by whether the running system
depends on them, and staged through the same review-then-apply path.

Descriptions come from modinfo, which costs about 6ms per module. Running it
across the whole tree would take most of a minute, so it is run for the rows
actually on screen and cached on the Module record.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from .. import kmod as kmod_module  # noqa: E402

#: Rows per page. Every row carries a checkbox and a modinfo call, so this is
#: the number that keeps the page responsive rather than a ceiling.
PAGE_LIMIT = 50

VERDICT_STYLE = {
    "refused": ("status-differs", "In use — cannot be blacklisted"),
    "caution": ("status-pending-reboot", "Risky"),
    "candidate": ("status-not-set", "Candidate"),
}

FILTERS = ("candidates", "risky", "in use", "everything")


class KmodPage(Gtk.Box):
    """Search, classify and stage kernel modules for blacklisting."""

    __gtype_name__ = "OssKmodPage"

    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.window = window
        if not hasattr(window, "kmod_inventory"):
            window.kmod_inventory = kmod_module.read_inventory()
        self.inventory = window.kmod_inventory
        self.append(self._build())

    def _rebuild(self) -> None:
        self.window._show_section(self.window.current_section)

    # ------------------------------------------------------------------ #

    @property
    def _search(self) -> str:
        return getattr(self.window, "kmod_search", "")

    @property
    def _filter(self) -> str:
        return getattr(self.window, "kmod_filter", "candidates")

    @property
    def _limit(self) -> int:
        return getattr(self.window, "kmod_limit", PAGE_LIMIT)

    def _build(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_margin_bottom(14)
        box.append(self._summary_group())
        box.append(self._deletion_group())
        box.append(self._list_group())
        return box

    # -- summary --------------------------------------------------------- #

    def _summary_group(self) -> Adw.PreferencesGroup:
        counts = self.inventory.counts()
        total = len(self.inventory.modules)
        staged = len(self.window.module_blacklist)
        group = Adw.PreferencesGroup(
            title="Kernel modules",
            description=(
                f"This kernel ({self.inventory.release}) ships {total} loadable "
                f"modules and is using {self.inventory.loaded_count} of them right "
                f"now, plus {len(self.inventory.builtin)} compiled in. Every other "
                f"module is code the kernel will load automatically if something "
                f"asks for it — a device appearing, an image being mounted, a "
                f"packet arriving for a protocol nobody uses. That autoload path "
                f"is what blacklisting closes."
            ),
        )
        group.add(
            self._row(
                f"{counts.get('candidate', 0)} candidates",
                "Not loaded on this boot and not part of a subsystem where that "
                "would be misleading.",
            )
        )
        group.add(
            self._row(
                f"{counts.get('caution', 0)} risky",
                "Not loaded either, but storage, input, filesystem or graphics — "
                "where “not loaded now” does not mean “not needed at next boot”.",
            )
        )
        group.add(
            self._row(
                f"{counts.get('refused', 0)} in use",
                "Loaded right now. Not offered for blacklisting at all.",
            )
        )
        if staged:
            row = self._row(
                f"{staged} staged for blacklisting",
                f"Written to {kmod_module.TARGET} on apply, as blacklist plus "
                f"install /bin/false. Delete that file to undo all of them.",
            )
            clear = Gtk.Button(label="Clear", valign=Gtk.Align.CENTER)
            clear.add_css_class("destructive-action")
            clear.connect("clicked", self._on_clear)
            row.add_suffix(clear)
            group.add(row)
        return group

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

    # -- the list -------------------------------------------------------- #

    def _visible(self) -> tuple[list, int]:
        search = self._search
        wanted = self._filter
        out = []
        for module in self.inventory.modules.values():
            level, _why = module.verdict(self.inventory.mounted_fstypes)
            if wanted == "candidates" and level != "candidate":
                continue
            if wanted == "risky" and level != "caution":
                continue
            if wanted == "in use" and level != "refused":
                continue
            if search and search not in module.name.lower() and search not in module.category.lower():
                continue
            out.append(module)

        # Staged first so they do not vanish as the filter changes, then largest
        # first — removing a 2 MB driver is worth more than a 12 KB stub.
        staged = [m for m in out if m.name in self.window.module_blacklist]
        rest = sorted(
            (m for m in out if m.name not in self.window.module_blacklist),
            key=lambda m: -m.size_kb,
        )
        return (staged + rest)[: self._limit], len(out)

    def _list_group(self) -> Adw.PreferencesGroup:
        shown, total = self._visible()
        group = Adw.PreferencesGroup(
            title="Modules",
            description=f"{total} match. Largest first.",
        )

        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        controls.set_margin_top(4)
        controls.set_margin_bottom(4)
        entry = Gtk.SearchEntry(
            placeholder_text="Search name or subsystem", hexpand=True
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

        if not shown:
            group.add(self._row("Nothing matches", "Try a different filter."))
            return group

        for module in shown:
            group.add(self._module_row(module))

        remaining = total - len(shown)
        if remaining > 0:
            row = self._row(
                f"{remaining} more module(s)",
                "Search to jump straight to one, or load them here.",
            )
            more = Gtk.Button(
                label=f"Show {min(PAGE_LIMIT, remaining)} more", valign=Gtk.Align.CENTER
            )
            more.connect("clicked", self._on_show_more)
            row.add_suffix(more)
            every = Gtk.Button(label=f"Show all {total}", valign=Gtk.Align.CENTER)
            every.set_tooltip_text(
                "Renders every match, each with a modinfo lookup. Several thousand "
                "rows takes a while."
            )
            every.connect("clicked", self._on_show_all, total)
            row.add_suffix(every)
            group.add(row)
        return group

    def _module_row(self, module) -> Adw.ActionRow:
        level, why = module.verdict(self.inventory.mounted_fstypes)
        css, label = VERDICT_STYLE.get(level, ("status-unknown", level))

        description = kmod_module.describe(module)
        subtitle = f"{module.category}  ·  {module.size_kb} KB"
        if description:
            subtitle += f"  ·  {description}"
        subtitle += f"\n{why}"

        row = Adw.ActionRow(
            title=GLib.markup_escape_text(module.name),
            subtitle=GLib.markup_escape_text(subtitle),
        )
        row.set_subtitle_lines(4)

        icon = Gtk.Image.new_from_icon_name(
            "dialog-error-symbolic" if level == "refused"
            else "dialog-warning-symbolic" if level == "caution"
            else "package-x-generic-symbolic"
        )
        icon.add_css_class(css)
        row.add_prefix(icon)

        if level == "refused":
            row.set_sensitive(False)
            badge = Gtk.Label(label=label)
            badge.add_css_class("caption")
            badge.add_css_class("dim-label")
            badge.set_valign(Gtk.Align.CENTER)
            row.add_suffix(badge)
            return row

        check = Gtk.CheckButton(
            active=module.name in self.window.module_blacklist, valign=Gtk.Align.CENTER
        )
        check.set_tooltip_text("Stage this module for blacklisting")
        check.connect("toggled", self._on_select, module.name)
        row.add_suffix(check)
        return row

    # -- handlers -------------------------------------------------------- #

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

    def _on_show_all(self, _button: Gtk.Button, total: int) -> None:
        self.window.kmod_limit = total
        self._rebuild()

    def _on_clear(self, _button: Gtk.Button) -> None:
        self.window.module_blacklist.clear()
        self.window._refresh_chrome()
        self._rebuild()

    def _on_select(self, check: Gtk.CheckButton, name: str) -> None:
        if check.get_active():
            try:
                kmod_module.validate(name)
            except kmod_module.ModuleError as exc:
                self.window.toast(str(exc))
                return
            self.window.module_blacklist.add(name)
        else:
            self.window.module_blacklist.discard(name)
        self.window._refresh_chrome()

    @staticmethod
    def _row(title: str, subtitle: str) -> Adw.ActionRow:
        row = Adw.ActionRow(title=GLib.markup_escape_text(title))
        if subtitle:
            row.set_subtitle(GLib.markup_escape_text(subtitle))
        row.set_title_lines(3)
        row.set_subtitle_lines(4)
        return row
