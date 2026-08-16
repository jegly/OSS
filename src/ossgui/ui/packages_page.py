"""Installed packages, and removing them.

Removal only — no install path. The point of the page is the thing Synaptic gets
right: you never remove "one package", you remove whatever apt decides comes with
it, and you should see that list before you agree to it.

So the cascade is recomputed from apt every time the selection changes, and shown
here rather than only at review time. Selecting `ubuntu-wallpapers` on this
machine reports that it would also take gdm3 and gnome-shell.
"""

from __future__ import annotations

import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from .. import packages as packages_module  # noqa: E402

#: How many packages to render at a time. The full list is ~1700 rows and
#: building them all makes the page unusable, so this is a page size rather than
#: a ceiling: "Show more" raises the limit, "Show all" removes it, and changing
#: the search or the manual-only toggle drops back to one page.
SHOW_LIMIT = 40


class PackagesPage(Gtk.Box):
    """Search, select, and see what the removal would really do."""

    __gtype_name__ = "OssPackagesPage"

    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.window = window
        if not hasattr(window, "packages"):
            window.packages = packages_module.read_installed()
        self.append(self._build())

    def _rebuild(self) -> None:
        self.window._show_section(self.window.current_section)

    # ------------------------------------------------------------------ #

    def _build(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_margin_bottom(14)

        if not packages_module.available():
            group = Adw.PreferencesGroup(title="Packages")
            group.add(self._row("dpkg is not available", "Nothing to list."))
            box.append(group)
            return box

        box.append(self._summary_group())
        if self.window.package_removals:
            box.append(self._cascade_group())
        box.append(self._list_group())
        return box

    def _summary_group(self) -> Adw.PreferencesGroup:
        installed = self.window.packages
        manual = sum(1 for p in installed.values() if p.manual)
        protected = sum(1 for p in installed.values() if not p.removable)
        return Adw.PreferencesGroup(
            title="Installed packages",
            description=(
                f"{len(installed)} installed. {manual} you asked for; the rest "
                f"arrived as dependencies. {protected} are Essential or "
                f"Priority: required and are not offered for removal at all — "
                f"losing those does not break a feature, it breaks the system.\n\n"
                f"Removal only. Installing is what apt and the software centre "
                f"are for."
            ),
        )

    # -- the cascade ----------------------------------------------------- #

    def _cascade_group(self) -> Adw.PreferencesGroup:
        cascade = getattr(self.window, "package_cascade", None)
        selected = sorted(self.window.package_removals)

        if cascade is None:
            group = Adw.PreferencesGroup(title="Working out what this would remove…")
            group.add(self._row("Asking apt", ", ".join(selected)))
            return group

        if not cascade.ok:
            group = Adw.PreferencesGroup(title="apt refused this removal")
            group.add(self._row(cascade.error, "Nothing has been changed."))
            return group

        collateral = cascade.collateral
        blocked = cascade.blocked_by(self.window.packages)

        title = (
            f"This would remove {len(cascade.removing)} package(s)"
            if collateral
            else f"This would remove {len(cascade.removing)} package(s)"
        )
        group = Adw.PreferencesGroup(
            title=title,
            description=(
                f"You selected {len(selected)}. apt would take "
                f"{len(collateral)} more with them, freeing about "
                f"{cascade.freed_kb / 1024:.0f} MB."
                if collateral
                else f"Nothing else depends on these, so only the "
                f"{len(selected)} you picked would go, freeing about "
                f"{cascade.freed_kb / 1024:.0f} MB."
            ),
        )

        if blocked:
            row = self._row(
                "Refused: this would remove protected packages",
                ", ".join(blocked) + ". Apply will not run this.",
            )
            icon = Gtk.Image.new_from_icon_name("dialog-error-symbolic")
            icon.add_css_class("status-differs")
            row.add_prefix(icon)
            group.add(row)

        if collateral:
            expander = Adw.ExpanderRow(
                title=f"{len(collateral)} package(s) you did not select",
                subtitle="Removed because they depend on your selection.",
            )
            expander.set_expanded(len(collateral) <= 12)
            icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
            icon.add_css_class("status-pending-reboot")
            expander.add_prefix(icon)
            for name in collateral:
                package = self.window.packages.get(name)
                expander.add_row(
                    self._row(name, package.summary if package else "")
                )
            group.add(expander)

        clear = self._row("Clear the selection", "")
        button = Gtk.Button(label="Clear", valign=Gtk.Align.CENTER)
        button.connect("clicked", self._on_clear)
        clear.add_suffix(button)
        group.add(clear)
        return group

    # -- the list -------------------------------------------------------- #

    @property
    def _limit(self) -> int:
        """Rows to render. Lives on the window because the page is rebuilt."""
        return getattr(self.window, "package_limit", SHOW_LIMIT)

    def _visible(self) -> tuple[list, int]:
        search = getattr(self.window, "package_search", "")
        manual_only = getattr(self.window, "package_manual_only", True)

        candidates = [
            p for p in self.window.packages.values()
            if (not manual_only or p.manual) and (not search or search in p.name.lower()
                                                  or search in p.summary.lower())
        ]
        total = len(candidates)
        selected = [p for p in candidates if p.name in self.window.package_removals]
        rest = sorted(
            (p for p in candidates if p.name not in self.window.package_removals),
            key=lambda p: -p.size_kb,
        )
        return (selected + rest)[: self._limit], total

    def _list_group(self) -> Adw.PreferencesGroup:
        shown, total = self._visible()
        group = Adw.PreferencesGroup(
            title="Packages",
            description=f"{total} match. Largest first.",
        )

        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        controls.set_margin_top(4)
        controls.set_margin_bottom(4)
        entry = Gtk.SearchEntry(
            placeholder_text="Search name or description", hexpand=True
        )
        entry.set_text(getattr(self.window, "package_search", ""))
        entry.connect("search-changed", self._on_search)
        controls.append(entry)
        toggle = Gtk.ToggleButton(label="Only what I installed")
        toggle.set_active(getattr(self.window, "package_manual_only", True))
        toggle.set_tooltip_text(
            "Hide packages that arrived as dependencies. Those are better removed "
            "by removing whatever pulled them in."
        )
        toggle.connect("toggled", self._on_manual_toggle)
        controls.append(toggle)
        holder = Adw.PreferencesRow(activatable=False, selectable=False)
        holder.set_child(controls)
        group.add(holder)

        if not shown:
            group.add(self._row("Nothing matches", ""))
            return group

        for package in shown:
            group.add(self._package_row(package))
        remaining = total - len(shown)
        if remaining > 0:
            row = self._row(
                f"{remaining} more package(s)",
                "Search to jump straight to one, or load them here.",
            )
            more = Gtk.Button(
                label=f"Show {min(SHOW_LIMIT, remaining)} more", valign=Gtk.Align.CENTER
            )
            more.connect("clicked", self._on_show_more)
            row.add_suffix(more)

            every = Gtk.Button(label=f"Show all {total}", valign=Gtk.Align.CENTER)
            every.set_tooltip_text(
                "Renders every matching package. Unfiltered that is over a "
                "thousand rows and takes a moment."
            )
            every.connect("clicked", self._on_show_all, total)
            row.add_suffix(every)
            group.add(row)
        return group

    def _package_row(self, package) -> Adw.ActionRow:
        selected = package.name in self.window.package_removals
        subtitle = f"{package.version} · {package.size}"
        if package.summary:
            subtitle += f" · {package.summary}"
        if package.warning:
            subtitle += f"  ⚠ {package.warning}"

        row = Adw.ActionRow(
            title=GLib.markup_escape_text(package.name),
            subtitle=GLib.markup_escape_text(subtitle),
        )
        row.set_subtitle_lines(2)

        if not package.removable:
            row.set_sensitive(False)
            row.set_tooltip_text(package.refusal)
            badge = Gtk.Label(label="protected")
            badge.add_css_class("caption")
            badge.add_css_class("dim-label")
            badge.set_valign(Gtk.Align.CENTER)
            row.add_suffix(badge)
            return row

        if package.warning:
            icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
            icon.add_css_class("status-pending-reboot")
            row.add_prefix(icon)

        check = Gtk.CheckButton(active=selected, valign=Gtk.Align.CENTER)
        check.set_tooltip_text("Select for removal")
        check.connect("toggled", self._on_select, package.name)
        row.add_suffix(check)
        return row

    # -- handlers -------------------------------------------------------- #

    def _on_search(self, entry: Gtk.SearchEntry) -> None:
        self.window.package_search = entry.get_text().strip().lower()
        # A new search starts at one page again: keeping an expanded limit means
        # every keystroke re-renders hundreds of rows.
        self.window.package_limit = SHOW_LIMIT
        self._rebuild()

    def _on_manual_toggle(self, button: Gtk.ToggleButton) -> None:
        self.window.package_manual_only = button.get_active()
        self.window.package_limit = SHOW_LIMIT
        self._rebuild()

    def _on_show_more(self, _button: Gtk.Button) -> None:
        self.window.package_limit = self._limit + SHOW_LIMIT
        self._rebuild()

    def _on_show_all(self, _button: Gtk.Button, total: int) -> None:
        self.window.package_limit = total
        self._rebuild()

    def _on_clear(self, _button: Gtk.Button) -> None:
        self.window.package_removals.clear()
        self.window.package_cascade = None
        self.window._refresh_chrome()
        self._rebuild()

    def _on_select(self, check: Gtk.CheckButton, name: str) -> None:
        if check.get_active():
            self.window.package_removals.add(name)
        else:
            self.window.package_removals.discard(name)
        self.window._refresh_chrome()
        self._recompute()

    def _recompute(self) -> None:
        """Ask apt what the current selection would really do."""
        selection = sorted(self.window.package_removals)
        self.window.package_cascade = None
        if not selection:
            self._rebuild()
            return

        self._rebuild()  # show the "working it out" state

        def worker() -> None:
            cascade = packages_module.simulate_removal(selection)
            GLib.idle_add(self._cascade_ready, cascade)

        threading.Thread(target=worker, daemon=True).start()

    def _cascade_ready(self, cascade) -> bool:
        self.window.package_cascade = cascade
        if cascade.ok and cascade.collateral:
            self.window.toast(
                f"That selection would remove {len(cascade.removing)} packages — "
                f"{len(cascade.collateral)} more than you picked."
            )
        self._rebuild()
        return False

    @staticmethod
    def _row(title: str, subtitle: str) -> Adw.ActionRow:
        row = Adw.ActionRow(title=GLib.markup_escape_text(title))
        if subtitle:
            row.set_subtitle(GLib.markup_escape_text(subtitle))
        row.set_title_lines(2)
        row.set_subtitle_lines(4)
        return row
