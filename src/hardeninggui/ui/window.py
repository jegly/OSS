"""The main window — header, sidebar, card grid, footer.

Follows GUI_MOCKUP.html: preset picker and "N changed" counter in the header,
sections grouped under System/Network/Access/Monitoring/Desktop in the sidebar
with per-section badges, filter chips under the header, a grid of toggle cards,
the in-section navigation strip at the bottom of the grid, and a sticky footer
with the "asks for password" lock hint beside Review and Apply.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from .. import presets as presets_module  # noqa: E402
from .. import probe, settings as settings_module, ufw as ufw_module  # noqa: E402
from ..catalogue import Catalogue, Section  # noqa: E402
from ..probe import State  # noqa: E402
from ..staging import Staging  # noqa: E402
from .cards import FlagCard, GroupHeader  # noqa: E402

DASHBOARD = "__dashboard__"
OVERVIEW = "__overview__"

#: Sidebar badge glyphs, matching the mockup's amber ◐ / red ◍.
BADGE_REBOOT = "◐"
BADGE_DRIFT = "◍"

FILTERS = [
    ("changed", "Only flags you have changed"),
    ("drift", "Live value disagrees with our file"),
    ("needs reboot", "Takes effect after a reboot"),
    ("one-way", "Cannot be undone once applied"),
    ("not applied", "Not currently in effect"),
    ("hide risky", "Hide anything that can break something"),
]


class MainWindow(Adw.ApplicationWindow):
    """Everything the user sees, minus the dialogs."""

    __gtype_name__ = "HardeningMainWindow"

    def __init__(
        self,
        application: Adw.Application,
        catalogue: Catalogue,
        facts: probe.SystemFacts,
        staging: Staging,
        style_manager,
        app_settings,
    ) -> None:
        super().__init__(application=application, title="Hardening settings")
        self.catalogue = catalogue
        self.facts = facts
        self.staging = staging
        self.style_manager = style_manager
        self.app_settings = app_settings

        # Firewall state is edited directly rather than through the flag
        # catalogue: a rule list is not a set of toggles.
        self.firewall = ufw_module.read_unprivileged()
        self.firewall_baseline = self.firewall.copy()
        self.firewall_dirty = False

        self.states = probe.all_states(catalogue, facts, staging.selection)
        self.unaffected = probe.unaffected_mitigations(catalogue, facts)
        self.current_section = OVERVIEW
        self.search_text = ""
        self.active_filters: set[str] = set()
        self._cards: list[FlagCard] = []
        self._group_headers: list[GroupHeader] = []
        self._flows: list[Gtk.FlowBox] = []
        self._sidebar_rows: dict[str, Gtk.Box] = {}
        self._columns = 0

        self.set_default_size(1100, 760)
        self._build()

        self.staging.connect(self._on_staging_changed)
        self._show_section(DASHBOARD)

        # GtkWidget has no notifiable width, so the reflow is driven from the
        # window's own size properties plus a re-check once it is first mapped.
        for prop in ("default-width", "maximized", "fullscreened"):
            self.connect(f"notify::{prop}", lambda *_: self._apply_columns())
        self.connect("map", lambda *_: GLib.idle_add(self._apply_columns))

    # ------------------------------------------------------------------ #
    #  Construction
    # ------------------------------------------------------------------ #

    def _build(self) -> None:
        self.split = Adw.NavigationSplitView()
        self.split.set_min_sidebar_width(190)
        self.split.set_max_sidebar_width(240)
        self.split.set_sidebar(self._build_sidebar())
        self.split.set_content(self._build_content())
        self.set_content(self.split)

    # -- sidebar ------------------------------------------------------- #

    def _build_sidebar(self) -> Adw.NavigationPage:
        self.sidebar_list = Gtk.ListBox()
        self.sidebar_list.add_css_class("navigation-sidebar")
        self.sidebar_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.sidebar_list.connect("row-selected", self._on_sidebar_selected)

        self._add_sidebar_row(DASHBOARD, "Dashboard", header=False)
        self._add_sidebar_row(OVERVIEW, "Overview", header=False)
        for nav, sections in self.catalogue.nav_groups():
            self._add_sidebar_header(nav)
            for section in sections:
                self._add_sidebar_row(section.id, section.title)

        scroller = Gtk.ScrolledWindow(child=self.sidebar_list, vexpand=True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        toolbar = Adw.ToolbarView(content=scroller)
        toolbar.add_top_bar(Adw.HeaderBar(show_title=False))
        return Adw.NavigationPage(child=toolbar, title="Sections")

    def _add_sidebar_header(self, text: str) -> None:
        label = Gtk.Label(label=text.upper(), xalign=0)
        label.add_css_class("dim-label")
        label.add_css_class("caption")
        label.set_margin_top(10)
        label.set_margin_start(10)
        label.set_margin_bottom(2)
        row = Gtk.ListBoxRow(child=label, selectable=False, activatable=False)
        self.sidebar_list.append(row)

    def _add_sidebar_row(self, section_id: str, title: str, header: bool = True) -> None:
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        box.set_margin_start(8)
        box.set_margin_end(8)
        box.set_margin_top(5)
        box.set_margin_bottom(5)

        label = Gtk.Label(label=title, xalign=0, hexpand=True)
        box.append(label)

        badge = Gtk.Label(label="")
        badge.add_css_class("caption")
        box.append(badge)

        row = Gtk.ListBoxRow(child=box)
        row.section_id = section_id  # type: ignore[attr-defined]
        self.sidebar_list.append(row)
        self._sidebar_rows[section_id] = badge

    # -- content ------------------------------------------------------- #

    def _build_content(self) -> Adw.NavigationPage:
        self.header = Adw.HeaderBar()

        self.preset_button = Gtk.MenuButton(label="No preset")
        self.preset_button.set_menu_model(self._preset_menu())
        self.preset_button.set_tooltip_text("Load a preset, capture this system, or save your selection")
        self.header.pack_start(self.preset_button)

        self.search_entry = Gtk.SearchEntry(placeholder_text="Search flags")
        self.search_entry.set_max_width_chars(22)
        self.search_entry.connect("search-changed", self._on_search)
        self.header.pack_start(self.search_entry)
        self.header.pack_start(self._build_filter_menu())

        self.counter = Gtk.Label(label="")
        self.header.pack_end(self._menu_button())
        self.header.pack_end(self.counter)


        self.section_title = Gtk.Label(xalign=0)
        self.section_title.add_css_class("title-4")
        self.section_subtitle = Gtk.Label(xalign=0, wrap=True)
        self.section_subtitle.add_css_class("dim-label")
        self.section_subtitle.add_css_class("caption")

        heading = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        heading.set_margin_start(12)
        heading.set_margin_end(12)
        heading.set_margin_top(10)
        heading.append(self.section_title)
        heading.append(self.section_subtitle)

        self.grid_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.grid_box.set_margin_start(12)
        self.grid_box.set_margin_end(12)
        self.grid_box.set_margin_top(10)
        self.grid_box.set_margin_bottom(12)

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        body.append(heading)
        body.append(self.grid_box)

        self.scroller = Gtk.ScrolledWindow(child=body, vexpand=True)
        self.scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.scroller.add_css_class("content-pane")

        toolbar = Adw.ToolbarView(content=self.scroller)
        toolbar.add_top_bar(self.header)
        toolbar.add_bottom_bar(self._build_footer())

        self.toast_overlay = Adw.ToastOverlay(child=toolbar)
        return Adw.NavigationPage(child=self.toast_overlay, title="Hardening settings")

    def _build_footer(self) -> Gtk.Widget:
        footer = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        footer.set_margin_start(12)
        footer.set_margin_end(12)
        footer.set_margin_top(8)
        footer.set_margin_bottom(8)

        lock = Gtk.Label(label="\U0001f512 asks for password")
        lock.add_css_class("lock-hint")
        footer.append(lock)

        self.reboot_hint = Gtk.Label(label="")
        self.reboot_hint.add_css_class("reboot-hint")
        footer.append(self.reboot_hint)

        spacer = Gtk.Box(hexpand=True)
        footer.append(spacer)

        self.revert_button = Gtk.Button(label="Discard changes")
        self.revert_button.add_css_class("flat")
        self.revert_button.connect("clicked", self._on_discard)
        footer.append(self.revert_button)

        self.review_button = Gtk.Button(label="Review")
        self.review_button.connect("clicked", self._on_review)
        footer.append(self.review_button)

        self.apply_button = Gtk.Button(label="Apply")
        self.apply_button.add_css_class("suggested-action")
        self.apply_button.connect("clicked", self._on_apply)
        footer.append(self.apply_button)

        return footer

    def _build_filter_menu(self) -> Gtk.MenuButton:
        """The filter chips, folded into one small button so they stay out of the way."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        box.set_margin_top(6)
        box.set_margin_bottom(6)
        box.set_margin_start(6)
        box.set_margin_end(6)

        self.filter_buttons: dict[str, Gtk.CheckButton] = {}
        for name, tooltip in FILTERS:
            check = Gtk.CheckButton(label=name)
            check.set_tooltip_text(tooltip)
            check.connect("toggled", self._on_filter, name)
            box.append(check)
            self.filter_buttons[name] = check

        clear = Gtk.Button(label="Clear filters")
        clear.add_css_class("flat")
        clear.set_margin_top(4)
        clear.connect("clicked", self._on_clear_filters)
        box.append(clear)

        popover = Gtk.Popover(child=box)
        self.filter_button = Gtk.MenuButton(popover=popover)
        # Not "funnel-symbolic" — that one is missing from the icon theme here
        # and renders as the broken-image glyph.
        self.filter_button.set_icon_name("view-sort-descending-symbolic")
        self.filter_button.set_tooltip_text("Filter which flags are shown")
        return self.filter_button

    def _on_clear_filters(self, _button: Gtk.Button) -> None:
        for check in self.filter_buttons.values():
            check.set_active(False)

    def _refresh_filter_button(self) -> None:
        count = len(self.active_filters)
        self.filter_button.set_label(f"{count}" if count else "")
        if count:
            self.filter_button.add_css_class("suggested-action")
        else:
            self.filter_button.remove_css_class("suggested-action")

    def _menu_button(self) -> Gtk.MenuButton:
        menu = Gio.Menu()
        view = Gio.Menu()
        view.append("Appearance…", "app.appearance")
        menu.append_section(None, view)
        help_section = Gio.Menu()
        help_section.append("About", "app.about")
        menu.append_section(None, help_section)

        button = Gtk.MenuButton(icon_name="open-menu-symbolic")
        button.set_menu_model(menu)
        return button

    def _preset_menu(self) -> Gio.Menu:
        menu = Gio.Menu()
        shipped = Gio.Menu()
        for preset in presets_module.available():
            shipped.append(preset.name.title(), f"app.preset::{preset.key}")
        menu.append_section("Presets", shipped)

        actions = Gio.Menu()
        actions.append("Capture this system…", "app.capture")
        actions.append("Save selection as preset…", "app.save-preset")
        menu.append_section(None, actions)
        return menu

    # ------------------------------------------------------------------ #
    #  Section rendering
    # ------------------------------------------------------------------ #

    def _on_sidebar_selected(self, _list: Gtk.ListBox, row: Gtk.ListBoxRow | None) -> None:
        if row is None or not hasattr(row, "section_id"):
            return
        if row.section_id == self.current_section:
            return
        self._show_section(row.section_id)

    def _sync_sidebar_selection(self, section_id: str) -> None:
        """Keep the sidebar highlight on the section actually being shown.

        The ListBox selects its first row when it is realized, which would
        otherwise fire row-selected and drag the view back to Overview.
        """
        index = 0
        while (row := self.sidebar_list.get_row_at_index(index)) is not None:
            if getattr(row, "section_id", None) == section_id:
                if self.sidebar_list.get_selected_row() is not row:
                    self.sidebar_list.select_row(row)
                return
            index += 1

    def _show_section(self, section_id: str) -> None:
        self.current_section = section_id
        self._sync_sidebar_selection(section_id)
        child = self.grid_box.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self.grid_box.remove(child)
            child = nxt
        self._cards.clear()
        self._group_headers.clear()
        self._flows.clear()

        if section_id == DASHBOARD:
            from .dashboard import Dashboard

            self.section_title.set_label("Dashboard")
            self.section_subtitle.set_label(
                "How this machine is configured right now, where each setting "
                "comes from, and what is quietly wrong with it."
            )
            self.grid_box.append(Dashboard(self))
            self._refresh_chrome()
            return

        if section_id == OVERVIEW:
            self.section_title.set_label("Overview")
            self.section_subtitle.set_label(
                "Every flag in the catalogue, grouped by area. Enable anything from "
                "here — it stages exactly as it would in its own section."
            )
            groups = self.catalogue.by_group()
        else:
            section = self.catalogue.section(section_id)
            self.section_title.set_label(section.title)
            self.section_subtitle.set_label(section.desc)
            if section_id == "ufw":
                from .firewall import FirewallPage

                self.grid_box.append(FirewallPage(self))
                self._refresh_chrome()
                return
            if not section.implemented:
                self._show_pending(section)
                return
            groups = [
                (section.id, group, [f for f in section.flags if f.group == group])
                for group in section.group_order
            ]

        shown = 0
        for owner_id, group, flags in groups:
            visible = [f for f in flags if self._passes_filters(f)]
            if not visible:
                continue
            section = self.catalogue.section(owner_id)
            header = GroupHeader(section, group, self.staging)
            self._group_headers.append(header)
            self.grid_box.append(header)

            flow = Gtk.FlowBox()
            flow.set_selection_mode(Gtk.SelectionMode.NONE)
            flow.set_homogeneous(True)
            flow.set_column_spacing(8)
            flow.set_row_spacing(8)
            self._flows.append(flow)
            for flag in visible:
                card = FlagCard(
                    flag,
                    section,
                    self.staging,
                    self.states.get(flag.id),
                    self._unavailable_reason(section, flag),
                )
                self._cards.append(card)
                flow.append(card)
            self.grid_box.append(flow)
            shown += len(visible)

        if shown == 0:
            self.grid_box.append(self._empty_state())
        elif section_id != OVERVIEW:
            self.grid_box.append(self._section_footer_strip(section_id))

        self._apply_columns()
        self._refresh_chrome()

    #: Minimum card width from the mockup's `minmax(220px, 1fr)`, plus the 8px gap.
    CARD_MIN = 220
    CARD_GAP = 8

    def _column_count(self) -> int:
        """How many 220px cards fit across the content pane, capped at 3."""
        width = self.grid_box.get_width() or (self.get_width() - 260)
        fits = (width + self.CARD_GAP) // (self.CARD_MIN + self.CARD_GAP)
        return max(1, min(3, int(fits)))

    def _apply_columns(self) -> None:
        """Pin the grid to a column count derived from the pane width.

        A FlowBox picks its own column count from each child's *natural* width,
        which for these cards is wide enough that it settles on two and then
        stretches them. Setting min and max to the same number makes the
        breakpoints behave like the mockup's `repeat(auto-fit, minmax(220px, 1fr))`.
        """
        columns = self._column_count()
        self._columns = columns
        for flow in self._flows:
            flow.set_min_children_per_line(columns)
            flow.set_max_children_per_line(columns)

    def _show_pending(self, section: Section) -> None:
        """A section whose dedicated editor is not built yet — say so plainly."""
        status = Adw.StatusPage(
            title=f"{section.title} is not wired up yet",
            icon_name="applications-engineering-symbolic",
        )
        status.set_description(
            f"{section.desc}\n\nThis section needs its own editor rather than a "
            f"grid of toggles, so it is specified but not built. It stages nothing "
            f"and cannot contribute to an Apply — see BUILD_PLAN {section.plan_ref}."
        )
        status.set_vexpand(True)
        self.grid_box.append(status)
        self._refresh_chrome()

    def _empty_state(self) -> Gtk.Widget:
        status = Adw.StatusPage(
            title="Nothing matches",
            description="No flag here matches the search and filters.",
            icon_name="system-search-symbolic",
        )
        status.set_vexpand(True)
        return status

    def _section_footer_strip(self, section_id: str) -> Gtk.Widget:
        """`namespaces / apparmor · network · 19 more in this section` (mockup)."""
        strip = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        strip.add_css_class("section-footer")
        strip.set_margin_top(4)

        section = self.catalogue.section(section_id)
        groups = section.group_order
        for index, group in enumerate(groups[:3]):
            if index:
                strip.append(Gtk.Label(label="·"))
            button = Gtk.Button(label=group)
            button.add_css_class("flat")
            button.connect("clicked", self._on_jump_to_group, group)
            strip.append(button)
        if len(groups) > 3:
            more = Gtk.Label(label=f"{len(groups) - 3} more in this section")
            more.add_css_class("dim-label")
            strip.append(more)

        strip.append(Gtk.Box(hexpand=True))
        for glyph, text, css in (
            ("●", "applied", "status-applied"),
            ("◐", "reboot", "status-pending-reboot"),
            ("◍", "drift", "status-differs"),
        ):
            legend = Gtk.Label(label=f"{glyph} {text}")
            legend.add_css_class(css)
            legend.add_css_class("caption")
            strip.append(legend)
        return strip

    def _on_jump_to_group(self, _button: Gtk.Button, group: str) -> None:
        for header in self._group_headers:
            if header.group == group:
                header.grab_focus()
                break

    # ------------------------------------------------------------------ #
    #  Filtering
    # ------------------------------------------------------------------ #

    def _passes_filters(self, flag) -> bool:
        if self.search_text:
            haystack = " ".join(
                [flag.id, flag.key, flag.title, flag.desc, flag.why, flag.group]
            ).lower()
            if self.search_text not in haystack:
                return False

        state = self.states.get(flag.id)
        if "changed" in self.active_filters and not self.staging.is_changed(flag.id):
            return False
        if "drift" in self.active_filters and (
            state is None or state.state is not State.DIFFERS
        ):
            return False
        if "needs reboot" in self.active_filters and not flag.reboot:
            return False
        if "one-way" in self.active_filters and not (
            flag.one_way or flag.one_way_values
        ):
            return False
        if "not applied" in self.active_filters and (
            state is not None and state.state is State.APPLIED
        ):
            return False
        if "hide risky" in self.active_filters and flag.risk != "safe":
            return False
        return True

    def _unavailable_reason(self, section: Section, flag) -> str:
        state = self.states.get(flag.id)
        if state is not None and state.state is State.INVALID:
            return state.note
        if flag.id in self.unaffected:
            return (
                "This CPU reports 'Not affected' for the vulnerability this "
                "mitigates, so it would cost performance for nothing."
            )
        if section.requires_pkg and not probe.package_present(section.requires_pkg):
            return (
                f"Needs the {section.requires_pkg} package, which is not installed. "
                f"Install it offline with:  sudo apt install ./{section.requires_pkg}*.deb"
            )
        return ""

    def _on_search(self, entry: Gtk.SearchEntry) -> None:
        self.search_text = entry.get_text().strip().lower()
        self._show_section(self.current_section)

    def _on_filter(self, button: Gtk.CheckButton, name: str) -> None:
        if button.get_active():
            self.active_filters.add(name)
        else:
            self.active_filters.discard(name)
        self._refresh_filter_button()
        self._show_section(self.current_section)

    # ------------------------------------------------------------------ #
    #  Reacting to staging
    # ------------------------------------------------------------------ #

    def _on_staging_changed(self, _staging: Staging) -> None:
        for card in self._cards:
            card.refresh()
        for header in self._group_headers:
            header.refresh()
        self._refresh_chrome()

    def firewall_changes(self) -> list[tuple[list[str], str]]:
        """The ufw commands the staged firewall edits would run."""
        if not self.firewall_dirty:
            return []
        try:
            return ufw_module.plan_commands(self.firewall_baseline, self.firewall)
        except ufw_module.UfwError:
            return []

    def _refresh_chrome(self) -> None:
        count = self.staging.changed_count + len(self.firewall_changes())
        if count:
            self.counter.set_label(f"{count} changed")
            self.counter.add_css_class("changed-counter")
            self.counter.remove_css_class("dim-label")
            self.counter.set_tooltip_text(
                "Changes staged but not yet written. Review shows the exact diff."
            )
        else:
            # Nothing staged. Showing "0 changed" on a machine that is already
            # heavily configured reads as "nothing is set", so show what is
            # actually in effect instead.
            in_effect = sum(
                1
                for state in self.states.values()
                if state.state in (State.APPLIED, State.PENDING_REBOOT)
            )
            self.counter.set_label(f"{in_effect} in effect")
            self.counter.remove_css_class("changed-counter")
            self.counter.add_css_class("dim-label")
            self.counter.set_tooltip_text(
                "Settings already in effect on this machine, however they got "
                "that way. Nothing is staged to change."
            )
        self.apply_button.set_sensitive(count > 0)
        self.review_button.set_sensitive(count > 0)
        self.revert_button.set_sensitive(count > 0)

        reboot = self.staging.reboot_staged()
        self.reboot_hint.set_label(
            f"{BADGE_REBOOT} {len(reboot)} change{'s' if len(reboot) != 1 else ''} "
            "take effect after reboot"
            if reboot
            else ""
        )

        name = self.staging.preset_name
        if name and self.staging.changed_count:
            self.preset_button.set_label(f"{name} (modified)")
        elif name:
            self.preset_button.set_label(name)
        else:
            self.preset_button.set_label("No preset")

        for section in self.catalogue.sections:
            badge = self._sidebar_rows.get(section.id)
            if badge is None:
                continue
            changed = self.staging.changed_in_section(section.id)
            drift = sum(
                1
                for f in section.flags
                if (s := self.states.get(f.id)) and s.state is State.DIFFERS
            )
            pending = sum(
                1
                for f in section.flags
                if (s := self.states.get(f.id)) and s.state is State.PENDING_REBOOT
            )
            if changed:
                badge.set_label(str(changed))
                badge.add_css_class("changed-counter")
            elif drift:
                badge.set_label(f"{BADGE_DRIFT} {drift}")
                badge.remove_css_class("changed-counter")
                badge.add_css_class("status-differs")
            elif pending:
                badge.set_label(f"{BADGE_REBOOT} {pending}")
                badge.remove_css_class("changed-counter")
                badge.add_css_class("status-pending-reboot")
            else:
                badge.set_label("")

    # ------------------------------------------------------------------ #
    #  Actions
    # ------------------------------------------------------------------ #

    def _on_discard(self, _button: Gtk.Button) -> None:
        self.firewall = self.firewall_baseline.copy()
        self.firewall_dirty = False
        self.staging.reset_to_baseline()
        self._show_section(self.current_section)

    def _on_review(self, _button: Gtk.Button) -> None:
        from .review import ReviewDialog

        ReviewDialog(self, apply_callback=None).present()

    def _on_apply(self, _button: Gtk.Button) -> None:
        from .review import ReviewDialog

        ReviewDialog(self, apply_callback=self.run_apply).present()

    def run_apply(self) -> None:
        """Hand the staged selection to the helper, then refresh from the system."""
        from .review import ApplyProgressDialog

        ApplyProgressDialog(self).present()

    def refresh_from_system(self) -> None:
        """Re-probe after an Apply so every dot and badge tells the truth again."""
        self.facts = probe.gather(self.catalogue)
        self.states = probe.all_states(self.catalogue, self.facts, self.staging.selection)
        self.staging.rebaseline(self.facts)
        # Policies re-read from the readable files; rules keep whatever the last
        # privileged read gave us rather than silently reverting to "unknown".
        refreshed = ufw_module.read_unprivileged()
        refreshed.rules = self.firewall.rules
        refreshed.rules_loaded = self.firewall.rules_loaded
        self.firewall = refreshed
        self.firewall_baseline = refreshed.copy()
        self.firewall_dirty = False
        self._show_section(self.current_section)

    def toast(self, message: str, timeout: int = 4) -> None:
        toast = Adw.Toast(title=message, timeout=timeout)
        self.toast_overlay.add_toast(toast)


