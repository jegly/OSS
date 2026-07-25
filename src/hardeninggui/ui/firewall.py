"""Firewall editor — BUILD_PLAN §4.6.

Default policies and the enabled state come from readable files, so they are on
screen immediately. The rule list lives in root-only files and needs one
privileged read, which is an explicit button rather than a surprise password
prompt when you click the section.

Nothing here touches the firewall directly: edits stage into the window's
pending firewall state and go out through the same review-then-apply path as
everything else.
"""

from __future__ import annotations

import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from .. import privileged, ufw as ufw_module  # noqa: E402

POLICY_LABELS = {
    "deny": "deny (drop silently)",
    "reject": "reject (send refusal)",
    "allow": "allow",
}


class FirewallPage(Gtk.Box):
    """Policies, the rule list, and the quick port blocker."""

    __gtype_name__ = "HardeningFirewallPage"

    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.window = window
        self._updating = False
        self.append(self._build())

    # ------------------------------------------------------------------ #

    @property
    def state(self) -> ufw_module.State:
        return self.window.firewall

    def _changed(self) -> None:
        self.window.firewall_dirty = True
        self.window._refresh_chrome()
        self.window._show_section(self.window.current_section)

    def _build(self) -> Gtk.Widget:
        page = Adw.PreferencesPage()
        page.add(self._status_group())
        page.add(self._policy_group())
        page.add(self._quick_block_group())
        page.add(self._rules_group())
        page.add(self._suggestions_group())
        return page

    # -- status --------------------------------------------------------- #

    def _status_group(self) -> Adw.PreferencesGroup:
        state = self.state
        group = Adw.PreferencesGroup(
            title="Firewall",
            description=(
                "ufw is a front end to the kernel's own packet filter. Everything "
                "here runs through the ufw command; user.rules is never edited."
            ),
        )

        enabled = Adw.SwitchRow(
            title="Firewall enabled",
            subtitle="Turned on last in the transaction, after the policy and rules are in place",
            active=state.enabled,
        )
        enabled.connect("notify::active", self._on_enabled)
        group.add(enabled)
        self.enabled_row = enabled

        logging_row = Adw.ComboRow(
            title="Logging",
            subtitle="Higher levels log more, including accepted traffic",
            model=Gtk.StringList.new(list(ufw_module.LOG_LEVELS)),
        )
        logging_row.set_selected(ufw_module.LOG_LEVELS.index(state.logging))
        logging_row.connect("notify::selected", self._on_logging)
        group.add(logging_row)
        self.logging_row = logging_row
        return group

    def _on_enabled(self, row: Adw.SwitchRow, *_args) -> None:
        if self._updating:
            return
        self.state.enabled = row.get_active()
        self._changed()

    def _on_logging(self, row: Adw.ComboRow, *_args) -> None:
        if self._updating:
            return
        self.state.logging = ufw_module.LOG_LEVELS[row.get_selected()]
        self._changed()

    # -- default policies ------------------------------------------------ #

    def _policy_group(self) -> Adw.PreferencesGroup:
        group = Adw.PreferencesGroup(
            title="Default policies",
            description=(
                "What happens to traffic no rule matches. Deny incoming is the "
                "single highest-value change here; deny outgoing is stricter but "
                "needs allowances for DNS, NTP and updates or things break quietly."
            ),
        )

        self.policy_rows: dict[str, Adw.ComboRow] = {}
        for attribute, title, subtitle in (
            ("default_incoming", "Incoming", "Connections from the network to this machine"),
            ("default_outgoing", "Outgoing", "Connections from this machine to the network"),
            ("default_routed", "Routed", "Traffic forwarded through this machine"),
        ):
            row = Adw.ComboRow(
                title=title,
                subtitle=subtitle,
                model=Gtk.StringList.new([POLICY_LABELS[p] for p in ufw_module.POLICIES]),
            )
            row.set_selected(ufw_module.POLICIES.index(getattr(self.state, attribute)))
            row.connect("notify::selected", self._on_policy, attribute)
            group.add(row)
            self.policy_rows[attribute] = row

        preset = Adw.ActionRow(
            title="Deny all incoming",
            subtitle="The usual desktop posture: nothing reaches you unless you asked for it",
        )
        button = Gtk.Button(label="Apply posture", valign=Gtk.Align.CENTER)
        button.connect("clicked", self._on_deny_incoming)
        preset.add_suffix(button)
        group.add(preset)
        return group

    def _on_policy(self, row: Adw.ComboRow, _param, attribute: str) -> None:
        if self._updating:
            return
        setattr(self.state, attribute, ufw_module.POLICIES[row.get_selected()])
        self._changed()

    def _on_deny_incoming(self, _button: Gtk.Button) -> None:
        self.state.default_incoming = "deny"
        self.state.default_routed = "deny"
        self.state.enabled = True
        self._changed()

    # -- quick block ----------------------------------------------------- #

    def _quick_block_group(self) -> Adw.PreferencesGroup:
        group = Adw.PreferencesGroup(
            title="Block a port",
            description=(
                "Adds a deny rule for one port. Under a default-deny policy an "
                "explicit deny is already covered — it is worth adding anyway only "
                "if you want it to hold its position above a later allow."
            ),
        )

        entry_row = Adw.ActionRow(title="Custom port")
        self.port_entry = Gtk.Entry(placeholder_text="443 or 6000:6010", width_chars=12)
        self.port_entry.set_valign(Gtk.Align.CENTER)
        self.proto_drop = Gtk.DropDown.new_from_strings(["tcp", "udp", "any"])
        self.proto_drop.set_valign(Gtk.Align.CENTER)
        self.dir_drop = Gtk.DropDown.new_from_strings(["in", "out"])
        self.dir_drop.set_valign(Gtk.Align.CENTER)
        self.action_drop = Gtk.DropDown.new_from_strings(list(ufw_module.ACTIONS))
        self.action_drop.set_selected(1)  # deny
        self.action_drop.set_valign(Gtk.Align.CENTER)

        add = Gtk.Button(label="Add rule", valign=Gtk.Align.CENTER)
        add.add_css_class("suggested-action")
        add.connect("clicked", self._on_add_custom)

        for widget in (self.port_entry, self.proto_drop, self.dir_drop, self.action_drop, add):
            entry_row.add_suffix(widget)
        group.add(entry_row)

        flow = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE)
        flow.set_max_children_per_line(4)
        flow.set_column_spacing(6)
        flow.set_row_spacing(6)
        flow.set_margin_top(6)
        flow.set_margin_bottom(6)
        for port, proto, label in ufw_module.COMMON_PORTS:
            button = Gtk.Button(label=f"{label}  {port}/{proto}")
            button.set_tooltip_text(f"Add: deny in {port}/{proto}")
            button.connect("clicked", self._on_add_common, port, proto, label)
            flow.append(button)

        holder = Adw.PreferencesRow(activatable=False, selectable=False)
        holder.set_child(flow)
        group.add(holder)
        return group

    def _on_add_common(self, _button, port: str, proto: str, label: str) -> None:
        self._add_rule(
            ufw_module.Rule("deny", "in", port, proto, comment=label)
        )

    def _on_add_custom(self, _button: Gtk.Button) -> None:
        rule = ufw_module.Rule(
            action=ufw_module.ACTIONS[self.action_drop.get_selected()],
            direction=("in", "out")[self.dir_drop.get_selected()],
            port=self.port_entry.get_text().strip(),
            proto=("tcp", "udp", "any")[self.proto_drop.get_selected()],
        )
        self._add_rule(rule)

    def _add_rule(self, rule: ufw_module.Rule) -> None:
        try:
            rule.validate()
        except ufw_module.UfwError as exc:
            self.window.toast(str(exc))
            return
        if any(existing.key() == rule.key() for existing in self.state.rules):
            self.window.toast(f"There is already a rule for {rule.summary}.")
            return
        self.state.rules.append(rule)
        self.port_entry.set_text("")
        self._changed()

    # -- rule list ------------------------------------------------------- #

    def _rules_group(self) -> Adw.PreferencesGroup:
        state = self.state
        group = Adw.PreferencesGroup(title="Rules")

        if not state.rules_loaded:
            row = Adw.ActionRow(
                title="Rules have not been read yet",
                subtitle=(
                    "The rule list lives in /etc/ufw/user.rules, which is readable "
                    "only by root. Reading it asks for your password once and "
                    "writes nothing."
                ),
            )
            row.set_subtitle_lines(3)
            button = Gtk.Button(label="Read rules", valign=Gtk.Align.CENTER)
            button.add_css_class("suggested-action")
            button.connect("clicked", self._on_load_rules)
            row.add_suffix(button)
            group.add(row)
            return group

        redundant = {r.key() for r in state.redundant_rules()}
        active = [r for r in state.rules if r.key() not in redundant and not r.v6]
        folded = [r for r in state.rules if r.key() in redundant and not r.v6]

        group.set_description(
            f"{len(active)} rule(s) doing something, {len(folded)} that only "
            f"restate the default policy."
        )

        if not active and not folded:
            group.add(Adw.ActionRow(title="No rules", subtitle="Only the default policies apply."))

        for rule in active:
            group.add(self._rule_row(rule))

        if folded:
            expander = Adw.ExpanderRow(
                title=f"{len(folded)} rule(s) redundant with the default policy",
                subtitle=(
                    "These deny traffic the default policy already denies. Keeping "
                    "them is harmless; they hold their position above any later allow."
                ),
            )
            for rule in folded:
                expander.add_row(self._rule_row(rule))
            clean = Gtk.Button(label="Remove all", valign=Gtk.Align.CENTER)
            clean.add_css_class("destructive-action")
            clean.connect("clicked", self._on_clean_redundant, folded)
            expander.add_suffix(clean)
            group.add(expander)
        return group

    def _rule_row(self, rule: ufw_module.Rule) -> Adw.ActionRow:
        row = Adw.ActionRow(title=rule.summary)
        if rule.comment:
            row.set_subtitle(GLib.markup_escape_text(rule.comment))
        remove = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER)
        remove.add_css_class("flat")
        remove.set_tooltip_text("Stage this rule for removal")
        remove.connect("clicked", self._on_remove_rule, rule)
        row.add_suffix(remove)
        return row

    def _on_remove_rule(self, _button, rule: ufw_module.Rule) -> None:
        self.state.rules = [r for r in self.state.rules if r.key() != rule.key()]
        self._changed()

    def _on_clean_redundant(self, _button, folded: list) -> None:
        keys = {r.key() for r in folded}
        self.state.rules = [r for r in self.state.rules if r.key() not in keys]
        self.window.toast(f"Staged removal of {len(keys)} redundant rule(s).")
        self._changed()

    def _on_load_rules(self, button: Gtk.Button) -> None:
        button.set_sensitive(False)
        button.set_label("Reading…")

        def worker() -> None:
            outcome = privileged.read_firewall()
            GLib.idle_add(self._rules_loaded, outcome)

        threading.Thread(target=worker, daemon=True).start()

    def _rules_loaded(self, outcome: privileged.ApplyOutcome) -> bool:
        if not outcome.ok:
            self.window.toast(outcome.error or "Could not read the firewall.")
            self.window._show_section(self.window.current_section)
            return False
        try:
            state = ufw_module.from_payload(outcome.firewall)
        except ufw_module.UfwError as exc:
            self.window.toast(f"The firewall reported something unexpected: {exc}")
            return False
        self.window.firewall = state
        self.window.firewall_baseline = state.copy()
        self.window.firewall_dirty = False
        self.window.toast(f"Read {len(state.rules)} rule(s).")
        self.window._show_section(self.window.current_section)
        return False

    # -- suggestions ----------------------------------------------------- #

    def _suggestions_group(self) -> Adw.PreferencesGroup | None:
        missing = self.state.missing_recommended()
        group = Adw.PreferencesGroup(
            title="Outbound allowances",
            description=(
                "With a default-deny outgoing policy these three are what break, "
                "and they break quietly rather than with an error."
            ),
        )
        if not missing:
            if self.state.default_outgoing == "allow":
                group.set_description(
                    "Outgoing is set to allow, so nothing outbound needs an "
                    "explicit rule. These become relevant if you switch it to deny."
                )
                return group
            group.add(
                Adw.ActionRow(
                    title="All three are allowed",
                    subtitle="NTP, DNS-over-TLS and DHCP can get out.",
                )
            )
            return group

        for rule, why in missing:
            row = Adw.ActionRow(title=f"Allow {rule.summary}", subtitle=why)
            row.set_subtitle_lines(3)
            button = Gtk.Button(label="Add", valign=Gtk.Align.CENTER)
            button.connect("clicked", lambda _b, r=rule: self._add_rule(r))
            row.add_suffix(button)
            group.add(row)
        return group
