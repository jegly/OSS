"""The staged selection — what the grid, the counter and Apply all read from.

Staging is deliberately separate from the live system: toggling a card changes
nothing until Apply. The baseline is what the machine already has, so the
"N changed" counter means *changes you are about to make*, not *flags that
are on*.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .catalogue import Catalogue, Flag
from .probe import State, SystemFacts, all_states


@dataclass
class Staging:
    """Selected flag values, plus the baseline they are compared against."""

    catalogue: Catalogue
    #: flag id -> value the user has staged.
    selection: dict[str, str] = field(default_factory=dict)
    #: flag id -> value already in effect on this machine, at startup.
    baseline: dict[str, str] = field(default_factory=dict)
    #: Name of the preset the selection started from, for the header label.
    preset_name: str = ""
    #: Listeners called whenever the selection changes.
    _listeners: list = field(default_factory=list, repr=False)

    # -- construction ------------------------------------------------------ #

    @classmethod
    def from_system(cls, catalogue: Catalogue, facts: SystemFacts) -> "Staging":
        """Start from what *this app's own files* declare — nothing else.

        Seeding from everything currently in effect looks helpful and is a trap:
        on a machine hardened by hand, 248 settings live in the user's own files,
        so the first toggle of anything would drag all 248 into our drop-in and
        write four files the user never asked to touch. The staged selection is a
        statement of intent about what this app will write, so it starts as only
        what this app has already written.

        Settings in effect from elsewhere still *show* as applied — the status dot
        reads the live system (§6). Adopting them is a deliberate act: the
        dashboard's vendor-layer migration, or Capture.
        """
        states = all_states(catalogue, facts)
        baseline = {
            flag_id: state.on_disk
            for flag_id, state in states.items()
            if state.on_disk is not None
        }
        return cls(catalogue=catalogue, selection=dict(baseline), baseline=baseline)

    # -- listeners --------------------------------------------------------- #

    def connect(self, callback) -> None:
        self._listeners.append(callback)

    def _notify(self) -> None:
        for callback in self._listeners:
            callback(self)

    # -- queries ----------------------------------------------------------- #

    def is_set(self, flag_id: str) -> bool:
        return flag_id in self.selection

    def value(self, flag_id: str) -> str | None:
        return self.selection.get(flag_id)

    def is_changed(self, flag_id: str) -> bool:
        """Whether this flag differs from what the machine already has."""
        return self.selection.get(flag_id) != self.baseline.get(flag_id)

    def changed_ids(self) -> list[str]:
        ids = set(self.selection) | set(self.baseline)
        return sorted(i for i in ids if self.is_changed(i))

    @property
    def changed_count(self) -> int:
        return len(self.changed_ids())

    def changed_in_section(self, section_id: str) -> int:
        return sum(
            1
            for flag_id in self.changed_ids()
            if (flag := self.catalogue.get(flag_id)) and flag.section == section_id
        )

    def one_way_staged(self) -> list[Flag]:
        """Irreversible flags among the *changes* — what the review must gate on."""
        out = []
        for flag_id in self.changed_ids():
            flag = self.catalogue.get(flag_id)
            value = self.selection.get(flag_id)
            if flag and value is not None and flag.is_one_way_at(value):
                out.append(flag)
        return out

    def breaking_staged(self) -> list[Flag]:
        out = []
        for flag_id in self.changed_ids():
            flag = self.catalogue.get(flag_id)
            if flag and flag_id in self.selection and flag.risk == "breaking":
                out.append(flag)
        return out

    def reboot_staged(self) -> list[Flag]:
        out = []
        for flag_id in self.changed_ids():
            flag = self.catalogue.get(flag_id)
            if flag and flag_id in self.selection and flag.reboot:
                out.append(flag)
        return out

    # -- mutation ---------------------------------------------------------- #

    def set(self, flag_id: str, value: str | None) -> None:
        """Stage *value* for a flag, or unstage it with ``None``."""
        flag = self.catalogue.get(flag_id)
        if flag is None:
            return
        section = self.catalogue.section(flag.section)
        if not section.implemented:
            return
        if value is None:
            self.selection.pop(flag_id, None)
        else:
            if not flag.value_is_allowed(value):
                raise ValueError(f"{value!r} is not an allowed value for {flag_id}")
            self.selection[flag_id] = value
        self._notify()

    def toggle(self, flag_id: str) -> None:
        if self.is_set(flag_id):
            self.set(flag_id, None)
        else:
            flag = self.catalogue.get(flag_id)
            if flag is not None:
                self.set(flag_id, flag.value)

    def set_many(self, values: dict[str, str | None], preset_name: str = "") -> None:
        """Stage a whole preset in one notification."""
        for flag_id, value in values.items():
            flag = self.catalogue.get(flag_id)
            if flag is None:
                continue
            section = self.catalogue.section(flag.section)
            if not section.implemented:
                continue
            if value is None:
                self.selection.pop(flag_id, None)
            elif flag.value_is_allowed(value):
                self.selection[flag_id] = value
        if preset_name:
            self.preset_name = preset_name
        self._notify()

    def select_group(self, section_id: str, group: str, on: bool) -> None:
        """The `select all (33)` control on a group header."""
        section = self.catalogue.section(section_id)
        for flag in section.flags:
            if flag.group != group:
                continue
            # Never mass-enable something irreversible: those stay deliberate.
            if on and flag.is_one_way_at(flag.value):
                continue
            self.selection[flag.id] = flag.value if on else None
            if not on:
                self.selection.pop(flag.id, None)
        self._notify()

    def group_is_full(self, section_id: str, group: str) -> bool:
        section = self.catalogue.section(section_id)
        flags = [f for f in section.flags if f.group == group and not f.is_one_way_at(f.value)]
        return bool(flags) and all(f.id in self.selection for f in flags)

    def reset_to_baseline(self) -> None:
        self.selection = dict(self.baseline)
        self.preset_name = ""
        self._notify()

    def rebaseline(self, facts: SystemFacts) -> None:
        """After a successful Apply, the machine *is* the new baseline."""
        fresh = Staging.from_system(self.catalogue, facts)
        self.baseline = fresh.baseline
        self._notify()
