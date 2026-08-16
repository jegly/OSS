"""The remaining section pages: sandbox, bootloader, permissions, fstab, usb.

They share a shape — read the current state unprivileged, stage changes into the
window, let Review and Apply do the rest — so they live together rather than in
five near-identical files.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from .. import bootloader as bootloader_module  # noqa: E402
from .. import filemode as filemode_module  # noqa: E402
from .. import fstab as fstab_module  # noqa: E402
from .. import permissions as permissions_module  # noqa: E402
from .. import sandbox as sandbox_module  # noqa: E402
from .. import tpm as tpm_module  # noqa: E402
from .. import usb as usb_module  # noqa: E402


def _column(*groups) -> Gtk.Widget:
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
    box.set_margin_bottom(14)
    for group in groups:
        if group is not None:
            box.append(group)
    return box


def _row(title: str, subtitle: str = "", lines: int = 3) -> Adw.ActionRow:
    row = Adw.ActionRow(title=GLib.markup_escape_text(title))
    if subtitle:
        row.set_subtitle(GLib.markup_escape_text(subtitle))
    row.set_title_lines(2)
    row.set_subtitle_lines(lines)
    return row


# --------------------------------------------------------------------------- #
#  systemd sandboxing (§4.12)
# --------------------------------------------------------------------------- #


class SandboxPage(Gtk.Box):
    """Pick a unit, toggle directives, watch the exposure score move."""

    __gtype_name__ = "OssSandboxPage"

    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.window = window
        if not hasattr(window, "sandbox_overview"):
            window.sandbox_overview = sandbox_module.overview()
        self.append(self._build())

    def _rebuild(self) -> None:
        self.window._show_section(self.window.current_section)

    def _build(self) -> Gtk.Widget:
        return _column(self._picker_group(), self._directives_group())

    def _picker_group(self) -> Adw.PreferencesGroup:
        overview = self.window.sandbox_overview
        group = Adw.PreferencesGroup(
            title="Service sandboxing",
            description=(
                "systemd can confine a service without changing the service itself. "
                "The exposure score is systemd's own: 0 is fully sandboxed, 10 is a "
                "service with nothing standing between it and the system."
            ),
        )

        if not overview:
            group.add(_row("systemd-analyze is not available", "Nothing to score."))
            return group

        names = [name for name, _score, _verdict in overview]
        combo = Adw.ComboRow(
            title="Unit",
            subtitle="Listed worst-exposure first",
            model=Gtk.StringList.new(
                [f"{n}   {s:.1f} {v}" for n, s, v in overview]
            ),
        )
        selected = getattr(self.window, "sandbox_unit", names[0])
        if selected in names:
            combo.set_selected(names.index(selected))
        combo.connect("notify::selected", self._on_unit, names)
        group.add(combo)
        self.window.sandbox_unit = selected
        return group

    def _directives_group(self) -> Adw.PreferencesGroup:
        unit = getattr(self.window, "sandbox_unit", "")
        if not unit:
            return Adw.PreferencesGroup(title="Directives")

        current = set(sandbox_module.read_current(unit))
        staged = self.window.sandbox_changes.get(unit)
        chosen = set(staged) if staged is not None else current
        score, verdict = next(
            ((s, v) for n, s, v in self.window.sandbox_overview if n == unit), (None, "")
        )

        group = Adw.PreferencesGroup(
            title=f"Directives for {unit}",
            description=(
                f"Currently {score:.1f} ({verdict}). "
                if score is not None
                else ""
            )
            + f"{len(current)} already set by this app. Changes are written to "
            f"{sandbox_module.dropin_path(unit)}.",
        )

        for directive in sandbox_module.DIRECTIVES:
            row = Adw.SwitchRow(
                title=directive.title,
                subtitle=f"{directive.desc} — {directive.why}"
                + (f"  Breaks: {directive.breaks}" if directive.breaks else ""),
                active=directive.key in chosen,
            )
            row.set_subtitle_lines(3)
            if directive.risk != "safe":
                badge = Gtk.Label(label=directive.risk)
                badge.add_css_class("risk-badge")
                badge.add_css_class(directive.risk)
                badge.set_valign(Gtk.Align.CENTER)
                row.add_suffix(badge)
            row.connect("notify::active", self._on_directive, unit, directive.key)
            group.add(row)
        return group

    def _on_unit(self, combo: Adw.ComboRow, _param, names: list[str]) -> None:
        index = combo.get_selected()
        if 0 <= index < len(names):
            self.window.sandbox_unit = names[index]
            self._rebuild()

    def _on_directive(self, row: Adw.SwitchRow, _param, unit: str, key: str) -> None:
        current = set(sandbox_module.read_current(unit))
        chosen = set(self.window.sandbox_changes.get(unit, current))
        if row.get_active():
            chosen.add(key)
        else:
            chosen.discard(key)
        if chosen == current:
            self.window.sandbox_changes.pop(unit, None)
        else:
            self.window.sandbox_changes[unit] = sorted(chosen)
        self.window._refresh_chrome()


# --------------------------------------------------------------------------- #
#  Bootloader (§4.23)
# --------------------------------------------------------------------------- #


class TpmPage(Gtk.Box):
    """TPM state, measured boot, and what is actually sealed to it.

    Read-only. Enrolling a disk key is deliberately not offered: getting it
    wrong locks you out of your own disk, the recovery path is a passphrase you
    may not have set, and the operation belongs to systemd-cryptenroll rather
    than to a checkbox. What this page does is tell you where you stand and
    what the exact command would be.
    """

    __gtype_name__ = "OssTpmPage"

    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.window = window
        self.facts = tpm_module.read_facts()
        self.append(self._build())

    def _build(self) -> Gtk.Widget:
        return _column(
            self._device_group(),
            self._findings_group(),
            self._volumes_group(),
        )

    def _device_group(self) -> Adw.PreferencesGroup:
        facts = self.facts
        group = Adw.PreferencesGroup(
            title="The chip",
            description=(
                "A TPM stores keys in hardware and can refuse to release them "
                "unless the machine booted the way it did when they were sealed. "
                "On its own it protects nothing — what matters is what is bound "
                "to it, below."
            ),
        )

        if not facts.present:
            row = _row(
                "No TPM on this machine",
                "/sys/class/tpm is empty, so the kernel registered no TPM. Either "
                "the machine has none, or it is switched off in firmware — worth "
                "checking the setup screen before concluding it is absent.",
                lines=4,
            )
            icon = Gtk.Image.new_from_icon_name("dialog-information-symbolic")
            row.add_prefix(icon)
            group.add(row)
            return group

        group.add(_row(f"TPM {facts.version}", f"/dev/{facts.device}"))
        if facts.description:
            group.add(_row("Reported as", facts.description))
        group.add(
            _row(
                "Resource manager",
                "/dev/tpmrm0 present — several programs can use the TPM at once."
                if facts.has_resource_manager
                else "Absent. Anything using the TPM locks out everything else "
                "while it holds the device open.",
            )
        )
        group.add(
            _row(
                "Measured boot log",
                {
                    "present": "The firmware recorded what it hashed into the PCRs.",
                    "unreadable": "Present but needs root to read.",
                    "absent": "The firmware exposes no event log, so there is no "
                    "record of what was measured.",
                }[facts.event_log],
            )
        )
        if facts.device_mode:
            group.add(_row("Device permissions", f"mode {facts.device_mode}"))
        return group

    def _findings_group(self) -> Adw.PreferencesGroup | None:
        findings = self.facts.findings
        if not findings:
            return None
        group = Adw.PreferencesGroup(title="What this means")
        for severity, message in findings:
            row = _row(message, "", lines=6)
            row.set_title_lines(6)
            icon = Gtk.Image.new_from_icon_name(
                "dialog-warning-symbolic" if severity == "high"
                else "dialog-information-symbolic"
            )
            icon.add_css_class(
                "status-differs" if severity == "high" else "status-not-set"
            )
            row.add_prefix(icon)
            group.add(row)
        return group

    def _volumes_group(self) -> Adw.PreferencesGroup:
        facts = self.facts
        group = Adw.PreferencesGroup(
            title="Encrypted volumes",
            description=(
                "From /etc/crypttab. A volume sealed to the TPM unlocks without a "
                "passphrase, which is convenient and is also the whole risk: "
                "without a PIN, powering the machine on is enough to decrypt it."
            ),
        )

        if not facts.volumes:
            group.add(
                _row(
                    "No encrypted volumes",
                    "/etc/crypttab lists nothing, so there is no disk key for a "
                    "TPM to hold.",
                )
            )
            return group

        for volume in facts.volumes:
            if volume.tpm_bound:
                pin = "with a PIN" if volume.tpm_pin else "with NO PIN"
                pcrs = f", PCRs {volume.pcrs}" if volume.pcrs else ", no PCR binding"
                subtitle = f"{volume.device} — sealed to the TPM {pin}{pcrs}"
            else:
                subtitle = (
                    f"{volume.device} — unlocked by passphrase at boot, not sealed "
                    f"to any hardware"
                )
            row = _row(volume.name, subtitle, lines=3)
            icon = Gtk.Image.new_from_icon_name(
                "dialog-warning-symbolic"
                if volume.tpm_bound and not volume.tpm_pin
                else "drive-harddisk-symbolic"
            )
            if volume.tpm_bound and not volume.tpm_pin:
                icon.add_css_class("status-differs")
            row.add_prefix(icon)
            group.add(row)

        if facts.present and not facts.bound_volumes:
            hint = _row(
                "Binding a volume to the TPM",
                "This app does not do it: a mistake here locks you out of your own "
                "disk. The command is  systemd-cryptenroll --tpm2-device=auto "
                "--tpm2-with-pin=yes --tpm2-pcrs=7 <device>  — and keep the "
                "existing passphrase enrolled as the recovery path.",
                lines=5,
            )
            if "systemd-cryptenroll" not in facts.tools:
                hint.set_subtitle(
                    hint.get_subtitle() + "  systemd-cryptenroll is not installed here."
                )
            group.add(hint)
        return group


class BootloaderPage(Gtk.Box):
    """GRUB password, and the firmware facts that put it in context."""

    __gtype_name__ = "OssBootloaderPage"

    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.window = window
        self.facts = bootloader_module.read_facts()
        self.append(self._build())

    def _build(self) -> Gtk.Widget:
        return _column(self._password_group(), self._facts_group())

    def _password_group(self) -> Adw.PreferencesGroup:
        group = Adw.PreferencesGroup(
            title="Boot menu password",
            description=(
                "Stops anyone at the keyboard editing the kernel command line or "
                "reaching the GRUB shell. Without it, every flag in the grub "
                "section can be removed at boot by whoever is sitting there. "
                "Booting normally still needs no password — only editing does."
            ),
        )

        self.user_entry = Adw.EntryRow(title="Superuser name")
        self.user_entry.set_text(self.window.bootloader_change.get("username", "root"))
        group.add(self.user_entry)

        self.password_entry = Adw.PasswordEntryRow(title="Password")
        group.add(self.password_entry)
        self.confirm_entry = Adw.PasswordEntryRow(title="Confirm password")
        group.add(self.confirm_entry)

        staged = bool(self.window.bootloader_change.get("hash"))
        action = _row(
            "Staged" if staged else "Not staged",
            "The password is hashed here, in this process, and only the PBKDF2 "
            "digest is written anywhere — the plaintext never reaches disk."
            if not staged
            else "A password hash is staged. Review shows the script that will be written.",
        )
        button = Gtk.Button(label="Stage password", valign=Gtk.Align.CENTER)
        button.add_css_class("suggested-action")
        button.connect("clicked", self._on_stage)
        action.add_suffix(button)
        group.add(action)

        if self.facts.password_set or staged:
            remove = _row(
                "Remove the boot password",
                "Deletes the script and re-runs update-grub. Forgetting the "
                "password means rescue media, so removing it deliberately is "
                "better than being locked out.",
            )
            remove_button = Gtk.Button(label="Stage removal", valign=Gtk.Align.CENTER)
            remove_button.add_css_class("destructive-action")
            remove_button.connect("clicked", self._on_remove)
            remove.add_suffix(remove_button)
            group.add(remove)
        return group

    def _facts_group(self) -> Adw.PreferencesGroup:
        group = Adw.PreferencesGroup(title="Boot integrity")
        group.add(_row("Firmware", "EFI" if self.facts.efi else "Legacy BIOS"))
        group.add(_row("Secure Boot", self.facts.secure_boot))
        group.add(_row("TPM", "present" if self.facts.tpm else "not present"))
        group.add(
            _row(
                "Disk encryption",
                ("root is on LUKS" if self.facts.root_encrypted else "root is not encrypted")
                + (", /boot encrypted" if self.facts.boot_encrypted else ", /boot is not"),
            )
        )
        for severity, message in self.facts.findings:
            row = _row("Finding" if severity == "info" else "Worth fixing", message, lines=4)
            icon = Gtk.Image.new_from_icon_name(
                "dialog-warning-symbolic" if severity == "high" else "dialog-information-symbolic"
            )
            if severity == "high":
                icon.add_css_class("status-pending-reboot")
            row.add_prefix(icon)
            group.add(row)
        return group

    def _on_stage(self, _button: Gtk.Button) -> None:
        password = self.password_entry.get_text()
        confirm = self.confirm_entry.get_text()
        username = self.user_entry.get_text().strip() or "root"

        if password != confirm:
            self.window.toast("The two passwords do not match.")
            return
        try:
            bootloader_module.validate_username(username)
            digest = bootloader_module.hash_password(password)
        except bootloader_module.BootloaderError as exc:
            self.window.toast(str(exc))
            return

        self.window.bootloader_change = {"username": username, "hash": digest}
        self.password_entry.set_text("")
        self.confirm_entry.set_text("")
        self.window.toast("Password staged. Nothing is written until you Apply.")
        self.window._show_section(self.window.current_section)

    def _on_remove(self, _button: Gtk.Button) -> None:
        self.window.bootloader_change = {"remove": True}
        self.window.toast("Removal staged.")
        self.window._show_section(self.window.current_section)


# --------------------------------------------------------------------------- #
#  Permissions (§4.11)
# --------------------------------------------------------------------------- #


class PermissionsPage(Gtk.Box):
    """The recommended table, the SUID audit and the read-only scans."""

    __gtype_name__ = "OssPermissionsPage"

    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.window = window
        if not hasattr(window, "permission_rows"):
            rows = list(permissions_module.TABLE) + permissions_module.user_rows()
            window.permission_rows = permissions_module.inspect(rows)
        self.append(self._build())

    def _rebuild(self) -> None:
        self.window._show_section(self.window.current_section)

    def _build(self) -> Gtk.Widget:
        return _column(
            self._custom_group(),
            self._table_group("recommended"),
            self._table_group("aggressive"),
            self._do_not_change_group(),
            self._suid_group(),
            self._scans_group(),
        )

    def _custom_group(self) -> Adw.PreferencesGroup:
        """Any path, not just the recommended list."""
        staged = self.window.filemode_changes
        group = Adw.PreferencesGroup(
            title="Any file or folder",
            description=(
                "The table below covers paths worth fixing on any machine. This is "
                "for a specific one: pick it, set who can read, change and run it, "
                "and see what that means before anything happens. No terminal."
            ),
        )

        row = _row(
            "Set permissions on a file or folder",
            "Opens a picker and a permission grid, with an explanation of each "
            "choice as you make it.",
        )
        button = Gtk.Button(label="Choose…", valign=Gtk.Align.CENTER)
        button.add_css_class("suggested-action")
        button.connect("clicked", self._on_custom)
        row.add_suffix(button)
        group.add(row)

        for path, spec in sorted(staged.items()):
            mode = spec["mode"]
            how = "statoverride, survives upgrades" if spec.get("durable") else "chmod"
            extra = ", immutable" if spec.get("immutable") else ""
            entry = _row(
                path,
                f"{mode:04o}  {filemode_module.mode_string(mode)}  ({how}{extra})",
            )
            remove = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER)
            remove.add_css_class("flat")
            remove.set_tooltip_text("Unstage this change")
            remove.connect("clicked", self._on_unstage, path)
            entry.add_suffix(remove)
            group.add(entry)
        return group

    def _on_custom(self, _button: Gtk.Button) -> None:
        from .mode_dialog import ModeDialog

        ModeDialog(self.window).present()

    def _on_unstage(self, _button: Gtk.Button, path: str) -> None:
        self.window.filemode_changes.pop(path, None)
        self.window._refresh_chrome()
        self._rebuild()

    def _table_group(self, tier: str) -> Adw.PreferencesGroup:
        rows = [
            r for r in self.window.permission_rows
            if r.tier == tier and r.exists and not r.compliant
        ]
        compliant = [
            r for r in self.window.permission_rows if r.tier == tier and r.compliant
        ]
        titles = {
            "recommended": "Recommended",
            "aggressive": "Aggressive",
        }
        descriptions = {
            "recommended": "Safe and CIS-aligned. Nothing here should break anything.",
            "aggressive": (
                "Tighter than most systems need. Each of these can break log "
                "tooling or shared access, so they are separate from the safe set."
            ),
        }
        group = Adw.PreferencesGroup(
            title=f"{titles[tier]} — {len(rows)} to fix, {len(compliant)} already correct",
            description=descriptions[tier],
        )
        if not rows:
            group.add(_row("Nothing to change", "Every path in this tier is already correct."))
            return group

        for row_data in rows:
            row = _row(row_data.path, f"{row_data.summary} — {row_data.protects}")
            staged = row_data.path in self.window.permission_changes
            button = Gtk.Button(
                label="Staged" if staged else "Fix",
                valign=Gtk.Align.CENTER,
            )
            if staged:
                button.add_css_class("changed-counter")
            button.connect("clicked", self._on_fix, row_data)
            row.add_suffix(button)
            group.add(row)

        fix_all = _row("Fix all in this tier", f"{len(rows)} path(s)")
        button = Gtk.Button(label="Stage all", valign=Gtk.Align.CENTER)
        button.add_css_class("suggested-action")
        button.connect("clicked", self._on_fix_all, rows)
        fix_all.add_suffix(button)
        group.add(fix_all)
        return group

    def _do_not_change_group(self) -> Adw.PreferencesGroup:
        group = Adw.PreferencesGroup(
            title="Deliberately not offered",
            description="These come up in hardening guides and are wrong. The reason is here so it is clear the omission is on purpose.",
        )
        for path, reason in permissions_module.DO_NOT_CHANGE.items():
            group.add(_row(path, reason))
        return group

    def _suid_group(self) -> Adw.PreferencesGroup:
        binaries = getattr(self.window, "suid_binaries", None)
        group = Adw.PreferencesGroup(
            title="SUID / SGID binaries",
            description=(
                "Every one of these runs with privileges the caller does not have. "
                "The ones no package owns are the interesting ones."
            ),
        )
        if binaries is None:
            row = _row("Not scanned yet", "Walks /usr, /bin, /sbin and /opt — a few seconds.")
            button = Gtk.Button(label="Scan", valign=Gtk.Align.CENTER)
            button.add_css_class("suggested-action")
            button.connect("clicked", self._on_scan_suid)
            row.add_suffix(button)
            group.add(row)
            return group

        unpackaged = [b for b in binaries if b.unpackaged]
        group.set_description(
            f"{len(binaries)} found, {len(unpackaged)} owned by no package. "
            "A setuid binary with no package behind it is a classic persistence "
            "mechanism and worth explaining."
        )
        for binary in unpackaged + [b for b in binaries if not b.unpackaged][:25]:
            bits = "setuid" if binary.setuid else ""
            bits += " setgid" if binary.setgid else ""
            subtitle = f"{binary.mode:04o} {bits.strip()}"
            subtitle += f" · {binary.package}" if binary.package else " · NO PACKAGE OWNS THIS"
            if binary.consequence:
                subtitle += f" · strip: {binary.safe_to_strip} — {binary.consequence}"
            row = _row(binary.path, subtitle)
            if binary.unpackaged:
                icon = Gtk.Image.new_from_icon_name("dialog-error-symbolic")
                icon.add_css_class("status-differs")
                row.add_prefix(icon)
            group.add(row)
        return group

    def _scans_group(self) -> Adw.PreferencesGroup:
        scan = getattr(self.window, "permission_scan", None)
        group = Adw.PreferencesGroup(
            title="Findings",
            description="Read-only checks for things that should not be there.",
        )
        if scan is None:
            row = _row("Not scanned yet", "Walks /etc, /var and /usr/local.")
            button = Gtk.Button(label="Scan", valign=Gtk.Align.CENTER)
            button.connect("clicked", self._on_scan_findings)
            row.add_suffix(button)
            group.add(row)
            return group

        sections = [
            ("World-writable files", scan.world_writable,
             "Any user can replace the contents of these."),
            ("Writable directories in $PATH", scan.writable_path_dirs,
             "Anyone who can write here chooses what you run."),
            ("Home directories others can read", scan.readable_homes, ""),
            (".rhosts / .netrc / .forward files", scan.dangerous_dotfiles,
             "These grant access or store credentials in plaintext."),
        ]
        empty = True
        for title, items, why in sections:
            if not items:
                continue
            empty = False
            group.add(_row(f"{title} — {len(items)}", why or ", ".join(items[:4])))
            for item in items[:8]:
                group.add(_row(item, ""))
        if empty:
            group.add(_row("Nothing found", "None of these checks flagged anything."))
        return group

    # -- handlers -------------------------------------------------------- #

    def _on_fix(self, _button, row_data) -> None:
        try:
            permissions_module.validate_change(row_data.path, row_data.target_mode)
        except permissions_module.PermissionError_ as exc:
            self.window.toast(str(exc))
            return
        self.window.permission_changes[row_data.path] = {
            "mode": row_data.target_mode,
            "owner": row_data.owner,
            "group": row_data.group,
        }
        self.window._refresh_chrome()
        self._rebuild()

    def _on_fix_all(self, _button, rows) -> None:
        staged = 0
        for row_data in rows:
            try:
                permissions_module.validate_change(row_data.path, row_data.target_mode)
            except permissions_module.PermissionError_:
                continue
            self.window.permission_changes[row_data.path] = {
                "mode": row_data.target_mode,
                "owner": row_data.owner,
                "group": row_data.group,
            }
            staged += 1
        self.window.toast(f"Staged {staged} permission change(s).")
        self.window._refresh_chrome()
        self._rebuild()

    def _on_scan_suid(self, _button) -> None:
        self.window.toast("Scanning for setuid binaries…")
        binaries = permissions_module.annotate_packages(permissions_module.scan_suid())
        self.window.suid_binaries = binaries
        self._rebuild()

    def _on_scan_findings(self, _button) -> None:
        self.window.toast("Scanning…")
        self.window.permission_scan = permissions_module.run_scans()
        self._rebuild()


# --------------------------------------------------------------------------- #
#  fstab (§4.10)
# --------------------------------------------------------------------------- #


class FstabPage(Gtk.Box):
    """Per-mount option toggles, with the remount test explained up front."""

    __gtype_name__ = "OssFstabPage"

    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.window = window
        self.entries = fstab_module.read()
        self.live = fstab_module.read_live()
        self.append(self._build())

    def _rebuild(self) -> None:
        self.window._show_section(self.window.current_section)

    def _build(self) -> Gtk.Widget:
        warning = Adw.PreferencesGroup(
            title="Mount options",
            description=(
                "This is the highest-risk section in the app: a bad line in "
                "/etc/fstab drops the machine to an emergency shell at boot. "
                "Nothing is written until the exact option set has been proved on "
                "the running system — the helper runs mount -o remount first and "
                "refuses to write any entry whose live remount fails."
            ),
        )
        groups = [warning, self._live_group()]
        for entry in self.entries:
            if entry.touchable:
                groups.append(self._entry_group(entry))
        skipped = [e.mount for e in self.entries if not e.touchable]
        if skipped:
            group = Adw.PreferencesGroup(title="Not offered")
            group.add(
                _row(
                    ", ".join(skipped),
                    "Root, pseudo-filesystems and swap. Remounting these mid-session "
                    "takes the machine with it.",
                )
            )
            groups.append(group)
        return _column(*groups)

    def _live_group(self) -> Adw.PreferencesGroup:
        """What is mounted right now, and where it disagrees with fstab.

        fstab is the request made at boot; /proc/mounts is the answer. A hardened
        line in fstab that was never remounted, or a filesystem systemd mounts
        that fstab never mentions, both look like success from the file alone.
        """
        drifted = fstab_module.drift(self.entries, self.live)
        not_mounted = fstab_module.unmounted(self.entries, self.live)
        missing = fstab_module.unlisted(self.entries, self.live)

        group = Adw.PreferencesGroup(
            title="Live state",
            description=(
                f"{len(self.live)} filesystem(s) mounted right now, read from "
                f"/proc/mounts. fstab is what was asked for at boot; this is what "
                f"the kernel is actually enforcing."
            ),
        )

        if not drifted and not not_mounted and not missing:
            group.add(
                _row(
                    "fstab and the running system agree",
                    "Every entry below is mounted with the options its fstab line "
                    "asks for.",
                )
            )
            return group

        for mount, (wanted, actual) in sorted(drifted.items()):
            row = _row(
                f"{mount} — mounted differently from fstab",
                f"fstab asks for {', '.join(sorted(wanted)) or 'none'}; the kernel "
                f"is enforcing {', '.join(sorted(actual)) or 'none'}. A remount or "
                f"a reboot is what closes this gap.",
            )
            icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
            icon.add_css_class("status-differs")
            row.add_prefix(icon)
            group.add(row)

        for mount in missing:
            recommended = ", ".join(fstab_module.RECOMMENDED[mount.mount][0])
            have = ", ".join(sorted(mount.hardening)) or "none"
            row = _row(
                f"{mount.mount} is mounted but has no fstab entry",
                f"Mounted as {mount.fstype} by systemd, currently with {have}. "
                f"Recommended here: {recommended}. Toggling it needs an fstab line "
                f"to exist first — this page edits entries, it does not create "
                f"them.",
            )
            row.set_subtitle_lines(4)
            icon = Gtk.Image.new_from_icon_name("dialog-information-symbolic")
            icon.add_css_class("status-pending-reboot")
            row.add_prefix(icon)
            group.add(row)

        if not_mounted:
            group.add(
                _row(
                    f"{len(not_mounted)} fstab entr(ies) are not mounted",
                    ", ".join(not_mounted)
                    + ". Their options cannot be proved by a live remount, so "
                    "staging them is refused.",
                )
            )
        return group

    def _entry_group(self, entry: fstab_module.Entry) -> Adw.PreferencesGroup:
        staged = self.window.fstab_changes.get(entry.mount)
        chosen = set(staged) if staged is not None else set(entry.option_list)

        mounted = self.live.get(entry.mount)
        if mounted is None:
            live_text = "not mounted right now"
        else:
            live_text = f"live: {mounted.options}"

        group = Adw.PreferencesGroup(
            title=f"{entry.mount}  ({entry.fstype})",
            description=f"fstab: {entry.options}  ·  {live_text}"
            + (f"  ·  {entry.caveat}" if entry.caveat else ""),
        )
        for option in fstab_module.HARDENING_OPTIONS:
            title, why = fstab_module.OPTION_HELP[option]
            recommended = option in entry.recommended
            subtitle = why + ("  (recommended here)" if recommended else "")
            # Per-option drift, so it is visible on the switch itself and not
            # only in the summary above: an option present in fstab but not in
            # /proc/mounts has not taken effect on this boot.
            if mounted is not None and entry.has(option) != mounted.has(option):
                subtitle += (
                    "  ·  in fstab but not live — needs a remount"
                    if entry.has(option)
                    else "  ·  live but not in fstab — will not survive a reboot"
                )
            row = Adw.SwitchRow(
                title=f"{option} — {title}",
                subtitle=subtitle,
                active=option in chosen,
            )
            row.set_subtitle_lines(3)
            row.connect("notify::active", self._on_option, entry, option)
            group.add(row)
        return group

    def _on_option(self, row: Adw.SwitchRow, _param, entry, option: str) -> None:
        original = set(entry.option_list) & set(fstab_module.HARDENING_OPTIONS)
        chosen = set(
            self.window.fstab_changes.get(
                entry.mount, set(entry.option_list) & set(fstab_module.HARDENING_OPTIONS)
            )
        )
        if row.get_active():
            chosen.add(option)
        else:
            chosen.discard(option)
        if chosen == original:
            self.window.fstab_changes.pop(entry.mount, None)
        else:
            self.window.fstab_changes[entry.mount] = sorted(chosen)
        self.window._refresh_chrome()


# --------------------------------------------------------------------------- #
#  USB (§4.18)
# --------------------------------------------------------------------------- #


class UsbPage(Gtk.Box):
    """USBGuard policy, generated from what is plugged in right now."""

    __gtype_name__ = "OssUsbPage"

    def __init__(self, window) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.window = window
        self.state = usb_module.read_state()
        self.append(self._build())

    def _rebuild(self) -> None:
        self.window._show_section(self.window.current_section)

    def _build(self) -> Gtk.Widget:
        return _column(self._status_group(), self._devices_group())

    def _status_group(self) -> Adw.PreferencesGroup:
        safe, reason = self.state.safe_to_enforce
        group = Adw.PreferencesGroup(
            title="USB device policy",
            description=(
                "USBGuard blocks any USB device not on an allowlist. The order is "
                "everything: build the allowlist from what is connected now, then "
                "enforce. The other way round, the keyboard you would fix it with "
                "is the first thing blocked."
            ),
        )

        if not self.state.installed:
            row = _row(
                "usbguard is not installed",
                "Install it offline with:  sudo apt install ./usbguard*.deb\n"
                "The device list below is read from sysfs and works either way.",
            )
            group.add(row)
            return group

        group.add(
            _row(
                f"Policy: {self.state.rule_count} rule(s)"
                if self.state.rules_present
                else "No policy yet",
                f"implicit target: {self.state.implicit_policy or 'not set'}",
            )
        )

        staged = bool(self.window.usb_change)
        action = _row(
            "Generate policy from connected devices",
            reason if not safe else
            "Allows exactly what is plugged in now, input devices first. "
            "Anything else is blocked.",
        )
        button = Gtk.Button(label="Staged" if staged else "Generate", valign=Gtk.Align.CENTER)
        button.add_css_class("suggested-action")
        button.set_sensitive(bool(self.state.devices))
        button.connect("clicked", self._on_generate)
        action.add_suffix(button)
        group.add(action)

        if not safe:
            warn = _row("Enforcement is not offered", reason, lines=4)
            icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
            icon.add_css_class("status-differs")
            warn.add_prefix(icon)
            group.add(warn)
        return group

    def _devices_group(self) -> Adw.PreferencesGroup:
        group = Adw.PreferencesGroup(
            title=f"Connected devices — {len(self.state.devices)}",
            description="Read from sysfs, so this works whether or not usbguard is installed.",
        )
        if not self.state.devices:
            group.add(_row("No USB devices detected", ""))
            return group
        for device in sorted(self.state.devices, key=lambda d: (not d.is_hid, d.device_id)):
            labels = []
            if device.is_hid:
                labels.append("input device — must stay allowed")
            if device.is_hub:
                labels.append("hub")
            group.add(
                _row(
                    f"{device.device_id}  {device.label}",
                    " · ".join(labels) or f"port {device.port}",
                )
            )
        return group

    def _on_generate(self, _button) -> None:
        try:
            rules = usb_module.generate_rules(self.state.devices)
            usb_module.validate_rules(rules)
        except usb_module.UsbError as exc:
            self.window.toast(str(exc))
            return
        safe, reason = self.state.safe_to_enforce
        self.window.usb_change = {
            "rules": rules,
            "implicit": "block",
            "enable": False,
            "hid_confirmed": self.state.has_hid,
        }
        self.window.toast(
            "Policy staged (not enforcing). Review shows the exact rule list."
            if safe
            else f"Policy staged. Enforcement stays off: {reason}"
        )
        self.window._refresh_chrome()
        self._rebuild()
