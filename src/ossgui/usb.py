"""USB and peripherals — BUILD_PLAN §4.18.

USBGuard blocks USB devices that are not on an allowlist. The order matters
enormously: generate the allowlist from what is plugged in *now*, then enable
enforcement. Do it the other way round and the keyboard you would use to fix it
is the first thing blocked.

So this refuses to stage enforcement unless the policy contains an HID device.
That single check is the difference between a hardening feature and a lockout.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field

from . import branding
from pathlib import Path

USBGUARD = "/usr/sbin/usbguard"
RULES_PATH = "/etc/usbguard/rules.conf"
CONFIG_PATH = "/etc/usbguard/usbguard-daemon.conf"

#: USB class codes we treat as "this could be your keyboard".
HID_CLASS = "03"

POLICY_TARGETS = ("allow", "block", "reject")

_RULE_OK = re.compile(r"^(allow|block|reject)\s+[-\w\s:=\"'{}.,/]+$")
_DEVICE_ID = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}$")


class UsbError(ValueError):
    """A rule or policy we refuse to write."""


@dataclass
class Device:
    """One USB device as the system currently sees it."""

    device_id: str  # vendor:product
    name: str = ""
    serial: str = ""
    classes: tuple[str, ...] = ()
    port: str = ""

    @property
    def is_hid(self) -> bool:
        """Keyboard, mouse or similar — the devices you cannot afford to block."""
        return any(c.startswith(HID_CLASS) for c in self.classes)

    @property
    def is_hub(self) -> bool:
        return any(c.startswith("09") for c in self.classes)

    @property
    def label(self) -> str:
        return self.name or self.device_id


@dataclass
class State:
    """USBGuard's installed state and the devices present right now."""

    installed: bool = False
    daemon_enabled: bool = False
    rules_present: bool = False
    rule_count: int = 0
    devices: list[Device] = field(default_factory=list)
    implicit_policy: str = ""

    @property
    def has_hid(self) -> bool:
        return any(d.is_hid for d in self.devices)

    @property
    def safe_to_enforce(self) -> tuple[bool, str]:
        """Whether enabling enforcement now would be survivable."""
        if not self.installed:
            return False, "usbguard is not installed."
        if not self.devices:
            return False, (
                "No USB devices were detected, so a generated policy would allow "
                "nothing — including your keyboard."
            )
        if not self.has_hid:
            return False, (
                "No keyboard or other input device is among the devices that would "
                "be allowed. Enabling enforcement now would leave you unable to type."
            )
        return True, ""


def _sysfs_devices() -> list[Device]:
    """Read connected USB devices from sysfs — no usbguard needed."""
    out: list[Device] = []
    base = Path("/sys/bus/usb/devices")
    if not base.is_dir():
        return out

    def read(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return ""

    try:
        entries = sorted(base.iterdir())
    except OSError:
        return out

    for entry in entries:
        vendor = read(entry / "idVendor")
        product = read(entry / "idProduct")
        if not vendor or not product:
            continue
        classes: list[str] = []
        device_class = read(entry / "bDeviceClass")
        if device_class:
            classes.append(device_class)
        for interface in sorted(entry.glob(f"{entry.name}:*")):
            interface_class = read(interface / "bInterfaceClass")
            if interface_class:
                classes.append(interface_class)
        name = " ".join(
            part for part in (read(entry / "manufacturer"), read(entry / "product")) if part
        )
        out.append(
            Device(
                device_id=f"{vendor}:{product}",
                name=name,
                serial=read(entry / "serial"),
                classes=tuple(classes),
                port=entry.name,
            )
        )
    return out


def read_state() -> State:
    """Everything readable without root, plus the device list from sysfs."""
    state = State(
        installed=bool(shutil.which("usbguard") or Path(USBGUARD).exists()),
        devices=_sysfs_devices(),
    )

    rules = Path(RULES_PATH)
    if rules.exists():
        state.rules_present = True
        try:
            state.rule_count = sum(
                1
                for line in rules.read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip() and not line.strip().startswith("#")
            )
        except OSError:
            state.rule_count = 0

    config = Path(CONFIG_PATH)
    try:
        for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("ImplicitPolicyTarget="):
                state.implicit_policy = line.split("=", 1)[1].strip()
    except OSError:
        pass
    return state


def generate_rules(devices: list[Device]) -> str:
    """An allowlist from the devices present now, HID first so it is obvious."""
    if not devices:
        raise UsbError("there are no devices to build a policy from")

    lines = [
        branding.with_footer(
            "Generated from the devices connected when it was written.\n"
            "Anything not listed here is blocked.\n"
            "Delete this file and restart usbguard to remove the policy."
        ).rstrip("\n"),
        "",
    ]
    ordered = sorted(devices, key=lambda d: (not d.is_hid, d.device_id))
    for device in ordered:
        if not _DEVICE_ID.match(device.device_id):
            continue
        comment = f"  # {device.label}" + ("  (input device)" if device.is_hid else "")
        lines.append(f"allow id {device.device_id}{comment}")
    return "\n".join(lines) + "\n"


def validate_rules(text: str) -> None:
    """Every non-comment line must be a rule shape we recognise."""
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        body = stripped.split("#", 1)[0].strip()
        if not _RULE_OK.match(body):
            raise UsbError(f"line {number} is not a rule this app will write: {body!r}")


def daemon_config(implicit: str = "block") -> str:
    if implicit not in POLICY_TARGETS:
        raise UsbError(f"unknown implicit policy {implicit!r}")
    return (
        "# Managed by OSS.\n"
        f"RuleFile={RULES_PATH}\n"
        f"ImplicitPolicyTarget={implicit}\n"
        "PresentDevicePolicy=apply-policy\n"
        "PresentControllerPolicy=keep\n"
        "InsertedDevicePolicy=apply-policy\n"
        "RestoreControllerDeviceState=false\n"
        "DeviceRulesWithPort=false\n"
    )


def from_payload(data: dict) -> dict:
    """Validate a usb payload from the GUI."""
    if not isinstance(data, dict):
        raise UsbError("usb payload is not an object")

    rules = data.get("rules", "")
    if not isinstance(rules, str) or not rules.strip():
        raise UsbError("a policy with no rules would block every device")
    validate_rules(rules)

    if "allow id" not in rules:
        raise UsbError("the policy allows nothing at all")

    implicit = data.get("implicit", "block")
    if implicit not in POLICY_TARGETS:
        raise UsbError(f"unknown implicit policy {implicit!r}")

    enable = bool(data.get("enable", False))
    if enable and not data.get("hid_confirmed"):
        # Belt and braces with the UI check: refuse enforcement unless the caller
        # has confirmed an input device is in the allowlist.
        raise UsbError(
            "refusing to enable enforcement without an input device in the policy"
        )
    return {"rules": rules, "implicit": implicit, "enable": enable}
