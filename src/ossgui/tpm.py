"""TPM presence, measured boot, and TPM-bound disk encryption.

Everything here is an unprivileged read. The TPM's own attributes live in
/sys/class/tpm and are world-readable; the event log under
/sys/kernel/security is not, and that is reported as "needs root" rather than
guessed at.

The question this section answers is narrower than "do I have a TPM": a TPM
that nothing is bound to protects nothing. What matters is whether the disk
key is sealed to it, and whether unsealing needs a PIN — because a TPM that
releases the key on boot with no PIN means an attacker who steals the machine
gets a decrypted disk by pressing the power button.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

TPM_CLASS = "/sys/class/tpm"
EVENT_LOG = "/sys/kernel/security/tpm0/binary_bios_measurements"
CRYPTTAB = "/etc/crypttab"

#: Tools that can bind a LUKS volume to the TPM, in the order we mention them.
ENROLL_TOOLS = ("systemd-cryptenroll", "clevis", "tpm2_pcrread")


def _read(path: str | Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


@dataclass
class CryptVolume:
    """One /etc/crypttab entry."""

    name: str
    device: str
    keyfile: str
    options: str

    @property
    def option_list(self) -> list[str]:
        return [o for o in self.options.split(",") if o]

    @property
    def tpm_bound(self) -> bool:
        """Whether the key is sealed to the TPM rather than typed in."""
        return any(o.startswith("tpm2-device=") for o in self.option_list)

    @property
    def tpm_pin(self) -> bool:
        """Whether unsealing also requires a PIN."""
        return any(o.startswith("tpm2-with-pin=") and o.endswith("yes")
                   for o in self.option_list)

    @property
    def pcrs(self) -> str:
        for option in self.option_list:
            if option.startswith("tpm2-pcrs="):
                return option.partition("=")[2]
        return ""


@dataclass
class TpmFacts:
    """What the TPM is, and what — if anything — depends on it."""

    present: bool = False
    device: str = ""
    version: str = ""
    description: str = ""
    #: /dev/tpmrm0 is the kernel resource manager; talking to /dev/tpm0 directly
    #: is exclusive and locks other users out.
    has_resource_manager: bool = False
    device_mode: str = ""
    event_log: str = "absent"  # absent | unreadable | present
    volumes: list[CryptVolume] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)

    @property
    def bound_volumes(self) -> list[CryptVolume]:
        return [v for v in self.volumes if v.tpm_bound]

    @property
    def findings(self) -> list[tuple[str, str]]:
        """``(severity, message)`` — the things worth saying out loud."""
        out: list[tuple[str, str]] = []

        if not self.present:
            if self.volumes:
                out.append((
                    "info",
                    "No TPM is present, so the disk passphrase has to be typed at "
                    "every boot and there is no hardware root of trust to seal it "
                    "to. That is not a weakness in itself — a typed passphrase is "
                    "stronger than a TPM with no PIN — but measured boot is not "
                    "available on this machine.",
                ))
            else:
                out.append((
                    "info",
                    "No TPM is present. Measured boot and TPM-sealed disk keys are "
                    "not available on this machine.",
                ))
            return out

        if self.version.startswith("1"):
            out.append((
                "high",
                "This is a TPM 1.2. It has no SHA-256 PCR bank, so measurements "
                "are SHA-1 only, and systemd-cryptenroll will not use it. Treat it "
                "as unusable for sealing a disk key.",
            ))

        if not self.has_resource_manager:
            out.append((
                "info",
                "There is no /dev/tpmrm0 resource manager, so anything using the "
                "TPM has to open /dev/tpm0 exclusively and will lock out every "
                "other user of it while it holds the handle.",
            ))

        if self.device_mode and self.device_mode not in ("600", "660"):
            out.append((
                "high",
                f"The TPM device is mode {self.device_mode}. Any local user can "
                f"talk to it directly, which includes exhausting its dictionary "
                f"attack lockout and reading whatever is unsealed to them.",
            ))

        if self.event_log == "absent":
            out.append((
                "info",
                "The firmware exposes no measured-boot event log, so there is no "
                "record of what was hashed into the PCRs. Sealing to PCR values "
                "still works; verifying why they changed after a firmware update "
                "does not.",
            ))

        if not self.volumes:
            out.append((
                "info",
                "No encrypted volumes are listed in /etc/crypttab, so there is "
                "nothing on this machine for the TPM to protect.",
            ))
            return out

        bound = self.bound_volumes
        if not bound:
            out.append((
                "info",
                f"A TPM is present and {len(self.volumes)} encrypted volume(s) "
                f"exist, but none are sealed to it — every boot needs the "
                f"passphrase typed. systemd-cryptenroll can bind one if you want "
                f"unattended boot; read the next point before you do.",
            ))
            return out

        for volume in bound:
            if not volume.tpm_pin:
                out.append((
                    "high",
                    f"{volume.name} unseals from the TPM with no PIN. The disk is "
                    f"encrypted at rest, but the machine decrypts itself the "
                    f"moment it is powered on — so a stolen laptop is an unlocked "
                    f"laptop. Add tpm2-with-pin=yes to make it ask for something.",
                ))
            if not volume.pcrs:
                out.append((
                    "info",
                    f"{volume.name} does not pin the seal to any PCRs, so the key "
                    f"is released regardless of what booted. Binding to PCR 7 "
                    f"(Secure Boot state) at minimum ties it to the boot chain.",
                ))
        return out


def parse_crypttab(text: str) -> list[CryptVolume]:
    """Parse /etc/crypttab. Fields are name, device, keyfile, options."""
    out: list[CryptVolume] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        out.append(
            CryptVolume(
                name=parts[0],
                device=parts[1],
                keyfile=parts[2] if len(parts) > 2 else "none",
                options=parts[3] if len(parts) > 3 else "",
            )
        )
    return out


def _device_name() -> str:
    """The first TPM the kernel registered, or "" if there is none."""
    try:
        entries = sorted(p.name for p in Path(TPM_CLASS).iterdir())
    except OSError:
        return ""
    # tpm0 rather than tpmrm0: the class directory lists both, and the character
    # device is the one carrying the attributes.
    for name in entries:
        if re.fullmatch(r"tpm\d+", name):
            return name
    return ""


def read_facts() -> TpmFacts:
    """Everything readable without root."""
    facts = TpmFacts()
    facts.volumes = parse_crypttab(_read(CRYPTTAB))
    facts.tools = [tool for tool in ENROLL_TOOLS if shutil.which(tool)]

    name = _device_name()
    if not name:
        return facts

    facts.present = True
    facts.device = name
    base = Path(TPM_CLASS) / name

    major = _read(base / "tpm_version_major")
    if major:
        facts.version = f"{major}.0" if major == "2" else "1.2"
    else:
        # Pre-4.16 kernels had no tpm_version_major; a TPM 1.2 is the only thing
        # that exposes a `pcrs` file, so its absence means 2.0.
        facts.version = "1.2" if (base / "pcrs").exists() else "2.0"

    facts.description = _read(base / "device/description") or _read(base / "description")
    facts.has_resource_manager = Path(f"/dev/{name}rm0").exists() or Path(
        "/dev/tpmrm0"
    ).exists()

    device_path = Path(f"/dev/{name}")
    try:
        facts.device_mode = oct(device_path.stat().st_mode & 0o777)[2:]
    except OSError:
        facts.device_mode = ""

    log = Path(EVENT_LOG)
    if not log.exists():
        facts.event_log = "absent"
    elif _read(log) or log.stat().st_size:
        facts.event_log = "present"
    else:
        facts.event_log = "unreadable"
    return facts
