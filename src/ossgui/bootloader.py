"""Bootloader password and boot integrity — BUILD_PLAN §4.23.

Without a GRUB password, every kernel hardening flag in the grub section is one
keypress away from being removed by anyone with physical access: edit the
command line at the boot menu, drop `init=/bin/sh`, done.

Password handling: ``grub-mkpasswd-pbkdf2`` does not need root, so the GUI hashes
the password itself and only the PBKDF2 digest is ever written to the payload
file or handed to the helper. The plaintext stays in the GUI process's memory
and never touches disk.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

MKPASSWD = "/usr/bin/grub-mkpasswd-pbkdf2"
MOKUTIL = "/usr/bin/mokutil"

#: Runs before 10_linux, so `set superusers` is in scope for the menu entries.
PASSWORD_SCRIPT = "/etc/grub.d/01_oss_password"

#: The hash format grub-mkpasswd-pbkdf2 emits. Nothing else is accepted.
_PBKDF2 = re.compile(r"^grub\.pbkdf2\.sha512\.\d+\.[0-9A-Fa-f]+\.[0-9A-Fa-f]+$")

_HASH_LINE = re.compile(r"(grub\.pbkdf2\.sha512\.\S+)")

#: A GRUB superuser name. Deliberately narrow — it is interpolated into a script.
_USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class BootloaderError(ValueError):
    """A password hash or username we refuse to write."""


@dataclass
class BootFacts:
    """What the firmware and disk layout actually look like."""

    efi: bool = False
    secure_boot: str = "unknown"
    tpm: bool = False
    boot_encrypted: bool = False
    root_encrypted: bool = False
    grub_cfg_mode: str = ""
    password_set: bool = False

    @property
    def findings(self) -> list[tuple[str, str]]:
        """``(severity, message)`` for the things worth saying out loud."""
        out: list[tuple[str, str]] = []
        if not self.password_set:
            out.append((
                "high",
                "No GRUB password is set. Anyone with physical access can edit the "
                "kernel command line at the boot menu and remove every flag in the "
                "grub section — or boot straight to a root shell with init=/bin/sh.",
            ))
        if self.secure_boot == "disabled":
            out.append((
                "info",
                "Secure Boot is off, so the firmware does not check the bootloader "
                "or kernel signature. module.sig_enforce still works, but the chain "
                "below the kernel is unverified.",
            ))
        elif self.secure_boot == "unsupported":
            out.append((
                "info",
                "This system's firmware does not support Secure Boot at all, so "
                "signature enforcement stops at the kernel.",
            ))
        if not self.boot_encrypted:
            out.append((
                "info",
                "/boot is not encrypted. The kernel and initrd can be read and "
                "replaced by anyone who can attach the disk — a GRUB password does "
                "not protect against that, only against editing the menu.",
            ))
        if self.grub_cfg_mode and self.grub_cfg_mode not in ("600", "400"):
            out.append((
                "info",
                f"/boot/grub/grub.cfg is mode {self.grub_cfg_mode}, so any local "
                f"user can read your full kernel command line and see exactly which "
                f"hardening flags are set.",
            ))
        return out


def _run(argv: list[str], stdin: str | None = None, timeout: int = 30) -> tuple[int, str]:
    if shutil.which(argv[0]) is None and not Path(argv[0]).exists():
        return 127, f"{argv[0]} is not installed"
    try:
        result = subprocess.run(
            argv, input=stdin, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, str(exc)
    return result.returncode, result.stdout + result.stderr


def read_facts() -> BootFacts:
    """Firmware and disk facts, all readable without root."""
    facts = BootFacts(efi=Path("/sys/firmware/efi").is_dir())

    code, output = _run([MOKUTIL, "--sb-state"])
    lowered = output.lower()
    if code != 0 and "not installed" in lowered:
        facts.secure_boot = "unknown"
    elif "doesn't support secure boot" in lowered or "not supported" in lowered:
        facts.secure_boot = "unsupported"
    elif "secureboot enabled" in lowered:
        facts.secure_boot = "enabled"
    elif "secureboot disabled" in lowered:
        facts.secure_boot = "disabled"

    facts.tpm = any(Path("/dev").glob("tpm*"))

    code, output = _run(["lsblk", "-no", "NAME,FSTYPE,MOUNTPOINT"])
    if code == 0:
        for line in output.splitlines():
            if "crypto_LUKS" in line:
                facts.root_encrypted = True
            if "/boot" in line and "crypt" in line.lower():
                facts.boot_encrypted = True

    try:
        facts.grub_cfg_mode = oct(Path("/boot/grub/grub.cfg").stat().st_mode & 0o777)[2:]
    except OSError:
        facts.grub_cfg_mode = ""

    facts.password_set = password_is_set()
    return facts


def password_is_set() -> bool:
    """Whether a GRUB superuser password is configured by us or by anything else."""
    for path in (PASSWORD_SCRIPT, "/etc/grub.d/40_custom", "/etc/grub.d/01_users"):
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "password_pbkdf2" in text:
            return True
    return False


def hash_password(password: str) -> str:
    """Turn a password into a PBKDF2 digest, unprivileged.

    Doing this in the GUI rather than the helper is deliberate: only the digest
    then goes into the payload file, so the plaintext never lands on disk.
    """
    if not password:
        raise BootloaderError("the password is empty")
    if len(password) < 8:
        raise BootloaderError("use at least 8 characters — this is your last line of defence")

    # grub-mkpasswd-pbkdf2 prompts twice and reads from stdin.
    code, output = _run([MKPASSWD], stdin=f"{password}\n{password}\n", timeout=60)
    if code != 0:
        raise BootloaderError(f"grub-mkpasswd-pbkdf2 failed: {output.strip()[:200]}")

    match = _HASH_LINE.search(output)
    if match is None:
        raise BootloaderError("grub-mkpasswd-pbkdf2 did not return a hash")
    digest = match.group(1)
    validate_hash(digest)
    return digest


def validate_hash(digest: str) -> None:
    if not _PBKDF2.match(digest):
        raise BootloaderError("that is not a grub PBKDF2 hash")


def validate_username(name: str) -> None:
    if not _USERNAME.match(name):
        raise BootloaderError(f"not a usable GRUB superuser name: {name!r}")


def render_script(username: str, digest: str) -> str:
    """The /etc/grub.d script that installs the superuser and password.

    Both values are pattern-checked before they get here, so the generated shell
    contains nothing the user typed verbatim.
    """
    validate_username(username)
    validate_hash(digest)
    return (
        "#!/bin/sh\n"
        "# Managed by OSS. Do not edit by hand.\n"
        "# Delete this file and run update-grub to remove the boot password.\n"
        "#\n"
        "# `superusers` may edit menu entries and reach the GRUB command line.\n"
        "# Menu entries stay bootable without a password because 10_linux marks\n"
        "# them --unrestricted; only editing them is gated.\n"
        "cat <<'EOF'\n"
        f"set superusers=\"{username}\"\n"
        f"password_pbkdf2 {username} {digest}\n"
        "EOF\n"
    )


def from_payload(data: dict) -> tuple[str, str] | None:
    """Validate a bootloader payload. Returns ``(username, digest)`` or None."""
    if not isinstance(data, dict):
        raise BootloaderError("bootloader payload is not an object")
    if data.get("remove"):
        return None
    username = data.get("username", "root")
    digest = data.get("hash", "")
    if not isinstance(username, str) or not isinstance(digest, str):
        raise BootloaderError("username and hash must both be strings")
    validate_username(username)
    validate_hash(digest)
    return username, digest
