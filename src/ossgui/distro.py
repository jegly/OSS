"""Per-family differences in the commands the catalogue declares.

The catalogue is written in Debian terms because that is where this started,
and rewriting 614 flags into an abstract vocabulary would make the data harder
to read for no gain — most of it is already portable. What is not portable is a
short, enumerable list: two reload commands and one systemd unit name. Those
are resolved here, at plan time, against the family detected from os-release.

Sections whose *target file* has no equivalent elsewhere are a different
problem and are not solved here. Those declare ``families`` in the catalogue
and simply do not apply off it — see :func:`section_supported`. Rewriting only
the reload command for such a section would be worse than leaving it alone: the
reload would succeed while the file it was meant to activate sat somewhere
nothing reads, and the app would report that as applied.

Stdlib only; imported by the privileged helper.
"""

from __future__ import annotations

from . import probe

#: Reload commands whose Debian spelling does not exist on other families,
#: keyed by the argv the catalogue declares.
#:
#: update-grub is a Debian wrapper script. Arch and Fedora call grub-mkconfig
#: directly and disagree about both the binary name and where grub.cfg lives.
#: update-initramfs is likewise Debian-only: Arch uses mkinitcpio, and Fedora
#: and openSUSE use dracut.
_COMMANDS: dict[tuple[str, ...], dict[str, tuple[str, ...]]] = {
    ("/usr/sbin/update-grub",): {
        "arch": ("/usr/bin/grub-mkconfig", "-o", "/boot/grub/grub.cfg"),
        "fedora": ("/usr/sbin/grub2-mkconfig", "-o", "/boot/grub2/grub.cfg"),
        "suse": ("/usr/sbin/grub2-mkconfig", "-o", "/boot/grub2/grub.cfg"),
    },
    ("/usr/sbin/update-initramfs", "-u"): {
        "arch": ("/usr/bin/mkinitcpio", "-P"),
        "fedora": ("/usr/bin/dracut", "--force", "--regenerate-all"),
        "suse": ("/usr/bin/dracut", "--force", "--regenerate-all"),
    },
}

#: systemd units named differently across families. Debian calls the SSH
#: daemon's unit ssh.service; everyone else calls it sshd.service. Getting this
#: wrong means the config is written correctly and never picked up, which is
#: the failure this app exists to make visible rather than commit.
#: Every non-Debian family agrees with the upstream project's own unit names
#: here; it is Debian that renames them, so one mapping covers all three.
_ELSEWHERE = ("arch", "fedora", "suse")


def _renamed(elsewhere: str) -> dict[str, str]:
    return {family: elsewhere for family in _ELSEWHERE}


_UNITS: dict[str, dict[str, str]] = {
    "ssh.service": _renamed("sshd.service"),
    # Masking a unit that does not exist under that name quietly succeeds:
    # systemd just links the name to /dev/null. So getting these wrong does not
    # fail, it silently leaves the service running — Samba answering on the
    # network while the app reports it as masked.
    "smbd.service": _renamed("smb.service"),
    "nmbd.service": _renamed("nmb.service"),
    "rsync.service": _renamed("rsyncd.service"),
}


def resolve_command(argv, family: str | None = None) -> tuple[str, ...]:
    """Rewrite one reload command for *family* (default: this machine).

    An unknown family gets the catalogue's own wording unchanged. That is the
    conservative choice: a command we have not thought about is more likely to
    be right as written than as a guess, and it fails loudly if it is not.
    """
    argv = tuple(argv)
    family = family or probe.detect_family()

    replacement = _COMMANDS.get(argv, {}).get(family)
    if replacement is not None:
        return replacement

    return tuple(_UNITS.get(part, {}).get(family, part) for part in argv)


def section_supported(section, family: str | None = None) -> bool:
    """Whether *section* applies on this family at all.

    A section with no ``families`` restriction applies everywhere. An unknown
    family is treated as supported, so an unrecognised derivative degrades to
    "try it and report honestly" rather than hiding most of the application.
    """
    if not getattr(section, "families", ()):
        return True
    family = family or probe.detect_family()
    if family == "unknown":
        return True
    return family in section.families


#: What each optional package is called per family, where they disagree. Only
#: the differences: anything absent is spelled the same everywhere.
_PACKAGE_NAMES: dict[str, dict[str, str]] = {
    "openssh-server": {"arch": "openssh", "suse": "openssh"},
    "auditd": {"arch": "audit", "fedora": "audit", "suse": "audit"},
    "apparmor-utils": {"arch": "apparmor"},
    # debsums is Debian's own tool; the equivalent check elsewhere is built
    # into the package manager, so there is nothing to install.
    "debsums": {"arch": "", "fedora": "", "suse": ""},
}

#: How each family installs a package, as the user would type it.
_INSTALL = {
    "debian": "sudo apt install {}",
    "arch": "sudo pacman -S {}",
    "fedora": "sudo dnf install {}",
    "suse": "sudo zypper install {}",
}


def package_name(package: str, family: str | None = None) -> str:
    """What *package* is called here. Empty when it has no local equivalent."""
    family = family or probe.detect_family()
    return _PACKAGE_NAMES.get(package, {}).get(family, package)


def install_hint(package: str, family: str | None = None) -> str:
    """The command to install *package*, phrased for this system.

    Telling an Arch user to run ``apt install`` is the sort of small wrongness
    that makes someone stop believing the rest of the interface.
    """
    family = family or probe.detect_family()
    local = package_name(package, family)
    if not local:
        return f"no equivalent of {package} on this system"
    template = _INSTALL.get(family)
    if template is None:
        return f"install {local} with your package manager"
    return template.format(local)


def flag_supported(flag, family: str | None = None) -> bool:
    """Whether *flag* applies on this family. Same rules as a section."""
    if not getattr(flag, "families", ()):
        return True
    family = family or probe.detect_family()
    if family == "unknown":
        return True
    return family in flag.families


def unsupported_reason(section, family: str | None = None) -> str:
    """Why a section is not offered here, for the placeholder in the UI."""
    family = family or probe.detect_family()
    supported = ", ".join(section.families)
    return (
        f"This section writes files that only {supported} reads. On "
        f"{probe.distro_name()} they would be written and then ignored, so it "
        f"is not offered here rather than reporting a change that did nothing."
    )
