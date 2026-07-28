"""Back up the config files themselves, and put them back.

Not the same thing as :mod:`ossgui.capture`. Capture reads the *effective*
state, maps it onto catalogue flags and drops what no longer works. This copies
the actual files — whatever the user put there, however they put it, including
settings this application knows nothing about.

The path list is derived from the catalogue rather than hardcoded, so it stays
correct as sections are added: every section already declares where it writes,
and the directory holding that target is a directory worth backing up.

Root is required to read some of it — ``/etc/sudoers.d`` is 0440 — so the
archive is built inside the privileged helper.

Stdlib only; imported by the helper.
"""

from __future__ import annotations

import io
import os
import socket
import tarfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from .catalogue import Catalogue

#: Files and directories worth taking that no section target points at: the
#: in-place files, and the directories a section writes into but never names a
#: file in.
EXTRA_PATHS = (
    "/etc/default/grub",
    "/etc/login.defs",
    "/etc/fstab",
    "/etc/sysctl.conf",
    "/etc/pam.d",
    "/etc/ufw",
    "/etc/audit/auditd.conf",
    "/etc/usbguard",
)

#: Where the manifest lives inside the archive. Leading dot so it sorts first
#: and cannot collide with anything from /etc.
MANIFEST_NAME = ".oss-manifest.toml"

#: Nothing under /etc that matters to us is anywhere near this big. A config
#: directory that exceeds it is something we have misunderstood, not something
#: to silently truncate.
MAX_TOTAL_BYTES = 64 * 1024 * 1024


class BackupError(Exception):
    """An archive we refuse to create or unpack."""


@dataclass
class Manifest:
    """What a backup says about where it came from."""

    hostname: str = ""
    family: str = ""
    distro: str = ""
    created: str = ""
    version: str = ""

    def to_toml(self) -> str:
        return (
            "# Written by oss. Describes where this backup came from.\n"
            f'hostname = "{self.hostname}"\n'
            f'family   = "{self.family}"\n'
            f'distro   = "{self.distro}"\n'
            f'created  = "{self.created}"\n'
            f'version  = "{self.version}"\n'
        )

    @classmethod
    def from_toml(cls, text: str) -> "Manifest":
        values: dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, raw = line.partition("=")
            values[key.strip()] = raw.strip().strip('"')
        return cls(
            hostname=values.get("hostname", ""),
            family=values.get("family", ""),
            distro=values.get("distro", ""),
            created=values.get("created", ""),
            version=values.get("version", ""),
        )


@dataclass
class BackupResult:
    """What went into an archive, and what did not."""

    path: str = ""
    files: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    bytes_written: int = 0

    def summary(self) -> str:
        return (
            f"{len(self.files)} file(s) from {len(set(os.path.dirname(f) for f in self.files))} "
            f"location(s), {self.bytes_written // 1024} KB"
        )


def backup_paths(catalogue: Catalogue) -> list[str]:
    """Every path worth backing up, derived from the catalogue plus the extras.

    A section's target names a file; the directory holding it is what we want,
    because the user's own drop-ins live alongside ours. In-place targets are
    files in their own right and are taken as files.
    """
    out: set[str] = set()
    for section in catalogue.sections:
        for target in section.targets():
            if not target:
                continue
            parent = os.path.dirname(target)
            # An in-place target is a real system file, not a drop-in we own,
            # so its directory is somebody else's and only the file is ours to
            # take. /etc/login.defs must not drag all of /etc in with it.
            if section.in_place or parent in ("/etc", "", "/"):
                out.add(target)
            else:
                out.add(parent)
    out.update(EXTRA_PATHS)
    return sorted(out)


def _walk(path: Path) -> list[Path]:
    """Every regular file at or under *path*, skipping symlinks."""
    if path.is_symlink():
        return []
    if path.is_file():
        return [path]
    if not path.is_dir():
        return []
    found: list[Path] = []
    for entry in sorted(path.rglob("*")):
        # Symlinks are skipped rather than followed: a link out of /etc would
        # pull in whatever it points at, and restoring one is not something
        # this is trying to do.
        if entry.is_symlink() or not entry.is_file():
            continue
        found.append(entry)
    return found


def location_of(path: str, locations: list[str]) -> str:
    """Which backup location *path* belongs to — the longest matching prefix.

    Restore groups its file list by this, so a whole category (all of
    /etc/sudoers.d, say) can be left out in one gesture.
    """
    best = ""
    for location in locations:
        if path == location or path.startswith(location.rstrip("/") + "/"):
            if len(location) > len(best):
                best = location
    return best or os.path.dirname(path)


def create(
    catalogue: Catalogue,
    destination: str | Path,
    manifest: Manifest,
    root: str = "/",
    locations: list[str] | None = None,
) -> BackupResult:
    """Write a gzipped tar of every backup path that exists.

    *root* exists for the tests, which run this against a sandbox tree rather
    than the real ``/etc``. *locations* limits the archive to those backup
    paths; ``None`` takes everything.
    """
    destination = Path(destination)
    result = BackupResult(path=str(destination))
    base = Path(root)

    chosen = backup_paths(catalogue)
    if locations is not None:
        chosen = [p for p in chosen if p in set(locations)]

    total = 0
    with tarfile.open(destination, "w:gz") as archive:
        raw = manifest.to_toml().encode("utf-8")
        info = tarfile.TarInfo(MANIFEST_NAME)
        info.size = len(raw)
        info.mtime = int(time.time())
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(raw))

        for wanted in chosen:
            source = base / wanted.lstrip("/")
            files = _walk(source)
            if not files:
                result.skipped.append(wanted)
                continue
            for path in files:
                total += path.stat().st_size
                if total > MAX_TOTAL_BYTES:
                    raise BackupError(
                        f"backup exceeded {MAX_TOTAL_BYTES // (1024 * 1024)}MB at {path}"
                    )
                # Stored without the sandbox prefix, so an archive made in a
                # test restores to the same place a real one would.
                arcname = str(path)[len(str(base)):].lstrip("/")
                archive.add(path, arcname=arcname, recursive=False)
                result.files.append("/" + arcname)

    result.bytes_written = destination.stat().st_size
    return result


def read_manifest(archive_path: str | Path) -> Manifest:
    """The manifest from an archive, or an empty one if it has none."""
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            member = archive.extractfile(MANIFEST_NAME)
            if member is None:
                return Manifest()
            return Manifest.from_toml(member.read().decode("utf-8", "replace"))
    except (tarfile.TarError, OSError, KeyError):
        return Manifest()


def read_files(archive_path: str | Path) -> dict[str, tuple[str, int]]:
    """``{absolute path: (content, mode)}`` for every file in the archive.

    Refuses anything that would land outside ``/etc``. A tar can name absolute
    paths, ``..`` segments and symlinks, and unpacking one blindly is how an
    archive from elsewhere writes wherever it likes as root.
    """
    out: dict[str, tuple[str, int]] = {}
    total = 0
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            if member.name == MANIFEST_NAME:
                continue
            if not member.isfile():
                # Directories are implied by the files in them; symlinks,
                # devices and hardlinks are refused outright.
                if member.issym() or member.islnk() or member.isdev():
                    raise BackupError(f"archive contains a link or device: {member.name}")
                continue

            target = os.path.normpath("/" + member.name)
            if not target.startswith("/etc/"):
                raise BackupError(f"archive would write outside /etc: {member.name}")

            total += member.size
            if total > MAX_TOTAL_BYTES:
                raise BackupError("archive is larger than this will unpack")

            handle = archive.extractfile(member)
            if handle is None:
                continue
            content = handle.read().decode("utf-8", "replace")
            out[target] = (content, member.mode & 0o7777)
    return out


def mismatch_warning(manifest: Manifest, family: str, distro: str) -> str:
    """Why restoring this archive here might be a bad idea, or "" if it is fine."""
    if not manifest.family:
        return (
            "This archive has no manifest, so there is no way to tell which "
            "system it came from. Check the file list before applying it."
        )
    if manifest.family != family:
        return (
            f"This backup came from {manifest.distro or manifest.family}, and "
            f"this machine is {distro or family}. Paths differ between them — "
            f"a Debian grub.d drop-in is read by nothing on Fedora or Arch, and "
            f"/etc/pam.d fights authselect there. Restoring it will not break "
            f"the transaction, but much of it may simply do nothing."
        )
    return ""
