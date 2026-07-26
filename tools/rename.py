#!/usr/bin/python3
"""Rename the application. Kept in-tree because it was used for real once.

    python3 tools/rename.py            # apply the rename below
    python3 tools/rename.py --check    # report leftovers only

Renaming after release is not free: the drop-in filenames under /etc carry the
name, so a machine that installed the old version keeps orphaned files the new
version does not recognise. This was run before the first release, when it was.
"""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Old path -> new path. Done with `git mv` so history follows.
MOVES = [
    ("src/ossgui", "src/ossgui"),
    ("oss", "oss"),
    ("helper/oss-helper", "helper/oss-helper"),
    (
        "data/polkit/io.github.jegly.OSS.policy",
        "data/polkit/io.github.jegly.OSS.policy",
    ),
    ("data/desktop/oss.desktop", "data/desktop/oss.desktop"),
]

#: Longest patterns first, so "oss-helper" is not eaten by "oss".
SUBS = [
    ("io.github.jegly.OSS", "io.github.jegly.OSS"),
    ("OSS", "OSS"),
    ("oss-helper", "oss-helper"),
    ("oss-fonts", "oss-fonts"),
    ("oss-extras", "oss-extras"),
    ("99-oss", "99-oss"),
    ("01_oss_password", "01_oss_password"),
    ("OSS_ROOT", "OSS_ROOT"),
    ("OSS_DATA", "OSS_DATA"),
    ("OSS_DEV_HELPER", "OSS_DEV_HELPER"),
    ("oss", "oss"),
    ("ossgui", "ossgui"),
    # GObject type names, which have to stay unique per process.
    ("OssMainWindow", "OssMainWindow"),
    ("OssFlagCard", "OssFlagCard"),
    ("OssGroupHeader", "OssGroupHeader"),
    ("OssApplication", "OssApplication"),
    ("OssReviewDialog", "OssReviewDialog"),
    ("OssApplyDialog", "OssApplyDialog"),
    ("OssAppearanceDialog", "OssAppearanceDialog"),
    ("OssCaptureDialog", "OssCaptureDialog"),
    ("OssDashboard", "OssDashboard"),
    ("OssFirewallPage", "OssFirewallPage"),
    ("OssServicesPage", "OssServicesPage"),
    ("OssApparmorPage", "OssApparmorPage"),
    ("OssIntegrityPage", "OssIntegrityPage"),
    ("OssSandboxPage", "OssSandboxPage"),
    ("OssBootloaderPage", "OssBootloaderPage"),
    ("OssPermissionsPage", "OssPermissionsPage"),
    ("OssFstabPage", "OssFstabPage"),
    ("OssUsbPage", "OssUsbPage"),
]

TEXT_SUFFIXES = {
    ".py", ".toml", ".md", ".sh", ".policy", ".desktop", ".rules", ".conf", ".txt",
}
#: Extensionless files that are still text.
TEXT_NAMES = {
    "oss", "oss-helper", "oss", "oss-helper",
    "rules", "control", "changelog", "compat", "format", "postinst", "postrm",
}
SKIP_DIRS = {".git", "build", "docs", "__pycache__"}


def text_files() -> list[pathlib.Path]:
    out = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix in TEXT_SUFFIXES or path.name in TEXT_NAMES:
            out.append(path)
    return out


def apply() -> int:
    for source, destination in MOVES:
        old, new = ROOT / source, ROOT / destination
        if not old.exists():
            continue
        new.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["git", "mv", str(old), str(new)], cwd=ROOT, capture_output=True, text=True
        )
        if result.returncode != 0:
            old.rename(new)  # not tracked by git yet
        print(f"  moved    {source} -> {destination}")

    changed = 0
    for path in text_files():
        try:
            original = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        text = original
        for old_text, new_text in SUBS:
            text = text.replace(old_text, new_text)
        if text != original:
            path.write_text(text, encoding="utf-8")
            changed += 1
    print(f"  rewrote  {changed} files")
    return 0


def check() -> int:
    """Report leftover references to the previous name.

    The patterns are assembled from fragments rather than written literally,
    because this script is itself subject to the substitution above — a literal
    would have been rewritten along with everything else, leaving the check
    searching for the *new* name and reporting every file in the tree.
    """
    old = "hardening" + "-gui"
    stale = [
        old,
        old.replace("-", ""),
        "org." + "hardening",
        "Hardening" + " Control Center",
    ]
    skip_files = {"BUILD_PLAN.md", "GUI_MOCKUP.html", "rename.py"}

    found = 0
    for path in text_files():
        if path.name in skip_files:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for pattern in stale:
            if pattern in text:
                print(f"  LEFTOVER {path.relative_to(ROOT)}: {pattern}")
                found += 1
    if found:
        print(f"\n{found} leftover reference(s).")
        return 1
    print("  no leftover references to the previous name")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="report leftovers only")
    args = parser.parse_args()
    return check() if args.check else apply()


if __name__ == "__main__":
    sys.exit(main())
