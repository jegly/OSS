# OSS — working memory

Context that isn't derivable from the code or the git history: what this
project is for, and the decisions already taken that shouldn't be relitigated.

This lives in the repo deliberately, so it travels between machines. It is the
authoritative copy — prefer updating it here over any per-machine memory store.

---

## What OSS is

OSS ("Operating System Security" / "Open Source Security") is a GTK4 +
PyGObject hardening control centre for Linux. The goal is that it becomes the
thing Linux desktops ship by default: everything you would otherwise harden by
hand in a terminal, exposed in a GUI, on every major distro.

**The design rule that settles most decisions:** the app exists to catch
*silent* misconfiguration — a setting written to a file nothing reads, a
drop-in directory no one includes, a key the kernel ignores. So anything OSS
does that quietly fails, hides state behind an unexplained filter, or reports
success it did not verify is not a cosmetic bug; it contradicts the product.
Prefer refusing with a reason over doing nothing visibly.

## Architecture worth knowing

- 614 flags across 25 sections, all declared in TOML under `data/catalogue/`.
  The GUI and the privileged helper both load it, so a flag not in the
  catalogue cannot be applied even by a tampered GUI.
- `helper/oss-helper` is a thin pkexec entry point; the real work is
  `src/ossgui/apply.py`. One password prompt per Apply; the payload is only a
  mapping of flag ids to values, each re-checked against the catalogue.
- Changes are staged unprivileged, shown as a literal file diff, applied as one
  transaction, rolled back as a unit, and read back afterwards.
- `tools/build-deb.sh` builds the .deb without debhelper.
  `tools/packaging-gate.sh` checks everything verifiable outside a VM.
- `tools/screenshot.py out.png [--section <id>]` renders the real widget tree to
  a PNG — the practical way to inspect the UI without a compositor screenshot
  API.
- Tests: `python3 -m unittest discover -s tests` (there is no pytest in this
  environment). `debian/rules` runs them during the package build, which may be
  headless, so any GTK-dependent test must skip without a display — see
  `tests/test_cards.py` for the pattern.

---

## Decision: multi-distro strategy (2026-07-27)

OSS targets Arch, Debian/Ubuntu and Fedora from **one codebase and one
catalogue**, selecting a distro family automatically from `/etc/os-release`
(`ID`, then `ID_LIKE`), with a manual override in Preferences for unrecognised
derivatives.

**Why not a startup picker:** the machine already knows the answer. A wrong
manual answer makes OSS write config to paths that do nothing — silent no-op
config is the exact failure mode the app exists to detect, so a picker would
have it commit the sin it was built to catch.

**Why not separate builds:** it would fork ~16k lines of Python *and* the
614-flag catalogue four ways.

**Why no AppImage or Flatpak:** `data/polkit/com.jegly.OSS.policy` pins
`org.freedesktop.policykit.exec.path` to `/usr/libexec/oss-helper`, and polkit
only honours actions installed under `/usr/share/polkit-1/actions/`. Neither
format can place those, so either would ship a GUI that reads everything and
can never apply anything. Native packages only: `.deb`, `.rpm`, `PKGBUILD`.

**How to implement it:** extend the mechanisms that already exist rather than
adding new ones — `Section.requires_pkg` + `probe.package_present()`, and
`Flag.needs` + `probe.has_capability()` (which already understands `gnu-sudo`
and `path:` tokens). Sections and flags with no equivalent on a family should
*disappear or read as unavailable*, never silently no-op.

### Measured cost of the port

~370 of 614 flags port with little change — `sysctl.d`, `modprobe.d`,
`sudoers.d`, `audit/rules.d`, journald, resolved and NetworkManager drop-ins
are universal. The hard parts:

| area | why it's hard |
|---|---|
| `grub` (54 flags) | `/etc/default/grub.d/` is a Debian invention that Fedora/Arch `grub-mkconfig` never reads; `update-grub` is a Debian wrapper. Fedora adds BLS/`grubby`. |
| `pam` (39 flags) | Edits `login.defs`/`faillock.conf` in place. On Fedora the PAM stack is owned by `authselect` and hand-edits get clobbered. |
| `updates` (17 flags) | apt-only. Fedora is `dnf-automatic`; Arch has no equivalent. |
| 6 sections | Need per-family backends: ufw→firewalld, apparmor→SELinux, packages and integrity→dnf/rpm or pacman, plus snap and usb. |

**Already wrong off Ubuntu, cheap to fix:** the ssh section reloads
`ssh.service` (Fedora/Arch call it `sshd.service`), and modprobe runs
`update-initramfs` (Arch `mkinitcpio -P`, Fedora `dracut -f`).

---

## Open threads

- `apply.py` (982 lines, transaction and rollback) and `probe.py` have been
  read but not audited line by line. A rollback bug is the one failure this app
  cannot afford — audit these before the distro work churns them.
- Large uncommitted working tree (~3,700 lines across 28 files, including the
  whole accounts feature) as of 2026-07-27. Land it before starting the distro
  layer, which touches many of the same files.
