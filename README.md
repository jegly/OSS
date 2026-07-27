<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="OSS.png">
  <source media="(prefers-color-scheme: light)" srcset="OSS2.png">
  <img alt="OSS — Operating System Security" src="OSS.png" width="440">
</picture>

<br>

**Linux hardening in a window. See the diff. Apply once. Roll back if it breaks.**

<br>

![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Linux-333?style=flat-square&logo=linux&logoColor=white)
![GTK4](https://img.shields.io/badge/GTK-4.0-4A90D9?style=flat-square&logo=gtk&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Settings](https://img.shields.io/badge/settings-614-success?style=flat-square)
![Tests](https://img.shields.io/badge/tests-168%20passing-brightgreen?style=flat-square)
![Packages](https://img.shields.io/badge/packages-deb%20%7C%20rpm%20%7C%20pkgbuild-orange?style=flat-square)
![Offline](https://img.shields.io/badge/network-never-critical?style=flat-square)

</div>

---

## Install

| Distribution | Command |
|---|---|
| **Debian · Ubuntu · Mint · Pop!\_OS · elementary · Zorin** | `sudo apt install ./oss_0.1.0_all.deb` |
| **Arch · Manjaro · EndeavourOS · CachyOS** | `sudo pacman -U oss-0.1.0-1-any.pkg.tar.*` |
| **Fedora · Nobara · RHEL · Rocky · Alma** | `sudo dnf install oss-0.1.0-1.noarch.rpm` |
| **openSUSE Tumbleweed · Leap** | `sudo zypper install oss-0.1.0-1.noarch.rpm` |

Or let it work out which one your system wants, build it, and install it:

```bash
./tools/install.sh
```

It reads `/etc/os-release` the same way the app does, prints the exact command before running it, and takes `--dry-run` if you want to see that first. It downloads nothing.

> [!IMPORTANT]
> Read [Distro support](#distro-support) before installing on Arch or Fedora. The packaging is finished; the catalogue underneath it is not.

### Requirements

Everything is present on a stock desktop: `python3` (3.11+), `python3-gi`, GTK 4, libadwaita, polkit, fontconfig. The package is 4.6 MB and contains the app, the catalogue, the icon set and twelve typefaces.

There is **no AppImage, Flatpak or Snap**, and there will not be. See [Why no AppImage](#why-no-appimage-flatpak-or-snap).

---

## What is OSS?

OSS — Operating System Security — is a GTK4 app that puts Linux hardening settings in a window. You tick what you want, it shows you the exact diff of every file it is about to change, and applies the whole lot behind one password prompt.

It installs on a machine that has never been online.

> On the name: OSS also means Open Source Software, and Open Sound System, the Linux audio API that ALSA replaced. This app writes files called `99-oss.conf` into `/etc/modprobe.d`, where that can read as audio configuration. It isn't.

---

## Why

There's no shortage of advice on hardening a Linux box. The Arch wiki, the CIS benchmarks, a hundred blog posts, and everybody's own half-remembered shell script all cover roughly the same ground. Knowing what to set was never really the hard part.

The hard part is that the settings live in about fifteen different places, in five different file formats, and there's nowhere you can look at all of them at once. So you edit `/etc/default/grub`, drop a file in `/etc/sysctl.d`, another in `/etc/modprobe.d`, rewrite half of `sshd_config`, tighten `fstab`, run some `ufw` commands you half remember, and then six months later you can't say what you set, what broke because of it, or whether a distro upgrade quietly put some of it back.

What makes that genuinely bad rather than just annoying is that most of these mistakes are **silent**:

- A misspelled sysctl key doesn't error, it's just ignored.
- A file in `/etc/sudoers.d` does nothing at all unless `/etc/sudoers` has the `@includedir` line, and nothing tells you it's being skipped.
- Settings in `/usr/lib/sysctl.d` get replaced on the next package upgrade.

You don't generally discover that your hardening did nothing — you just carry on believing it worked.

OSS makes the same edits you would. What it adds is that you see the diff before anything is written, everything it touches is backed up, a failure anywhere rolls the entire transaction back, and afterwards it re-reads every value off the live system to confirm the setting actually took.

### Distro-hopping without losing your posture

Changing distro costs you your security posture. Someone who has spent years working out what to set on Ubuntu moves to Arch and is more or less starting again — different paths, different tooling, different defaults, and the same settings living somewhere else entirely. The concepts carry over perfectly well; none of the specifics do. So people either spend a fortnight relearning it or, more often, just don't bother, and run a less secure machine than the one they left.

OSS is meant to carry that across. Same settings, described the same way, with the app working out where they actually live on the machine you're on now. **Capture** reads your current configuration into a preset, and applying that preset on the new install should put you back roughly where you were.

### The threat model moved

Local hardening used to be easy to skip on a desktop: if something is already running as your user, the reasoning went, you have lost anyway. That was never quite true, but it was close enough while the only things running as you were things you had personally installed and understood.

It isn't close enough now. A normal desktop runs coding agents, editor extensions, language servers, MCP servers and package post-install scripts — all with your full user permissions, most pulling code you have not read, some of it chosen at runtime by a model. None of that needs to be malicious to be a problem. The interesting question stopped being *"is this process trusted"* and became *"how much can it reach if it turns out not to be"*.

Nothing here is new, which is rather the point — the kernel has had most of it for a decade:

| Setting | What it stops |
|---|---|
| `kernel.yama.ptrace_scope` | One process reading another's memory — how a browser token or SSH agent key gets lifted |
| `fs.protected_symlinks` · `fs.protected_regular` | Symlink races that turn a world-writable temp directory into arbitrary file overwrite |
| `kernel.unprivileged_userns_clone` | The usual route from unprivileged code to kernel attack surface |
| Per-unit systemd sandboxing | What a compromised service can see of the rest of the filesystem |
| USB device policy · snap permissions | Physical and packaged-app reach |

What's missing was never the mechanism. It's that almost nobody turns them on, because until now you had to know they existed, know what each one breaks, and find them across fifteen files.

### How it compares

| | Preview | Undo | Verifies it took | Scope |
|---|---|---|---|---|
| **OSS** | Full file diff | Transaction rollback | Reads back live state | 614 settings, 25 areas |
| Lynis and other auditors | — | — | — | Reports only, you fix it |
| SCAP / OpenSCAP | Profile-level | — | Scan re-run | Compliance reporting |
| Hardening scripts | — | — | — | Applies blind |

---

## Screenshots

| | |
|:---:|:---:|
| ![Dashboard](docs/shots/dashboard.png) | ![sysctl](docs/shots/sysctl.png) |
| **Dashboard** — what the machine is actually doing, and what's quietly wrong with it | **sysctl.d** — 144 kernel, memory and network settings |
| ![GRUB](docs/shots/grub.png) | ![Review](docs/shots/review-summary.png) |
| **GRUB** — kernel command line, every flag risk-rated | **Review** — every file and command, before anything is written |
| ![Packages](docs/shots/packages.png) | ![Accounts](docs/shots/accounts.png) |
| **Packages** — removal with the real dependency cascade | **Accounts** — users, groups and the system accounts nothing else cleans up |
| ![Firewall](docs/shots/firewall.png) | ![Snap](docs/shots/snap.png) |
| **Firewall** — ufw policies and rules | **Snap** — the permission UI snapd doesn't have |
| ![Permissions](docs/shots/permissions.png) | ![Integrity](docs/shots/integrity.png) |
| **Permissions** — SUID/SGID review and file modes | **Integrity** — package verification and a full baseline |
| ![Services](docs/shots/services.png) | ![AppArmor](docs/shots/apparmor.png) |
| **Services** — what's running that needn't be | **AppArmor** — profile modes and unconfined processes |
| ![modprobe](docs/shots/modprobe.png) | ![PAM](docs/shots/pam.png) |
| **modprobe.d** — 170 kernel modules you can refuse to load | **PAM** — password quality, lockout and login policy |
| ![auditd](docs/shots/auditd.png) | ![Appearance](docs/shots/appearance.png) |
| **auditd** — what gets recorded, and where it goes | **Appearance** — 114 palettes, contrast-corrected |

---

## What's in it

**25 sections, 614 settings.** All of it lives in TOML data files under `data/catalogue/`, so adding a setting means editing data, not code.

| Group | Sections |
|---|---|
| **System** | sysctl (kernel, memory, network), GRUB command line, module blacklists, installed packages, bootloader password |
| **Network** | ufw policies and rules, SSH, DNS over TLS, NetworkManager MAC privacy |
| **Access** | PAM and passwords, users and groups, sudo, mount options, file permissions, USB device policy, snap permissions |
| **Monitoring** | systemd sandboxing, services, auditd, AppArmor, journald, file integrity |
| **Desktop** | telemetry, automatic updates, screen lock, login screen |

### Worth calling out

**Dashboard** — reports how the machine is configured right now, regardless of whether this app had anything to do with it. On the machine I built this on, it turned up five sysctl keys set to conflicting values in different files, 20 settings sitting in `/usr/lib/sysctl.d` where a package upgrade would overwrite them, a `crashkernel=` reservation that `kexec_load_disabled=1` had quietly made useless, and a default-deny outbound firewall with no rule for NTP, which explained why the clock kept drifting.

**Packages** — lists everything installed with the package manager's own description, defaulting to packages you asked for rather than ones that arrived as dependencies. Removals go through a simulated run first, so ticking `ubuntu-wallpapers` reports that it would also take `gdm3` and `gnome-shell`, and `libgtk-3-0t64` comes to 64 packages and 670 MB. There's no install path, deliberately.

**Users and groups** — removing a package doesn't remove the system account it created. Debian avoids doing that on purpose, since the UID might still own files somewhere on disk, so these accounts accumulate and nothing ever cleans them up. The account you're running as, and anything with UID 0, are refused — in the GUI, and again independently in the privileged helper.

**Snap permissions** — snaps have no permission UI at all outside `snap connections` and `snap disconnect`. Interfaces are sorted by whether they need a decision from you: camera, microphone, `removable-media` and `ssh-keys` first, then the mundane ones, then the ones that will break the snap if you revoke them.

**Capture** — reads the effective configuration rather than copying config files around, maps what it finds onto the catalogue, and tells you what it saw. A machine hardened by hand accumulates keys that stopped doing anything years ago; this one had `kernel.exec-shield` and `security.bprm_checkIP` sitting in its config, neither of which has existed in a kernel for a very long time.

---

## Not breaking your machine

| Mechanism | How it works |
|---|---|
| **Undo is deleting a file** | Each section writes a single drop-in. Remove it, re-run the reload, that section is back to stock. |
| **In-place edits are backed up** | `login.defs`, `faillock.conf`, `fstab` and file permissions have no drop-in mechanism, so they get a `.bak` and only their managed keys are touched. |
| **The helper doesn't trust the GUI** | `/usr/libexec/oss-helper` takes one JSON file and re-renders every target from the shipped catalogue itself. It accepts only flag ids and values, each checked against the catalogue's own allowlist. |
| **Nothing reaches a shell** | Every command is on a fixed list. Free-form input is pattern-checked at both ends — ports, unit names, snap plugs, package names, account names. |
| **Validators run first** | `sshd -t`, `visudo -c`, `auditctl -R` against the candidate file. For `fstab`, a live `mount -o remount`, so an option the kernel won't accept fails while the filesystem is still mounted rather than at boot. |
| **One transaction** | Any failure restores every file and inverts the unit changes. |
| **Read-back after apply** | Every value is re-read off the live system and reported as in effect, waiting for a reboot, or didn't take. |
| **Irreversible things are gated** | `kexec_load_disabled`, `modules_disabled`, `lockdown=confidentiality` and audit `-e 2` appear in no preset except `paranoid`, and Apply stays disabled until you've scrolled to the end of the risk summary. |
| **The platform is checked, not assumed** | Ubuntu 26.04 ships `sudo-rs`, which rejects four sudoers directives GNU sudo has. Those are greyed out with the reason rather than failing the transaction at validation time. |

---

## Distro support

The packaging is portable. The catalogue is not yet.

The app works its family out from `/etc/os-release` at startup — not per-distro forks, and not a picker, because the machine already knows the answer and a wrong answer would write config to paths that silently do nothing. Set `OSS_DISTRO_FAMILY` to override.

About **370 of the 614** settings are already distro-neutral: `/etc/sysctl.d`, `/etc/modprobe.d`, `/etc/sudoers.d`, `/etc/audit/rules.d` and the journald, resolved and NetworkManager drop-in directories work the same way everywhere. Two reload commands and three unit names are resolved per family:

| Debian | Arch | Fedora · openSUSE |
|---|---|---|
| `update-grub` | `grub-mkconfig -o /boot/grub/grub.cfg` | `grub2-mkconfig -o /boot/grub2/grub.cfg` |
| `update-initramfs -u` | `mkinitcpio -P` | `dracut --force --regenerate-all` |
| `ssh.service` | `sshd.service` | `sshd.service` |
| `smbd` · `nmbd` · `rsync` | `smb` · `nmb` · `rsyncd` | `smb` · `nmb` · `rsyncd` |

These do **not** translate and are Debian-shaped today:

| Section | Problem elsewhere |
|---|---|
| grub (54 settings) | `/etc/default/grub.d/` is a Debian invention — Fedora and Arch's `grub-mkconfig` never reads it |
| updates (17 settings) | writes `/etc/apt/apt.conf.d`; Fedora uses `dnf-automatic`, Arch has no equivalent |
| pam (39 settings) | edits `login.defs` in place, but on Fedora the PAM stack belongs to `authselect`, which overwrites it |
| ufw · apparmor · packages · integrity | need firewalld, SELinux, and dnf/rpm or pacman backends |

The two whose target file has no equivalent — grub and updates — declare `families = ["debian"]` and are skipped entirely elsewhere, in the GUI and independently in the helper. Substituting only their reload command would have been worse than leaving them alone: `grub2-mkconfig` would run happily while the drop-in it was meant to activate sat in a directory nothing reads.

**Until that's finished, treat the Arch and RPM packages as unfinished.** They give you roughly 370 of the 614 settings and are honest about the rest.

### Why no AppImage, Flatpak or Snap

polkit matches an action to **one literal absolute path**. A helper running from a randomised mountpoint can never be authorised, and neither Flatpak nor Snap can install a polkit action into a directory polkit reads. Every workaround ends up being a privileged first-run bootstrap that drops root-owned files outside the package manager — which is exactly the sort of thing this app's integrity section exists to catch.

A hardening tool has to be installable through the mechanism it tells you to trust.

---

## Building from source

```bash
git clone https://github.com/jegly/OSS
cd oss

./tools/build-deb.sh          # Debian, Ubuntu and derivatives
./tools/build-arch.sh         # Arch — needs base-devel
./tools/build-rpm.sh          # Fedora, RHEL, openSUSE

./tools/packaging-gate.sh     # everything checkable without a VM
```

The Arch and RPM wrappers build a source tarball from your working tree, including uncommitted changes, because that's usually the thing you're testing.

### Development

```bash
PYTHONPATH=src python3 oss              # run from the tree
python3 -m unittest discover -s tests   # 145 tests
python3 tools/audit-targets.py          # check every target against this system
python3 tools/screenshot.py out.png --section ufw
python3 tools/build_presets.py          # regenerate the derived presets
```

Modules directly under `src/ossgui/` are stdlib-only, so the privileged helper can import them. Anything that touches `gi` lives in `src/ossgui/ui/`. GTK tests skip themselves when there's no display, since the package build runs the suite in a chroot.

`tools/audit-targets.py` is worth running after changing any target path. It checks that nothing we write is owned by a package unless declared in-place, that our filename isn't already taken, that our file sorts last so our values win, that the consuming tool actually reads that directory, and that the rendered output passes that tool's own validator.

Applying from a source checkout doesn't work and isn't meant to. The helper ships in the package at `/usr/libexec/oss-helper`, so Apply refuses outright rather than half-working.

---

## Appearance

**114 palettes**, ported from a Compose theme set: Catppuccin at 4 flavours × 14 accents, Dracula light and dark × 7 accents, and 44 Ptyxis terminal palettes carrying their full 16-slot ANSI tables. Plus a glass mode with translucent surfaces and a hairline edge.

Terminal palettes were designed for terminal text, and a fair few fall well under WCAG AA once they're driving UI chrome instead — C64 reads at 1.5:1. Rather than drop those palettes, colours get walked away from the background until they clear the threshold.

---

## Known limits

- **Not yet installed on a fresh offline VM.** That's the whole install promise, and `tools/packaging-gate.sh` says plainly it can't stand in for the real thing.
- **Not yet applied to a live machine at full scale.** `fstab`, SUID stripping, USBGuard, faillock and `kernel.modules_disabled` each lock you out in their own distinct way. Use a VM snapshot.
- **`sysctl --system` reads `/etc/sysctl.conf` after `/etc/sysctl.d`**, so a key set in both gets written by this app and then immediately overridden. Boot is different — `systemd-sysctl` doesn't read that file at all — so such a setting appears to fail on Apply and then starts working after a reboot. The app spots this and names the keys; it won't edit your `/etc/sysctl.conf` for you.
- **Immutable distributions** — Silverblue, Kinoite, MicroOS, SteamOS — aren't supported. `/etc` is writable there so most drop-ins would be fine, but the helper can't be installed into a read-only `/usr` without `rpm-ostree` layering and a reboot.
- **`recommended` is generated, not curated.** It is by definition every setting rated `safe`, which is 427 of them. That's a defensible way to stop presets drifting from the catalogue and a poor way to make a recommendation. Treat it as "everything safe", not as advice.

---

## Licence

<div align="center">

![Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge)

</div>

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE).
Copyright 2026 the OSS authors.

The bundled typefaces are under the SIL Open Font License 1.1; Cormorant Garamond is copyright 2015 The Cormorant Project Authors. Full breakdown in [`debian/copyright`](debian/copyright).

---

## Links

| | |
|---|---|
| Repository | https://github.com/jegly/OSS |
| Issues | https://github.com/jegly/OSS/issues |
| Manual page | `man oss` |
| Cormorant Garamond | https://github.com/CatharsisFonts/Cormorant |
| Catppuccin | https://github.com/catppuccin |
| Dracula | https://draculatheme.com |
