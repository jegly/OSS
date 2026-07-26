# OSS

Operating System Settings. A GTK4 app for Ubuntu 26.04 that turns Linux hardening
into checkboxes, shows you the exact diff of every file it will change, then
applies the lot behind one password prompt.

It installs with `dpkg -i` on a machine that has never been online.

![the sysctl section](docs/screenshot-sysctl.png)

![the dashboard](docs/screenshot-dashboard.png)

> On the name: OSS also means Open Source Software, and Open Sound System, the
> Linux audio API that ALSA replaced. This app writes files called `99-oss.conf`
> into `/etc/modprobe.d`, where that can read as audio configuration. It isn't.

## The problem

Hardening a machine means editing `/etc/default/grub`, dropping files in
`/etc/modprobe.d` and `/etc/sysctl.d`, rewriting `sshd_config`, tightening
`fstab`, and running `ufw` commands from memory. Then doing all of it again on the
next install.

Six months later nobody can say what is set, what broke because of it, or whether
an upgrade quietly reverted half of it.

OSS makes the same edits. The difference is that it shows the diff first, backs up
what it touches, rolls the whole transaction back if any step fails, and re-reads
every value afterwards to check it took. That last part matters more than it
sounds: an invalid sysctl key fails silently. A tool that reports success for a
line which has never done anything is worse than no tool.

## What is in it

24 sections. 484 flags defined in TOML data files, so adding one is editing data
rather than code.

| Group | Sections |
|---|---|
| System | sysctl (kernel, memory, network), GRUB command line, module blacklists, installed packages, bootloader password |
| Network | ufw policies and rules, SSH, DNS over TLS, NetworkManager MAC privacy |
| Access | PAM and passwords, sudo, mount options, file permissions, USB device policy, snap permissions |
| Monitoring | systemd sandboxing, services, auditd, AppArmor, journald, file integrity |
| Desktop | telemetry, automatic updates, screen lock, login screen |

Some of these do things you would otherwise do by hand.

**Packages.** Lists all 1693 installed packages with dpkg's own description,
defaulting to the ones you asked for rather than the ones that arrived as
dependencies. Removal puts the selection through `apt-get --simulate` and shows
what apt would really take with it. On the machine this was built on, ticking
`ubuntu-wallpapers` reports that it would also remove `gdm3` and `gnome-shell`.
`libgtk-3-0t64` comes to 64 packages and 670MB. There is no install path, on
purpose.

**Snap permissions.** Snaps have no permission UI outside `snap connections` and
`snap disconnect`. This lists each snap's interfaces sorted by whether they need a
decision: camera, microphone, `removable-media`, `ssh-keys` first, then the
ordinary ones, then the ones that break the snap if you turn them off.

**Dashboard.** Reports how the machine is configured now, not what this app has
done to it. On the development machine it found five sysctl keys set to
conflicting values in different files, 20 settings living in `/usr/lib/sysctl.d`
where the next package upgrade would overwrite them, a `crashkernel=` reservation
made useless by `kexec_load_disabled=1`, and a default-deny outbound firewall with
no allowance for NTP, so the clock had been drifting.

**Capture.** Reads the effective configuration instead of copying config files,
maps it onto the catalogue, and reports what it found. Reading live state is the
point: a hand-hardened machine collects keys that have never done anything.
`kernel.exec-shield` and `security.bprm_checkIP` were both in the development
machine's config, and neither has existed in a kernel for years.

## How it avoids breaking things

**Undo is deleting a file.** Each section writes one drop-in. Delete it, re-run
the reload, and that section is back to stock. Four things have no drop-in
mechanism: `login.defs`, `faillock.conf`, `fstab` and file permissions. Those are
declared as in-place edits, backed up to `.bak`, and only their managed keys are
touched.

**The helper does not trust the GUI.** `/usr/libexec/oss-helper` takes one JSON
file and re-renders every target from the shipped catalogue itself. All it accepts
is flag ids and values, each checked against the catalogue's own allowlist.
Nothing is interpolated into a shell, and every command it can run is on a fixed
list. Where free-form input exists it is pattern-checked at both ends: a port, a
unit name, a snap plug reference, a package name.

**Validators run before writes.** `sshd -t` on the candidate config. `visudo -c`
on the candidate sudoers. `auditctl -R` on the candidate rules. A live
`mount -o remount` before `fstab` is touched, so an option set the kernel rejects
fails while the filesystem is still mounted rather than at boot.

**Read-back after apply.** Every value is re-read and reported as in effect,
waiting for a reboot, or did not take.

**Irreversible things are gated.** `kexec_load_disabled`, `modules_disabled`,
`lockdown=confidentiality` and audit `-e 2` are never included by a preset except
`paranoid`, and Apply stays disabled until you have scrolled to the end of the
risk summary.

**It checks the platform rather than assuming it.** Ubuntu 26.04 ships `sudo-rs`,
which implements a subset of sudoers and rejects `logfile`, `log_input`,
`log_output` and `requiretty`. Those four are greyed out with the reason instead
of failing the transaction at validation time. Drop-in directories are checked for
the include line that makes them work, because writing to `/etc/sudoers.d` when
`/etc/sudoers` has no `@includedir` produces a file that is silently ignored.

## Install

```
sudo dpkg -i oss_0.1.0_all.deb
```

One package, 4.7MB, containing the app, 12 typefaces, the icon set and the
catalogue. Every dependency is present on a stock Ubuntu desktop: `python3`,
`python3-gi`, `gir1.2-gtk-4.0`, `gir1.2-adw-1`, polkit, `fontconfig`.

Build it yourself:

```
./tools/build-deb.sh
./tools/packaging-gate.sh
```

A few sections need an optional tool, and say so when it is missing rather than
hiding: `auditd`, `usbguard`, `debsums`, `apparmor-utils`, `openssh-server`.

## Appearance

114 palettes, ported from a Compose theme set: Catppuccin at 4 flavours by 14
accents, Dracula light and dark by 7 accents, and 44 Ptyxis terminal palettes
carrying their full 16-slot ANSI tables. Plus a glass mode with translucent
surfaces and a hairline edge.

Terminal palettes were designed for terminal text, and several fall well under
WCAG AA once they are driving UI chrome. C64 reads at 1.5:1. Rather than dropping
those palettes, colours are walked away from the background until they clear the
threshold.

## Development

```
PYTHONPATH=src python3 oss              # run from the tree
python3 -m unittest discover -s tests   # 81 tests
python3 tools/audit-targets.py          # check every target against this system
python3 tools/screenshot.py out.png --section ufw
python3 tools/build_presets.py          # regenerate the derived presets
```

Modules directly under `src/ossgui/` are stdlib-only so the privileged helper can
share them. Anything importing `gi` lives in `src/ossgui/ui/`.

`tools/audit-targets.py` is worth running after any change to a target path. It
checks that no file we write is owned by a package unless declared in-place, that
our filename is not already taken, that our file sorts last so our values win,
that the consuming tool reads the directory, and that the rendered output passes
that tool's own validator.

Applying from a source checkout does not work, by design. The helper ships in the
package and lives at `/usr/libexec/oss-helper`, so Apply refuses rather than
half-working. Install the deb to test it.

## Known limits

`dpkg -i` on a fresh, offline 26.04 VM has not been run. That is the install
promise, and the packaging gate says outright that it cannot substitute for it.

Applying to a live machine has not been done either. `fstab`, SUID stripping,
USBGuard, faillock and `kernel.modules_disabled` each lock you out in a different
way. Test those in a VM snapshot.

`sysctl --system` applies `/etc/sysctl.conf` after `/etc/sysctl.d`, so a key set
in both is written by this app and then immediately overridden. Boot uses
`systemd-sysctl`, which does not read that file at all, so such a setting fails on
Apply and then starts working after a reboot. The app detects this and names the
keys. It will not edit your `/etc/sysctl.conf` for you.

## Licence

GPL-3.0.
