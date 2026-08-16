# OSS 1.0.0

**27 sections · 689 settings · 285 tests**

The first stable release. Three new sections, a substantially larger catalogue,
and a set of fixes to a single recurring class of bug: settings the app reported
as applied that were doing nothing at all.

---

## Read this before upgrading from 0.1.1

**The grub section now edits `/etc/default/grub` directly.** Releases up to 0.1.1
wrote `/etc/default/grub.d/99-oss.cfg` instead. That works on Debian, and it
splits the truth across two files — the `GRUB_CMDLINE_LINUX_DEFAULT` you read in
`/etc/default/grub` was not the line that booted, and anything you set there by
hand was silently overridden by the drop-in sourced after it.

On the first apply after upgrading, OSS removes the stale
`/etc/default/grub.d/99-oss.cfg`. It has to: `grub-mkconfig` sources that
directory *after* the main file, so leaving it would let an old drop-in quietly
outrank everything merged into the real one. The file is backed up before it is
removed, like every other file this app touches.

Your existing `/etc/default/grub` is merged into, not replaced. Comments,
ordering, `GRUB_DISTRIBUTOR`'s command substitution and every token OSS does not
manage are preserved byte for byte. Tokens for keys OSS *does* manage are
rebuilt from your selection, so a key set twice by hand collapses to one value.

**Two sysctl settings were removed** — `net.ipv4.conf.all.mc_forwarding` and its
IPv6 counterpart. Both shipped in all five presets. See below.

---

## New

### Kernel debloat

A stock Ubuntu kernel ships around 6,900 loadable modules and boots using about
130. Every one of the rest is code the kernel will autoload on demand: a device
appearing, an image being mounted, a packet arriving for a protocol nobody uses.
That autoload path is the attack surface this section closes.

It browses all of them, classified against what the running system actually
depends on rather than against a static list:

| | |
|---|---|
| **In use** | Loaded now, or has loaded dependents, or is a mounted filesystem. Not offered at all. |
| **Risky** | Not loaded, but storage, input, HID, USB, filesystem, crypto or graphics — where "not loaded now" does not mean "not needed at next boot". |
| **Candidate** | Not loaded, and nothing has asked for it. A candidate, not a guarantee. |

On a typical desktop that comes out at roughly 126 / 1,258 / 5,517.

Blacklisting only. Deleting the `.ko` files is explained in the section and not
offered: it buys nothing that `install <mod> /bin/false` does not already buy,
and it costs you dpkg integrity, every kernel update putting the files back, and
any way to undo it without rescue media.

Writes `/etc/modprobe.d/98-oss-debloat.conf` — deliberately a different file from
the curated section's `99-oss.conf`, so reverting one does not disturb the other
— then runs `depmod` and rebuilds the initramfs. That rebuild is not optional:
the initramfs carries its own copy of `modprobe.d`, so without it a blacklisted
module still loads during early boot.

### TPM and measured boot

Whether this machine has a TPM, what the firmware measured into it, whether
`/dev/tpmrm0` exists, and — the part that actually matters — whether the disk key
is sealed to it.

A TPM with nothing bound to it protects nothing, and one that unseals with no PIN
means powering the machine on is enough to decrypt it. That is reported as a
finding, not buried.

Read-only by design. Sealing a disk key wrong locks you out of your own disk, the
recovery path is a passphrase you may not have set, and the operation belongs to
`systemd-cryptenroll` rather than to a checkbox. The page prints the exact
command instead.

### CPU vulnerabilities on the dashboard

Reads `/sys/devices/system/cpu/vulnerabilities` and reports what is mitigated,
what this CPU is not affected by, and what is still vulnerable — worst first,
with "Not affected" folded away.

This is the one part of the app the catalogue cannot change: the kernel decides
what it can mitigate, and some bugs have no fix at all. Worth showing precisely
because a machine can be fully hardened by this app and still be vulnerable here.
Where the catalogue has an unapplied mitigation for a vulnerable bug, the row
links straight to it.

### fstab live state

`/etc/fstab` is the request made at boot; `/proc/mounts` is the answer. The
section now reads both and shows where they disagree — an entry hardened in fstab
but never remounted, an option live but not in fstab, and filesystems mounted
with no fstab entry at all.

That last case matters more than it sounds: `/tmp` and `/dev/shm` are mounted by
systemd on most machines with no fstab line, so a page built only from fstab
never showed two of the three filesystems §4.10 most wants hardened.

---

## Catalogue

**614 → 689 settings.**

| Section | Added |
|---|---|
| **sysctl** | 27 `conf.default.*` counterparts. Setting only `conf.all` hardens the interfaces that exist when sysctl runs and leaves the template new ones are built from at the kernel default — so a VPN, container bridge or USB tether appearing later comes up unhardened. |
| **grub** | ITS, TSA and VMSCAPE mitigations; opt-in L1D flush; `init_mlocked_on_free`; `bdev_allow_write_mounted`; `usbcore.authorized_default`. |
| **ssh** | 14, including `PerSourcePenalties` and `PerSourceMaxStartups` (OpenSSH 9.8+ rate limiting, which does what fail2ban was installed for), `PermitOpen`/`PermitListen`, `RekeyLimit`, `CASignatureAlgorithms`, and GSSAPI/Kerberos off. |
| **auditd** | 12, including the identity files the original rule missed — it watched `/etc/passwd` alone, so a password change, a group membership change or a hand-edited hash went unrecorded. Plus `chown` syscalls, session records and `clock_adjtime`. |
| **desktop** | 15 privacy and lockdown keys, including the two `media-handling` automount settings — between them, an inserted disk was mounted and opened before you had decided you trusted it. |
| **ufw** | 20 → 43 one-click ports in six categories, three default-policy postures, four more outbound allowances, and source/destination addresses plus comments in the rule builder — all of which the `Rule` model already supported and only the UI could not reach. |

Every CPU-mitigation flag now carries an **Affects:** line on the card face
naming the hardware it applies to, so a preset captured on one machine can be
judged before it is applied on another.

---

## Fixes

### Settings that reported success and did nothing

**A CPU mitigation was verified by the presence of its kernel parameter, not by
whether it took effect.** `spec_store_bypass_disable=on` on a machine whose
kernel reports `spec_store_bypass: Vulnerable` read as **applied**. The sysfs
verdict is now the authority; a contradiction reads as drift and names the
parameter that overrode it — `nospec_store_bypass_disable` is parsed first by the
kernel and silently discards everything else. `mitigations=off`, `nopti`,
`nospectre_v2` and friends are recognised the same way, with `mds=off`
distinguished from `mds=full`. Where the cause is missing microcode, it says so
rather than implying a kernel flag will help.

**Every `login.defs` setting reported "didn't take" after every apply.** The
in-place write path was the one branch that never stamped the OSS banner, and
that banner is what `probe.is_ours()` looks for — so the app wrote
`PASS_MAX_DAYS 365` correctly and then could not recognise its own edit. All 14
flags in that file were affected.

**Two sysctl settings could never apply.** `net.ipv4.conf.all.mc_forwarding` and
the IPv6 one are mode 0444 in `/proc/sys` — status files reporting whether a
multicast routing daemon has claimed the interface, not settings. `sysctl -w`
returns EPERM on them even as root. Both were in all five shipped presets, so
every apply hit errors on them. Removed.

**Applying grub settings silently loosened `/etc/default/grub` from 0600 to
0644**, undoing a hardening step the permissions section itself offers. In-place
writes now preserve the file's existing mode.

**One audit rule could take down the entire audit configuration.** `auditd` loads
a rule file as a set — a single `-w` on a path that does not exist fails *every
other rule in the file*. The "Logins and sessions" flag bundled five watches,
three of them on paths absent from a current Ubuntu (`/var/run/utmp` — systemd
256 dropped utmp — plus `/var/run/faillock` and historically wtmp/btmp). Split
into one watch per flag, each gated on its own path. `audit_kernel_params` had
the same problem: it watched `/etc/sysctl.conf`, which modern Ubuntu does not
ship, as its primary key.

**`ssbd=force-on` is an arm64 parameter** and was offered on x86, where the kernel
lists it under "Unknown kernel command line parameters" and ignores it. Now gated
by architecture. An `arch:` capability was added for this class of problem.

**`thunderbolt_net` was not blacklisted** while `thunderbolt` was.

### Interface

**A greyed-out card gave no reason.** The explanation was attached as a tooltip,
and GTK does not deliver motion events to an insensitive widget, so it could
never be shown — a whole section of them looked broken with nothing on screen to
say why. The reason is now rendered inside the card, and a section whose package
is missing shows a row naming it with a copyable install command.

**"Not affected" CPU mitigations are selectable again.** They were disabled,
which took the decision away over a verdict that a microcode update can change,
that the kernel does not always get right, and that does not travel with a
preset. They now carry an advisory note instead. "Unavailable" is reserved for
things that genuinely cannot work here.

**The unit and package browsers no longer stop at a fixed cap** with no way to
reach the rest. Both page in, with "Show more" and "Show all", and reset to one
page when the filter changes.

**Overview covered 14 of the 25 sidebar categories.** The 11 sections with their
own editor have no flags, so they never appeared and there was no sign they
existed. They are now listed and linked at the bottom.

**About declared GPL-3.0.** The project is Apache-2.0.

---

## Distro support

The grub section is **no longer Debian-only**. `/etc/default/grub` is read by
every family and the reload was already resolved per family, so its 61 settings
now apply everywhere.

**672 of the 689 settings are distro-neutral.** `updates` remains the only
section skipped elsewhere — `/etc/apt/apt.conf.d` has no equivalent, Fedora uses
`dnf-automatic` and Arch has nothing at all.

---

## Appearance

Defaults are now Ptyxis **Twilight**, **Quicksand**, glass mode on at **0.60**.
Existing settings in `~/.config/oss/settings.toml` are untouched; delete that
file to pick the new defaults up.

---

## Tests

**234 → 285.** The suite now runs green from a clean checkout — two tests were
reading the host's real `/etc` rather than their own fixture, because `OSS_ROOT`
relocates writes but not reads, so they failed on any machine that already had an
`/etc/sysctl.d/99-oss.conf`.

New coverage for the grub in-place merge, the debloat model, the sysfs
cross-check, and a set of catalogue invariants that pin the bug class above: no
read-only sysctl may be offered, an audit watch on a path that can be absent must
be gated, a path gate must name a path the flag actually watches, and every CPU
mitigation must carry an `Affects:` line.

---

## Install

| Distribution | Command |
|---|---|
| **Debian · Ubuntu · Mint · Pop!\_OS · elementary · Zorin** | `sudo apt install ./oss_1.0.0_all.deb` |
| **Arch · Manjaro · EndeavourOS · CachyOS** | `sudo pacman -U oss-1.0.0-1-any.pkg.tar.*` |
| **Fedora · Nobara · RHEL · Rocky · Alma** | `sudo dnf install oss-1.0.0-1.noarch.rpm oss-fonts-1.0.0-1.noarch.rpm` |
| **openSUSE Tumbleweed · Leap** | `sudo zypper install oss-1.0.0-1.noarch.rpm oss-fonts-1.0.0-1.noarch.rpm` |

The RPM ships the typefaces separately — install both, or the interface falls
back to system fonts.
