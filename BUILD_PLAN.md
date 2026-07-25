# Hardening Control Center — Build Plan

GTK4 app for Ubuntu 26.04. Pick hardening flags from categorised grids, mass-select whole
groups, hit **Apply**, enter password once, done. Simple by default (pick a preset, apply),
advanced when needed (every flag individually toggleable).

Replaces hand-editing `/etc/default/grub`, `/etc/modprobe.d/*`, `/etc/sysctl.d/*`,
`sshd_config`, `fstab` and running `ufw` commands by hand on every new machine.

**Core promise:** `dpkg -i hardening-gui.deb` on a *fresh, offline* Ubuntu install → open app →
pick the **stock** preset → Apply → reboot → *then* connect to the network for the first time.
The machine is hardened before it ever sees a packet.

---

## 1. Stack & packaging — zero-dependency offline install

- **Python 3.14 + PyGObject + GTK4 + libadwaita**, pure Python, stdlib + PyGObject only.
  No pip, no compiled extensions, no vendored wheels, no network at install or runtime.
- **Flags defined in TOML data files**, not code. Adding a flag = editing data.
  Read with stdlib `tomllib`; write profiles with a ~50-line TOML emitter of our own
  (`tomli-w` is *not* on a stock system — do not depend on it).
- **`pkexec` for privilege** — GUI runs as user, one helper does the writes, one password prompt.

### 1.1 Why `dpkg -i` works with no deps

Everything needed ships preinstalled on stock Ubuntu 26.04 desktop (verified on this machine):

| Depends | Stock version | Ships with |
|---|---|---|
| `python3` | 3.14.3 | base system |
| `python3-gi` | 3.56.2 | desktop (GNOME shell tooling) |
| `gir1.2-gtk-4.0` | 4.22.4 | desktop |
| `gir1.2-adw-1` | 1.9.0 | desktop |
| `ufw` | 0.36.2 | base system |
| `policykit-1` / `pkexec` | — | base system |

Declare these as `Depends:` — on any stock desktop they're already satisfied, so `dpkg -i`
succeeds with no apt and no network. Put the GTK stack in `Recommends:` instead if we want the
CLI to install cleanly on Ubuntu Server too (dpkg ignores Recommends; GUI simply isn't there).

**Optional tooling is degrade-gracefully, never a hard dep**: `auditd`, `aide`, `usbguard`,
`debsums`, `apparmor-profiles` sections detect absence and show an "install package X to use
this" state with the exact offline command. Optionally ship a companion
`hardening-gui-extras.deb` bundle (or a directory of cached `.deb`s) for air-gapped installs of
those tools.

`postinst` does nothing but `update-desktop-database`-style local calls. No downloads, ever.

### 1.2 First-boot / offline workflow (the primary use case)

1. Fresh install finishes, machine **stays offline**.
2. `dpkg -i hardening-gui.deb` from USB.
3. Launch → first-run screen offers: **apply a preset** (stock / recommended / paranoid) or
   **capture this system** (§5.2) or *start from scratch*.
4. Review diff → Apply → reboot.
5. Connect to network only after the reboot lands clean.

## 2. Files the app writes

| Section | Target |
|---|---|
| sysctl | `/etc/sysctl.d/99-hardening-gui.conf` |
| modprobe | `/etc/modprobe.d/99-hardening-gui.conf` |
| GRUB | `/etc/default/grub.d/99-hardening-gui.cfg` |
| SSH | `/etc/ssh/sshd_config.d/99-hardening-gui.conf` |
| sudo | `/etc/sudoers.d/99-hardening-gui` (validate with `visudo -c` before install) |
| PAM / login | `/etc/security/pwquality.conf.d/`, `/etc/security/faillock.conf`, `/etc/login.defs` |
| systemd units | `/etc/systemd/system/<unit>.d/99-hardening-gui.conf` drop-ins |
| journald | `/etc/systemd/journald.conf.d/99-hardening-gui.conf` |
| coredumps | `/etc/systemd/coredump.conf.d/99-hardening-gui.conf` |
| resolved | `/etc/systemd/resolved.conf.d/99-hardening-gui.conf` |
| NetworkManager | `/etc/NetworkManager/conf.d/99-hardening-gui.conf` |
| auditd | `/etc/audit/rules.d/99-hardening-gui.rules` |
| fstab | `/etc/fstab` (in-place, backed up — no drop-in mechanism exists) |
| UFW | `ufw` CLI |
| Services | `systemctl mask` / `disable` |
| Permissions | direct `chmod`/`chown`/`chattr` + rollback journal at `/var/lib/hardening-gui/perms.json` |

One file per section, `99-` prefix for precedence. Each backed up to `<file>.bak` before
writing. Delete the file to undo.

**sysctl layering (matters on 26.04):** the vendor defaults live in `/usr/lib/sysctl.d/`
(`/lib` is a symlink to it), and `/etc/sysctl.d/` **overrides** them — same filename in `/etc`
shadows the vendor file entirely, and later-sorting files win key-by-key. The app **writes only
to `/etc/sysctl.d/`** and never touches the vendor layer: package upgrades (procps, systemd)
silently replace files in `/usr/lib/sysctl.d/`, so edits there — like the ones currently on this
machine (§5.3) — get clobbered. Capture (§5.2) *reads* the full effective chain
(`/etc/sysctl.d` → `/run/sysctl.d` → `/usr/lib/sysctl.d` → `/etc/sysctl.conf`, last-wins per
key) and offers to migrate any vendor-layer customisations into the `/etc` layer where they
survive upgrades.

Two exceptions: `fstab` must be edited in place, and the permission controller (§4.11) changes
metadata with no config file behind it. Both get the loudest confirmation, and permissions get a
recorded before-state so "undo" actually works.

## 3. Flag record format

```toml
[[flag]]
id       = "kptr_restrict"
category = "kernel"
group    = "memory"
key      = "kernel.kptr_restrict"
value    = "2"
default  = "0"
title    = "Restrict kernel pointers"
desc     = "Hides kernel addresses in /proc"     # one line: WHAT it does (grid cell)
why      = "Leaked addresses defeat KASLR"       # one line: WHY it's good (overview row)
help     = "Longer text for the tooltip."
risk     = "safe"        # safe | caution | breaking | one-way
breaks   = ""            # what visibly stops working
reboot   = false

# optional — only for non-boolean flags:
values   = ["0", "1", "2", "3"]          # allowed values, in order
labels   = ["off", "children only", "admin only", "locked (one-way)"]

# optional — machine-specific quirks captured into a preset (e.g. an
# `options snd-intel-dspcfg` audio fix). Shown with a chip, skipped by
# default when the preset is applied to different hardware:
hw       = false
```

`desc` is the grid subtitle — keep it under ~40 characters so cells stay uniform.
`risk` drives the card border colour and badge — the UI wording for irreversible is
**one-way** (matches the mockup).

A flag *without* `values` renders as a plain toggle (screenshot style). A flag *with* `values`
renders the same card but the toggle is replaced by a compact dropdown showing the current
label — that's how `ptrace_scope` 0/1/2/3, `rp_filter` strict/loose, and `lockdown`
integrity/confidentiality fit the grid without inventing fake booleans.

---

## 4. Categories

### 4.1 Kernel / memory — sysctl

`kernel.kptr_restrict` 2, `dmesg_restrict` 1, `printk` `3 3 3 3`, `randomize_va_space` 2,
`yama.ptrace_scope` 1/2/3 (3 = irreversible; breaks gdb, strace), `sysrq` 0,
`kexec_load_disabled` 1 (irreversible), `perf_event_paranoid` 3 (breaks perf),
`unprivileged_bpf_disabled` 1, `modules_disabled` 1 (irreversible — apply last),
`io_uring_disabled` 2, `core_pattern` `|/bin/false`, `core_uses_pid` 1, `panic_on_oops` 1,
`panic` 20, `oops_limit` 100, `warn_limit` 100, `ctrl-alt-del` 0, `pid_max` 65536.

`vm.mmap_min_addr` 65536, `mmap_rnd_bits` 32, `mmap_rnd_compat_bits` 16,
`unprivileged_userfaultfd` 0, `max_map_count` 1048576, `panic_on_oom` 0.

`dev.tty.ldisc_autoload` 0, `dev.tty.legacy_tiocsti` 0.

`fs.suid_dumpable` 0, `protected_symlinks` 1, `protected_hardlinks` 1, `protected_fifos` 2,
`protected_regular` 2, `binfmt_misc.status` 0 (breaks Wine, qemu-user).

`net.core.bpf_jit_harden` 2.

### 4.2 Namespaces / AppArmor — sysctl

`kernel.apparmor_restrict_unprivileged_userns` 1 — **breaks Flatpak, Snap, Chrome sandbox,
rootless Docker, bwrap**. Same for `_force`. Plus `_complain` 0,
`apparmor_restrict_unprivileged_unconfined` 1, `apparmor_restrict_unprivileged_io_uring` 1,
`unprivileged_userns_apparmor_policy` 1, `user.max_user_namespaces` 0 (hard version).

`kernel.unprivileged_userns_clone` — **verified: still exists on 26.04** (`=0` live on this
machine, kernel 7.0.0-28) alongside the `apparmor_*` keys. Keep both in the catalogue; the
read-back (§8) is the safety net if a future kernel drops it.

Note: snaps are in active use on this machine *with* the full `apparmor_restrict_*` set
enabled — snapd's profiles carry the `userns` permission — so these are safer than their scary
reputation on 26.04. The hard `user.max_user_namespaces=0` variant is the one that breaks them.

### 4.3 Network — sysctl

**IPv4** — `conf.{all,default}.rp_filter` (1 strict / 2 loose, pick one), `accept_redirects` 0,
`secure_redirects` 0, `send_redirects` 0, `accept_source_route` 0, `log_martians` 1,
`arp_ignore` 1, `arp_announce` 2, `shared_media` 0, `bootp_relay` 0, `proxy_arp` 0,
`forwarding` 0, `drop_gratuitous_arp` 1.

`tcp_syncookies` 1, `tcp_rfc1337` 1, `tcp_timestamps` 0, `tcp_sack` 0 (perf cost on lossy
links), `tcp_dsack` 0, `tcp_fack` 0, `tcp_max_syn_backlog` 4096, `tcp_synack_retries` 2,
`tcp_syn_retries` 3, `tcp_challenge_ack_limit` 1000000, `ip_forward` 0,
`ip_local_port_range` `32768 60999`.

`icmp_echo_ignore_all` 1 (no ping replies; breaks some captive portals),
`icmp_echo_ignore_broadcasts` 1, `icmp_ignore_bogus_error_responses` 1, `icmp_ratelimit` 100.

**IPv6** — `conf.{all,default,lo}.disable_ipv6` 1; if on, grey out the rest.
`accept_ra` 0, `accept_ra_defrtr` 0, `accept_ra_pinfo` 0, `accept_ra_rtr_pref` 0,
`accept_redirects` 0, `accept_source_route` -1, `router_solicitations` 0, `autoconf` 0,
`max_addresses` 1, `use_tempaddr` 2, `temp_prefered_lft` 3600, `temp_valid_lft` 7200.

### 4.4 GRUB / kernel cmdline

Written as `GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT ..."`, then `update-grub`
with exit-code check.

**Memory** — `slab_nomerge`, `init_on_alloc=1`, `init_on_free=1`, `page_alloc.shuffle=1`,
`page_poison=1`, `randomize_kstack_offset=on`, `vsyscall=none`, `debugfs=off`,
`extra_latent_entropy`.

**LSM & lockdown** — `lsm=lockdown,yama,apparmor,bpf`, `lockdown=integrity|confidentiality`,
`apparmor=1`, `module.sig_enforce=1`.
⚠ `lockdown=confidentiality` + `module.sig_enforce=1` + Secure Boot blocks unsigned DKMS
(NVIDIA, VirtualBox, ZFS) without an enrolled MOK. Also blocks kexec, hibernation, `/dev/mem`.

**CPU mitigations** — master toggle plus individual overrides: `mitigations=auto,nosmt`,
`nosmt=force`, `pti=on`, `spectre_v2=on`, `spectre_v2_user=on`, `spec_store_bypass_disable=on`,
`ssbd=force-on`, `l1tf=full,force`, `mds=full,nosmt`, `tsx=off`, `tsx_async_abort=full,nosmt`,
`mmio_stale_data=full,nosmt`, `retbleed=auto,nosmt`, `gather_data_sampling=force`,
`reg_file_data_sampling=on`, `spec_rstack_overflow=safe-ret`, `srbds=on`,
`kvm.nx_huge_pages=force`.
⚠ Anything `nosmt` disables hyperthreading — roughly half your logical cores.
Each row shows live status from `/sys/devices/system/cpu/vulnerabilities/*`; grey out
anything reporting `Not affected`.

**IOMMU / DMA** — `intel_iommu=on`, `amd_iommu=force_isolation`, `iommu=force`,
`iommu.strict=1` (I/O throughput cost), `iommu.passthrough=0`, `efi=disable_early_pci_dma`.

**Misc** — `random.trust_cpu=off`, `random.trust_bootloader=off`, `nohibernate`, `oops=panic`,
`panic=20`, `loglevel=0`, `quiet`, `splash`, `ipv6.disable=1`, `pci=noaer`, `libata.force=noncq`.

Note: `nospec_store_bypass_disable=0` in the current cmdline is not a valid parameter — it gets
passed through to init. Don't carry it into the flag list.

**Debug/perf flags** — `slab_debug=FZP` (currently set on this machine): sanity checks, red
zoning and poisoning on every slab alloc/free. Real hardening value but a heavy performance tax,
and it disables slab merging on its own (making `slab_nomerge` redundant while it's on). Offer
it, badge it `caution: significant slowdown`, and don't put it in the recommended preset.

**kdump conflict check** — if `crashkernel=` is on the cmdline (kdump-tools drops it into
`/etc/default/grub.d/`) *and* `kernel.kexec_load_disabled=1` is set, kdump can never load its
crash kernel: the reserved RAM (hundreds of MB) is pure waste and crash dumps silently don't
happen. Exactly this conflict is live on this machine right now. The app should detect the pair
and offer: disable kdump-tools + drop `crashkernel` (keep kexec disabled — the hardening
choice), or keep kdump working (skip the kexec flag). Never leave both.

### 4.5 Module blacklisting — modprobe

Writes `blacklist <mod>` + `install <mod> /bin/false`. Use `/bin/false` consistently — it
errors loudly instead of silently succeeding like `/bin/true`. Each sub-group gets select-all.

**Filesystems** — `cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `udf`, `ufs`, `gfs2`,
`ksmbd`, `nfs`, `nfsv3`, `nfsv4`, `cifs`, `ntfs`, `ntfs3`, `exfat`, `fat`, `msdos`, `vfat`,
`squashfs`.
⚠ `squashfs` breaks **all Snaps** (Firefox on stock Ubuntu). `vfat` breaks **EFI mounts and
USB sticks**.

**Network protocols** — `dccp`, `sctp`, `rds`, `tipc`, `n-hdlc`, `ax25`, `netrom`, `x25`,
`rose`, `decnet`, `econet`, `af_802154`, `ipx`, `appletalk`, `psnap`, `p8023`, `p8022`,
`can`, `atm`, `llc`.

**Wireless / radio** — `bluetooth`, `btusb`, `btintel`, `btrtl`, `btbcm`, `btmtk`, `ath3k`,
`rfcomm`, `bnep`, `hidp`, `iwlwifi`, `iwlmvm`, `mac80211`, `cfg80211`, `rtl8188eu`,
`rtl8192cu`, `rtl8723be`, `nfc`, `pn533`, `pn544`, `microread`, `nfc_digital`.

**Intel ME / management** — `mei`, `mei_me`, `mei_txe`, `mei_gsc`, `mei_gsc_proxy`, `mei_vsc`,
`mei_vsc_hw`, `mei_wdt`, `mei_phy`, `mei_pxp`, `mei_hdcp`, `microread_mei`, `pn544_mei`,
`intel_vsec`, `intel_pmt`, `pmt_class`, `pmt_discovery`, `pmt_telemetry`, `intel_pmc_core`,
`intel_pmc_bxt`, `intel_pmc_ssram_telemetry`, `iTCO_wdt`, `ipmi_devintf`, `ipmi_msghandler`,
`ipmi_si`, `ipmi_ssif`, `ipmi_watchdog`.
Module names use **underscores** — `mei_me`, not `mei-me`. Hyphenated lines are silently ignored.

**Legacy / DMA-capable buses** — `firewire-core`, `firewire-ohci`, `firewire-sbp2`, `ohci1394`,
`sbp2`, `dv1394`, `thunderbolt` (may kill docks/displays), `pcmcia`, `yenta_socket`, `floppy`,
`joydev`, `usb-storage` (no USB drives), `uas`, `cdrom`, `sr_mod`.

**Legacy audio modems** — `snd-atiixp-modem`, `snd-intel8x0m`, `snd-via82xx-modem`.

**Camera / mic** — `uvcvideo`, `snd_usb_audio`, `videobuf2_v4l2`, `v4l2loopback`, `gspca_main`.

**Virtualisation** — `kvm`, `kvm_intel`, `kvm_amd`, `vboxdrv`, `vboxnetflt`,
`vmw_vsock_vmci_transport`, `vmw_balloon`.

Each cell shows whether the module is **currently loaded** (`lsmod`) and its refcount, so you
know if a blacklist needs a reboot.

### 4.6 Firewall — UFW

Enable/disable · default incoming/outgoing/routed policy · logging level ·
IPv6 on/off · rule list (add, delete, reorder) · `ufw limit` rate limiting.
Presets: *deny all inbound*, *deny inbound + outbound allowlist* (the stock preset, §5.1),
*SSH from LAN only*.

All via the `ufw` CLI — never edit `user.rules` directly.
⚠ If `$SSH_CONNECTION` is set, warn before a default-deny-incoming policy.

**Default-deny-outbound helpers** — the failure modes of `deny outgoing` are always the same
three, so surface them as one-click toggles next to the policy switch:
- `allow out 123/udp` — NTP; without it `systemd-timesyncd` fails and the clock drifts
  (this machine currently blocks it).
- `allow out 853/tcp` — DNS-over-TLS; required the moment §4.19 turns `DNSOverTLS=yes` on.
  The app should cross-check: DoT enabled + 853 not allowed = broken DNS, warn at review time.
- `allow out 67:68/udp` — DHCP renewals on some strict setups.

**Rule hygiene view** — with a default-deny policy, explicit `deny` rules for individual ports
are redundant (this machine has ~30 of them). Keep them if wanted — they hold their position
above any later `allow` — but show them folded into a "redundant with default policy" group so
the list stays readable, with a one-click *clean up* that removes them.

---

## New categories

### 4.7 SSH — `sshd_config.d/`

`PermitRootLogin no`, `PasswordAuthentication no`, `PermitEmptyPasswords no`,
`KbdInteractiveAuthentication no`, `ChallengeResponseAuthentication no`,
`PubkeyAuthentication yes`, `AuthenticationMethods publickey`, `MaxAuthTries 3`,
`MaxSessions 2`, `MaxStartups 10:30:60`, `LoginGraceTime 30`,
`X11Forwarding no`, `AllowAgentForwarding no`, `AllowTcpForwarding no`, `PermitTunnel no`,
`GatewayPorts no`, `PermitUserEnvironment no`, `AllowUsers <list>`, `Protocol 2`,
`ClientAliveInterval 300`, `ClientAliveCountMax 2`, `UsePAM yes`, `StrictModes yes`,
`IgnoreRhosts yes`, `HostbasedAuthentication no`, `Compression no`, `Banner /etc/issue.net`,
`LogLevel VERBOSE`, `Port <n>`.

Modern crypto only: `KexAlgorithms curve25519-sha256`, `Ciphers chacha20-poly1305@openssh.com,
aes256-gcm@openssh.com`, `MACs hmac-sha2-512-etm@openssh.com`,
`HostKeyAlgorithms ssh-ed25519`.

⚠ **Lockout guard.** Before applying, check that at least one authorised key exists for a user
in `AllowUsers`. Run `sshd -t` on the candidate config and refuse to install if it fails. If
`$SSH_CONNECTION` is set, keep the existing session alive and require reconnect confirmation.

### 4.8 Password & login policy — PAM / login.defs

`pwquality.conf` — `minlen 14`, `dcredit -1`, `ucredit -1`, `lcredit -1`, `ocredit -1`,
`minclass 4`, `maxrepeat 3`, `maxsequence 3`, `dictcheck 1`, `usercheck 1`, `enforcing 1`,
`retry 3`, `difok 5`.

`faillock.conf` — `deny 5`, `unlock_time 900`, `fail_interval 900`, `even_deny_root`,
`root_unlock_time 60`, `audit`, `silent`.
⚠ Lockout risk — pair with a "never lock the current user out" sanity check.

`login.defs` — `PASS_MAX_DAYS 365`, `PASS_MIN_DAYS 1`, `PASS_WARN_AGE 14`, `UMASK 077`,
`SHA_CRYPT_MIN_ROUNDS 640000`, `ENCRYPT_METHOD YESCRYPT`, `LOGIN_RETRIES 3`,
`LOGIN_TIMEOUT 60`, `SU_NAME su`, `DEFAULT_HOME no`, `USERGROUPS_ENAB no`.

Also: `pam_pwhistory remember=5`, `pam_wheel` for `su`, `TMOUT=900` shell idle timeout.

### 4.9 sudo hardening — `sudoers.d/`

`Defaults use_pty`, `logfile="/var/log/sudo.log"`, `log_input`, `log_output`,
`timestamp_timeout=0` (password every time), `passwd_tries=3`, `!visiblepw`,
`always_set_home`, `noexec`, `requiretty`, `env_reset`,
`secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"`,
`passwd_timeout=1`, `umask=0027`.

Detection: flag any `NOPASSWD` entries in existing sudoers as findings.
**Always validate with `visudo -c -f <tmpfile>` before installing** — a broken sudoers file
costs you root access.

### 4.10 Filesystem mounts — `/etc/fstab`

Per-mount toggles for `nodev`, `nosuid`, `noexec`, `ro`:

| Mount | Recommended |
|---|---|
| `/tmp` | `nodev,nosuid,noexec` (+ tmpfs) |
| `/var/tmp` | `nodev,nosuid,noexec` |
| `/dev/shm` | `nodev,nosuid,noexec` |
| `/home` | `nodev,nosuid` |
| `/var` | `nodev,nosuid` |
| `/var/log` | `nodev,nosuid,noexec` |
| `/var/log/audit` | `nodev,nosuid,noexec` |
| `/boot` | `nodev,nosuid,noexec` |
| `/boot/efi` | `nodev,nosuid,noexec` |
| `/proc` | `hidepid=2,gid=proc` |

⚠ **Highest brick risk in the app.** `noexec` on `/tmp` breaks some installers, DKMS builds,
and Steam. `hidepid=2` breaks some desktop session tooling. A bad `fstab` line drops you to an
emergency shell at boot.
Mitigation: test each change with `mount -o remount,<opts> <mount>` **before** writing fstab,
and refuse to write any entry that fails the live remount.

### 4.11 Permission controller

A dedicated section, not a flag list. Each row is a path with its **current** mode/owner, a
**recommended** mode, and a plain-English line on what the permission actually protects. User
can accept the recommendation, pick a custom mode from an octal grid, or add their own paths.

#### 4.11.1 Recommended path table

| Path | Now → target | Owner | What it protects |
|---|---|---|---|
| `/boot` | 755 → **700** | root:root | Kernel images and initrd — stops non-root reading or listing your boot set |
| `/boot/grub/grub.cfg` | 444 → **600** | root:root | Boot menu, kernel cmdline — hides your hardening flags |
| `/etc/default/grub` | 644 → **600** | root:root | Same, the source file |
| `/etc/shadow` | 640 → **640** | root:shadow | Password hashes — never make this world-readable |
| `/etc/gshadow` | 640 → **640** | root:shadow | Group password hashes |
| `/etc/shadow-`, `/etc/gshadow-` | → **600** | root:root | Backup copies, often missed and left readable |
| `/etc/passwd` | 644 → **644** | root:root | ⚠ Must stay world-readable — name lookup breaks otherwise |
| `/etc/group` | 644 → **644** | root:root | ⚠ Same |
| `/etc/sudoers` | 440 → **440** | root:root | ⚠ `sudo` refuses to run if this is group/world writable |
| `/etc/sudoers.d/*` | → **440** | root:root | Same |
| `/etc/ssh/sshd_config` | 644 → **600** | root:root | Server config — hides your auth policy and port |
| `/etc/ssh/ssh_host_*_key` | → **600** | root:root | ⚠ Host private keys — `sshd` refuses to start if looser |
| `/etc/ssh/ssh_host_*_key.pub` | → **644** | root:root | Public halves, must stay readable |
| `~/.ssh` | → **700** | user | ⚠ `ssh` ignores keys in a group-writable dir |
| `~/.ssh/authorized_keys` | → **600** | user | Which keys can log in as you |
| `~/.ssh/id_*` | → **600** | user | ⚠ Private keys — `ssh` refuses to use them if looser |
| `~/.gnupg` | → **700** | user | GPG keyring |
| `/root` | 700 → **700** | root:root | Root's home |
| `/home/<user>` | 755 → **750** | user:user | Stops other local users browsing your files |
| `/etc/crontab` | 644 → **600** | root:root | Scheduled root commands |
| `/etc/cron.d` | 755 → **700** | root:root | Same |
| `/etc/cron.{hourly,daily,weekly,monthly}` | 755 → **700** | root:root | Same |
| `/etc/cron.allow`, `/etc/at.allow` | → **600** | root:root | Who may schedule jobs |
| `/var/spool/cron/crontabs` | → **1730** | root:crontab | Per-user crontabs |
| `/var/log` | 755 → **750** | root:syslog | Log directory listing |
| `/var/log/auth.log` | → **640** | syslog:adm | Login attempts, sudo use |
| `/var/log/audit` | → **700** | root:root | ⚠ auditd requires 700; CIS checks this |
| `/var/log/wtmp`, `/btmp`, `/lastlog` | → **660** | root:utmp | Login history |
| `/etc/security/opasswd` | → **600** | root:root | Password history — old hashes live here |
| `/etc/fstab` | 644 → **644** | root:root | Readable is fine; write-protect matters |
| `/etc/machine-id` | 444 → **444** | root:root | Stable host identifier |
| `/etc/apt/sources.list{,.d}` | → **644** | root:root | Where packages come from |
| `/etc/issue`, `/etc/issue.net` | → **644** | root:root | Pre-login banner |
| `/tmp`, `/var/tmp`, `/dev/shm` | **1777** | root:root | ⚠ **Do not** drop below 1777 — the sticky bit is what stops users deleting each other's files. Removing world-write breaks nearly everything |
| `/usr/bin`, `/usr/sbin`, `/usr/lib` | **755** | root:root | ⚠ Never tighten or recurse here — you will break the system |

Rows split into **Recommended** (safe, CIS-aligned), **Aggressive** (`/home` 700, `/boot` 700,
`/var/log` 700 — may break log tooling or shared access), and **Do not change** (shown greyed
with the reason, so it's clear the app deliberately isn't offering them).

#### 4.11.2 SUID / SGID audit

Scan the filesystem for every SUID and SGID binary, list with: path, owning package
(`dpkg -S`), what it's for, and whether stripping the bit is safe.

| Binary | Safe to strip? | Consequence |
|---|---|---|
| `pkexec` | ⚠ **No** | This app needs it to apply anything |
| `sudo` | **No** | Lose privilege escalation |
| `su` | Usually | `sudo -i` covers it |
| `mount`, `umount` | Usually | Only affects non-root manual mounts; udisks handles removable media |
| `chsh`, `chfn` | Yes | Can't change shell/gecos as a user; `usermod` as root still works |
| `newgrp`, `gpasswd` | Yes | Rarely used outside multi-group setups |
| `wall`, `write` | Yes | Terminal broadcast messages |
| `at` | Yes | If you're not using `at` |
| `fusermount3` | ⚠ No | Breaks FUSE — sshfs, AppImage, some file managers |
| `umount.udisks2` | ⚠ No | Breaks removable-media unmount in the desktop |
| `pppd`, `ssh-agent`, `sg` | Usually | Depends on use |
| Unpackaged SUID binaries | — | **Flag loudly** — a SUID binary not owned by any package is a classic persistence mechanism |

Every strip is recorded so the section has a working **restore** — this is the one part of the
app where "undo" has to be a real feature, not just deleting a config file.

#### 4.11.3 Scans (read-only findings)

- World-writable files and directories missing the sticky bit
- Files with no owner or no group (`-nouser -nogroup`) — leftovers from deleted accounts
- Group- or world-writable files in `$PATH`
- Home directories readable by other users
- Dotfiles that are group/world writable
- `.rhosts`, `.netrc`, `.forward` files anywhere

Each finding gets a one-click fix with the resulting `chmod` shown first.

#### 4.11.4 Extras

- **Immutable flag** — `chattr +i` on `/etc/passwd`, `/etc/shadow`, `/etc/group`,
  `/etc/sudoers`, `/etc/ssh/sshd_config`, `/etc/fstab`, `/etc/hosts`, `/etc/resolv.conf`.
  ⚠ Blocks `apt` and `usermod` from updating those files — package upgrades will fail with
  confusing errors. Off by default, clearly labelled.
- **ACLs** — `setfacl` for finer-grained per-user access where mode bits aren't enough.
- **Default umask** — `077` (private) or `027` (group-readable) in `login.defs`, `/etc/profile`,
  and `pam_umask`. Ties to §4.8.

#### 4.11.5 UI for this section

- Octal picker: 3×3 grid of `r w x` checkboxes for owner / group / other, plus setuid, setgid,
  sticky. Live-updates a `0640` readout and a `-rw-r-----` string.
- Owner / group dropdowns populated from `/etc/passwd` and `/etc/group`.
- **Add custom path** — file picker, then the same controls. This is what makes the section
  general rather than a fixed checklist.
- **Recursive toggle, off by default.** When on: show the file count that would be affected
  *before* applying, and hard-block recursion on `/`, `/usr`, `/etc`, `/var`, `/bin`, `/lib`,
  `/boot/efi`. A recursive chmod on `/usr` is unrecoverable without a reinstall.
- Recursion should offer `find -type d` / `-type f` split (dirs 750, files 640) rather than a
  flat mode — a flat `chmod -R 640` strips the execute bit off directories and makes them
  untraversable, which is the single most common way people break their own home directory.
- Diff view before apply: `path: 0755 root:root → 0700 root:root`, one line per change.
- Full rollback list per transaction, since `chmod` has no config file to delete.

### 4.12 systemd service sandboxing — unit drop-ins

Applied per-unit as `/etc/systemd/system/<unit>.d/99-hardening-gui.conf`:

`NoNewPrivileges=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectSystem=strict`,
`ProtectHome=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`,
`ProtectKernelLogs=yes`, `ProtectControlGroups=yes`, `ProtectClock=yes`,
`ProtectHostname=yes`, `ProtectProc=invisible`, `RestrictNamespaces=yes`,
`RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`,
`MemoryDenyWriteExecute=yes`, `SystemCallArchitectures=native`,
`SystemCallFilter=@system-service`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`,
`CapabilityBoundingSet=`, `PrivateUsers=yes`, `IPAddressDeny=any`.

UI: pick a unit → toggle directives → **show `systemd-analyze security <unit>` score before and
after**. That score is the perfect built-in feedback loop for this section.
⚠ `MemoryDenyWriteExecute` breaks anything with a JIT. `ProtectSystem=strict` breaks services
that write outside their state dir.

### 4.13 Services & daemons

Enumerate enabled units and listening sockets (`ss -ltnup`), offer mask/disable:
`avahi-daemon`, `cups`, `cups-browsed`, `bluetooth`, `ModemManager`, `wpa_supplicant`,
`whoopsie`, `apport`, `kerneloops`, `rsync`, `nfs-server`, `rpcbind`, `smbd`, `nmbd`,
`snapd`, `packagekit`, `switcheroo-control`, `power-profiles-daemon`, `gnome-remote-desktop`,
`debug-shell.service` (⚠ should always be masked).

Each row shows which port it listens on, so it's obvious what closes.

### 4.14 Auditd

Enable `auditd`, plus rule groups:
`-e 2` (immutable rules, needs reboot to change), `-b 8192`, `--backlog_wait_time 60000`,
`-f 1` failure mode.

Watch groups (each a select-all): time changes, user/group modification, network environment,
MAC policy (`/etc/apparmor`), login/logout events, session initiation, permission
modifications, unauthorised access attempts, privileged command use, successful file mounts,
file deletion by users, sudoers changes, kernel module load/unload, `execve` for uid 0.

`auditd.conf` — `max_log_file 50`, `num_logs 10`, `space_left_action email`,
`admin_space_left_action halt` (⚠ halts the machine on full disk — off by default),
`disk_full_action`, `flush INCREMENTAL_ASYNC`.

⚠ `-e 2` means no rule changes until reboot. Mark irreversible.

### 4.15 AppArmor

- Set all profiles to `enforce` (vs `complain`), or per-profile toggles.
- Install `apparmor-profiles` and `apparmor-profiles-extra`.
- Enable profiles shipped in `/etc/apparmor.d/disable/`.
- Show unconfined processes that have listening sockets (`aa-unconfined`).
- Toggle `apparmor.d` profiles for browsers, `bwrap`, `cups`, `man`.

### 4.16 Logging — journald

`Storage=persistent`, `Compress=yes`, `Seal=yes` (FSS tamper detection),
`ForwardToSyslog=no`, `SystemMaxUse=1G`, `SystemMaxFileSize=128M`, `MaxRetentionSec=1month`,
`MaxLevelStore=info`, `Audit=yes`, `RateLimitBurst`, `RateLimitIntervalSec`.

Optional: remote syslog forwarding target.

### 4.17 Core dumps

`coredump.conf` — `Storage=none`, `ProcessSizeMax=0`.
`limits.conf` — `* hard core 0`.
Ties to `fs.suid_dumpable=0` and `kernel.core_pattern` in §4.1 — show them as one group.

### 4.18 USB & peripherals

- **USBGuard** — install, generate a policy from currently-connected devices, set
  `ImplicitPolicyTarget=block`, `PresentDevicePolicy=apply-policy`,
  `InsertedDevicePolicy=apply-policy`. ⚠ Generate the allowlist **before** enabling or you lose
  your keyboard. Refuse to enable without a policy containing an HID device.
- `/sys/bus/usb/devices/*/authorized_default` = 0.
- Disable USB autosuspend wakeups, `usbcore.authorized_default=0` cmdline flag.
- Thunderbolt/DMA: `boltctl` policy, `iommu` flags from §4.4.
- Disable wake-on-USB / wake-on-LAN.

### 4.19 DNS & name resolution — resolved

`DNSSEC=yes`, `DNSOverTLS=yes`, `DNS=<resolvers>`, `FallbackDNS=`,
`MulticastDNS=no`, `LLMNR=no` (both are LAN-broadcast name leaks),
`Cache=no-negative`, `ResolveUnicastSingleLabel=no`.

Presets for common privacy resolvers (Quad9, Cloudflare, Mullvad) with DoT hostnames.

### 4.20 NetworkManager & MAC privacy

`wifi.scan-rand-mac-address=yes`, `wifi.cloned-mac-address=random`,
`ethernet.cloned-mac-address=random`, `connection.stable-id`,
`ipv6.ip6-privacy=2`, `connection.mdns=0`, `connection.llmnr=0`.

⚠ Random MAC breaks MAC-based DHCP reservations and some captive-portal / enterprise networks.
Offer `stable` (per-network stable random) as the safer middle option.

### 4.21 Telemetry & crash reporting

Purge/disable: `apport`, `whoopsie`, `kerneloops`, `popularity-contest`, `ubuntu-report`,
`motd-news` (`/etc/default/motd-news` `ENABLED=0`), Snap store telemetry,
GNOME `org.gnome.desktop.privacy` — `report-technical-problems false`,
`send-software-usage-stats false`, `remember-recent-files false`,
`remove-old-temp-files true`, `remove-old-trash-files true`.

### 4.22 Automatic updates

`unattended-upgrades` — enable, security-only vs all, `Automatic-Reboot`,
`Automatic-Reboot-Time`, `Remove-Unused-Kernel-Packages`, `Remove-Unused-Dependencies`,
`Mail` on failure. Plus `APT::Periodic::Update-Package-Lists 1`,
`Download-Upgradeable-Packages 1`, `AutocleanInterval 7`.

Genuinely security-relevant and usually forgotten — unpatched packages beat most of §4.1.

### 4.23 Bootloader password & boot integrity

- GRUB superuser + `password_pbkdf2` — stops anyone editing the cmdline or dropping to a shell
  at the boot menu. Without this, **every kernel hardening flag in §4.4 is one keypress away
  from being removed** by anyone with physical access.
- `GRUB_DISABLE_RECOVERY=true`, `GRUB_DISABLE_OS_PROBER=true`, `GRUB_TIMEOUT=0`.
- Show Secure Boot state, MOK enrollment state, and whether `/boot` is on an encrypted volume.
- ⚠ Forgetting the GRUB password means rescue-media recovery. Confirm twice.

### 4.24 File integrity monitoring — AIDE + package verification

Detect tampering by comparing the live filesystem against a trusted reference. Two tiers,
offered together — a zero-setup quick check and a full-system baseline the user arms once.

**Tier 1 — package verification (no baseline, instant).** `debsums -ac` + `dpkg -V` check every
file installed from a `.deb` against the distro's own checksums. No setup, but only covers
packaged files — blind to anything an attacker *added* that no package owns.

**Tier 2 — full-system baseline (AIDE).** Hash the whole system on a known-clean install, then
detect any later change, including unpackaged files (the classic persistence spot). Needs a
baseline captured while the machine is still trusted.

#### 4.24.1 Baseline lifecycle

| Action | What it does | When |
|---|---|---|
| **Init** | Hash whole system → trusted DB | Once, on a clean install |
| **Check** | Re-hash, diff vs baseline, report only *new* deltas | Scheduled + on demand |
| **Accept** | Fold current state into the baseline | After changes you trust |

Only ever surface changes *new* since the last accepted baseline — never the raw "everything
that differs" dump, which is all noise. That diff-against-trusted-state model is the whole
difference between a usable audit and a wall of false positives.

#### 4.24.2 What AIDE watches

Strong attribute set: `p+i+n+u+g+s+b+m+c+sha256+sha512` (perms, inode, links, owner, group,
size, mtime, ctime, two content hashes). **ctime matters**: mtime is trivially forged
(`touch -r` copies a timestamp), but ctime updates whenever the inode is written and can't be
set directly — a file with a matching mtime but a changed ctime is a tampering tell. Full-system
coverage with volatile paths pruned (`/proc /sys /dev /run /tmp /var/tmp /var/log /var/cache
/var/spool`, `~/.cache`, browser and snap data). **Keep monitored** the paths that actually carry
persistence — `/etc`, `/boot`, `/usr`, `/bin`, `/sbin`, `/lib`, cron dirs, systemd units, and
user dotfiles (`.bashrc`, `.profile`, `~/.config/autostart`, `~/.ssh`). A changed `.bashrc` is a
louder signal than a changed cache file.

#### 4.24.3 Severity ranking — the core UX

A flat changed-files list is useless; rank by where the change landed:

| Priority | Change location | Why it matters |
|---|---|---|
| **Critical** | Changed **executable** in `/usr/bin`, `/bin`, `/usr/sbin`, `/lib` | Binary / trojaned tool |
| **Critical** | New **SUID/SGID** binary, or any binary no package owns (`dpkg -S` miss) | Privilege-escalation persistence |
| **Critical** | New/changed **systemd unit**, cron entry, autostart, shell rc, `~/.ssh/authorized_keys` | Persistence mechanism |
| **High** | Changed `/etc` auth files — `passwd`, `shadow`, `sudoers`, `sshd_config`, PAM | Account / access change |
| **Info** | Changed packaged file that an apt event explains (see 4.24.4) | Expected |

#### 4.24.4 Auto-explain legitimate changes

Most real "changes" are package upgrades, not attacks. Cross-reference every changed *packaged*
file against `/var/log/dpkg.log` and `/var/log/apt/history.log`: if the file's package was
upgraded around its mtime, tag it **"explained by apt upgrade &lt;date&gt;"** and drop it from the
alert list. What survives — changes with **no** package-manager event behind them — is the real
signal. (This is exactly the manual reasoning a human does auditing by hand; bake it in so the
user doesn't have to.)

#### 4.24.5 Baseline trust — state the limit honestly

The baseline DB is the root of trust, and a root-level attacker who can rewrite files can rewrite
the DB too. Mitigations, strongest last:
- Store the DB + its SHA-256 on read-only / offline media (write, then unmount).
- Record the baseline hash out-of-band and verify it before each check.
- ⚠ A baseline sitting world-readable on the same disk catches opportunistic malware, **not** a
  deliberate targeted attacker. Say so in the UI — don't imply more assurance than it gives.

#### 4.24.6 Interaction with this app ← don't skip

**Every Apply transaction in this app changes files AIDE watches** (`/etc/sysctl.d`,
`sshd_config.d`, GRUB, `sudoers.d`, …). Left unhandled, hardening the machine floods the next
integrity check with self-inflicted "changes" and trains the user to ignore the report. But the
app knows *exactly* which files it wrote — it has the diff and the `.bak`s from §8. So after a
successful Apply it should offer **"fold these known changes into the AIDE baseline"**: a scoped
`aide --update` limited to the paths that transaction touched, run through the same `pkexec`
helper. That keeps the hardening tool and the integrity monitor consistent instead of fighting.

#### 4.24.7 Scheduling & reporting

- systemd timer (daily/weekly) runs **Check**, writes the report to the journal, desktop-notifies
  on any Critical/High finding. No mail dependency by default; optional mail/remote-syslog target.
- Read-only status view: last run, baseline age, counts by severity, expandable per-file
  attribute diff (`sha256 old → new`, `mode 0644 → 0777`, `owner root → user`).
- ⚠ Flag a **stale baseline** (older than N months, or predating the last kernel/major upgrade) —
  an old baseline produces so much expected drift it gets ignored, defeating the feature.

#### 4.24.8 Build notes

- Tier 1 (debsums / `dpkg -V`) ships first — no baseline, immediate value, and a good smoke test
  of the helper's read path.
- The AIDE config is a data file like the TOML catalogue; watched paths and exclusions are
  user-tunable in the GUI (add/remove), same pattern as the permission controller's custom paths
  (§4.11.5).
- Init-hashing a full system is minutes of CPU — run it in the helper with a progress signal,
  never on the GUI thread.
- The status view here is the natural place to surface the §4.11.2 unpackaged-SUID scan and the
  §4.11.3 read-only findings — same "what's on this box that shouldn't be" question.

### 4.25 Desktop / login screen

GDM — `disable-user-list=true`, disable guest session, disable automatic login,
`AllowRoot=false`.
GNOME screen lock — `lock-enabled true`, `lock-delay 0`, `idle-delay 300`,
`disable-lock-screen false`, `show-in-lock-screen false` for notifications,
`disable-user-switching`, disable USB during lock.
`/etc/issue`, `/etc/issue.net`, `/etc/motd` warning banners.
Disable Ctrl-Alt-Del target (`systemctl mask ctrl-alt-del.target`).

---

## 5. Presets & profiles

**A preset is nothing special: it's a saved selection over the full flag catalogue** — a TOML
file mapping flag ids to values, plus section payloads (UFW rule list, modprobe module list,
permission rows). Applying one just pre-toggles the grid; the user can then flip any individual
flag before hitting Apply. Click-and-go and click-and-select are the same machinery at
different zoom levels. Custom presets are first-class: save the current selection under a name,
export it, carry it to the next machine.

```toml
[preset]
name = "stock"
base = ""                 # optional: inherit another preset, then override
desc = "Captured from the reference machine, 2026-07"

[[set]]
id = "kptr_restrict"
value = "2"

[[ufw.rule]]
action = "deny"; direction = "in"; port = "3389"; proto = "tcp"
```

`base` gives preset inheritance — *paranoid* = *recommended* + overrides, a user preset =
*stock* + their tweaks. Shipped in `/usr/share/hardening-gui/presets/`, user presets in
`~/.config/hardening-gui/presets/`.

### 5.1 Shipped presets

| Preset | Intent |
|---|---|
| **stock** | This reference machine's full config, captured and normalised (§5.3) |
| **recommended** | Everything `risk=safe`, nothing that breaks snaps/desktop — the sane default |
| **laptop** | recommended + MAC randomisation, USB lockdown, screen-lock, no SMT cost flags |
| **workstation** | recommended + dev tools kept working (ptrace 1, perf on, kvm allowed) |
| **server** | recommended + SSH hardening, auditd, no desktop sections, mitigations full |
| **paranoid** | Everything on, `nosmt`, one-way flags included — badge-heavy, VM-test-first |

Presets never auto-include `one-way` flags except *paranoid*, and even there they stay
individually visible in the review diff.

### 5.2 Capture — turn any running system into a preset

The **Capture this system** button reads the *effective* live state and emits a clean preset:

1. **Read the effective config**, not the files: merged sysctl chain (§2) *and* live
   `/proc/sys` values; `/proc/cmdline` *and* `/etc/default/grub` + `grub.d/*.cfg`; parsed
   `modprobe.d` directives; `ufw` status + defaults; every other section's target files.
2. **Normalise**: dedupe repeated keys last-wins, resolve conflicts (report them), map raw
   keys/modules/rules onto catalogue flag ids, collect unknown-but-valid keys as custom
   entries, tag hardware-specific quirks `hw = true`.
3. **Validate**: drop keys with no `/proc/sys` entry on this kernel, invalid grub params,
   malformed modprobe lines — each one *reported*, never silently kept.
4. **Emit** the preset TOML + a findings report (what was deduped, what was invalid, what
   conflicts were resolved and how).

This is also the upgrade path for hand-hardened machines: capture → inspect findings → apply
the cleaned version back through the app → delete the old hand-written files.

### 5.3 The **stock** preset — captured from this machine

What capture produces here, normalised. (Cascade-VPN/WireGuard rules deliberately excluded.)

**GRUB cmdline** — `slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on
vsyscall=none debugfs=off randomize_kstack_offset=on kptr_restrict=2 dmesg_restrict=1
lockdown=confidentiality module.sig_enforce=1 lsm=lockdown,yama,apparmor,bpf
mitigations=auto,nosmt spec_store_bypass_disable=on spectre_v2=on spectre_v2_user=on
mds=full,nosmt tsx=off tsx_async_abort=full,nosmt l1tf=full,force intel_iommu=on iommu=force
iommu.strict=1 slab_debug=FZP` — minus the invalid `nospec_store_bypass_disable=0`, minus
`crashkernel` (kdump conflict, §4.4).

**sysctl** (effective, last-wins) —
`kernel.*`: `kptr_restrict=2`, `dmesg_restrict=1`, `perf_event_paranoid=3`,
`yama.ptrace_scope=3` (one-way), `randomize_va_space=2`, `unprivileged_bpf_disabled=1`,
`kexec_load_disabled=1`, `sysrq=0`, `unprivileged_userns_clone=0`, the full
`apparmor_restrict_*` set `=1`, `unprivileged_userns_apparmor_policy=1`.
`net.core.bpf_jit_harden=2`.
`net.ipv4.*`: `tcp_syncookies=1`, `tcp_rfc1337=1`, `tcp_sack=0`, `tcp_dsack=0`,
`icmp_echo_ignore_all=1`, `icmp_ignore_bogus_error_responses=1`,
`conf.{all,default}.{accept_redirects,secure_redirects,send_redirects,accept_source_route}=0`,
`conf.all.rp_filter=2` / `conf.default.rp_filter=1` (conflict — capture asks, recommend `1`/`1`).
`net.ipv6.*`: `disable_ipv6=1` on all/default/lo, `accept_ra=0`, `accept_redirects=0`,
`accept_source_route=0`, `use_tempaddr=2`.
`fs.suid_dumpable=0`, `vm.mmap_rnd_bits=32`, `vm.mmap_rnd_compat_bits=16`,
`dev.tty.ldisc_autoload=0`.

**modprobe** — Intel ME/MEI full set (`mei*`, `intel_vsec`, `intel_pmt`, `pmt_*`,
`intel_pmc_*`), IPMI + watchdogs (`ipmi_*`, `iTCO_wdt`), wireless + bluetooth (`iwlwifi`,
`iwlmvm`, `cfg80211`, `mac80211`, `btusb`, `btintel`, `bluetooth`, `ath3k`, `nfc`, `pn544`,
`microread`), firewire, legacy modems (`snd-*-modem`), framebuffer + rare-network vendor lists.
All normalised to `blacklist` + `install <mod> /bin/false` (+ `softdep pre: blacklist` where
the source files used it). The `snd-intel-dspcfg dsp_driver=1` / `sof-audio-pci-intel-cnl`
audio fix is captured with `hw = true`.

**UFW** — enabled, `LOGLEVEL=low`, IPv6 on. Defaults: **deny in / deny out / deny routed**.
Outbound allowlist: `53`, `443`, `2408` (WARP). Explicit outbound denies `22, 80, 8080`;
the ~30 explicit inbound deny rules (SMB, RDP, VNC, IPMI 623, telnet, mDNS, high-port ranges…)
captured into the "redundant with default policy" group (§4.6). Missing-but-recommended chips
shown next to it: `123/udp out` (NTP — currently blocked → clock drift).

### 5.4 What capture found on this machine (why the normaliser exists)

Every one of these is a real finding from this box — the capture report makes them visible
instead of letting them rot in the files:

| Finding | Detail |
|---|---|
| Duplicate keys | `/etc/sysctl.d/sysctl.conf` sets many keys 2–4× with commented-out copies interleaved |
| Conflicting values | `ptrace_scope` 1 vs 3, `rp_filter` 1 vs 2 — whichever parses last silently wins |
| Invalid keys | `kernel.exec-shield`, `security.bprm_checkIP` (trailing whitespace too) — have never done anything; a read-back would have caught them years ago |
| Invalid grub param | `nospec_store_bypass_disable=0` passed through to init |
| kdump conflict | `crashkernel=` reserved RAM + `kexec_load_disabled=1` = kdump can never fire (§4.4) |
| Vendor-layer edits | customisations written into `/usr/lib/sysctl.d/*` — next procps/systemd upgrade overwrites them (§2) |
| `/bin/true` installs | `blacklist-mei.conf` uses `install mei /bin/true` — succeeds silently; normalised to `/bin/false` |
| Malformed modprobe | `install any new_module /bin/false` (no such module "any"); `options mei off` (no such option); `# Generated: $(date)` unexpanded |
| Mixed name styles | `mei-me` vs `mei_me` across files — normalised to underscores |
| Redundant pair | `slab_nomerge` + `slab_debug=FZP` (the latter already disables merging, at a perf cost) |
| Redundant UFW denies | ~30 explicit inbound denies under a default-deny-in policy |
| Blocked NTP | default deny-out with no `123/udp` allowance — time sync silently dead |

### 5.5 Preset operations

- **Apply** — load into the grid, review diff, apply. Never blind-applies: always through §8.
- **Diff two presets** — side-by-side: only in A / only in B / different values.
- **Diff preset vs live system** — the drift view (§6) with a preset as the reference.
- **Merge** — start from A, overlay B's non-conflicting flags, resolve conflicts interactively.
- **Export/import** — a single `.toml` file; that's the whole story for carrying config to the
  next machine. `hw = true` entries prompt before applying on different hardware.

---

## 6. Status & drift — every flag knows its live state

Each flag shows one of five states, computed on startup and after every apply:

| State | Meaning | Source |
|---|---|---|
| ● applied | live value == selected value | `/proc/sys`, `lsmod`, `/proc/cmdline`, `ufw status`, file contents |
| ◐ pending reboot | written to disk, live value differs, flag is boot-time | written file vs live value |
| ◍ differs | live value ≠ what our drop-in file says — something else changed it | file vs live |
| ○ not set | system default | — |
| ✕ invalid here | key/module doesn't exist on this kernel | `/proc/sys` probe |

No journal, no daemon — the drop-in files the app wrote *are* the record; drift is simply a
file-vs-live mismatch computed at startup. A "Drift" filter chip shows only ◍ flags — "did an
update undo my hardening?" answered in one click.

`/proc/cmdline` vs `/etc/default/grub` comparison also catches the classic "edited grub, forgot
`update-grub`" state and offers to finish the job.

---

## 7. UI

**Reference mockups:** `GUI_MOCKUP.html` (this folder) is the target look for the main window —
open it in a browser and match it: exact header/sidebar/grid/footer layout, card anatomy,
status-dot colours, badge styles, dark palette. `Screenshot From 2026-07-20 19-10-49.png` is
the original concept it extends.

**Overview is the landing page**: the first sidebar entry, above the sections. One scrollable
master list of *every* flag in the catalogue, grouped under category headers (kernel / memory,
namespaces, network, modules, ssh, …), each row showing: enable control · title · `desc`
(what it does) · `why` (why it's good) · risk badge · status dot. Enable anything directly from
here — same staging as the section grids, the changed-counter reacts identically. Search and
the filter chips operate on this list first, which makes Overview the fastest "find and flip a
flag" surface; the per-section grids remain the focused view for working through one area
deliberately. Collapse/expand per category, `select all` per category header, sticky category
header while scrolling.

The mockup is the reference: dark libadwaita window, sidebar of sections, card grid, sticky
footer. Keep its vocabulary — **"7 changed"** counter in the header, **"select all (33)"** on
the group header, **caution** / **one-way** badges, red border on one-way cards, the
**"asks for password"** lock hint beside **Review** / **Apply**, and the
**"namespaces / apparmor · network · 19 more in this section"** footer strip as in-section
navigation (each name clickable, jumps to that group).

Grid of compact toggle cards — 2 columns at ~700px, 3 at 1100px+, via
`repeat(auto-fit, minmax(220px, 1fr))`. Roughly 24 flags visible per screen so most groups fit
without scrolling.

Each cell: toggle (or value dropdown for multi-value flags, §3) · title · `desc` one-liner ·
the key in small mono · risk badge if any · **status dot** (§6) in the corner.
Cards with `caution`/`breaking`/`one-way` get a coloured border so they're scannable.

**Missing from the mockup, added:**

- **Header preset picker** — dropdown left of the changed-counter: Stock · Recommended ·
  Laptop · Workstation · Server · Paranoid · user presets · *Capture this system…* ·
  *Save selection as preset…*. Picking one stages it into the grid; the counter updates.
  Modified-from-preset shows as "Stock (modified)".
- **Search** (Ctrl+F / type-to-search) across id, key, title, desc, module names, ports.
- **Filter chips** under the header: `changed` · `drift` · `needs reboot` · `one-way` ·
  `not applied` · `hide risky`.
- **Sidebar badges** — per-section changed count and a ◐ reboot / ◍ drift dot, so the sidebar
  answers "where did I touch things" at a glance. Sidebar groups the 20+ sections under five
  headers to stay mockup-simple: **System** (sysctl · grub · modprobe · bootloader),
  **Network** (ufw · dns · network · ssh), **Access** (pam · sudo · permissions · fstab · usb),
  **Monitoring** (auditd · apparmor · logging · integrity · systemd · services),
  **Desktop** (desktop · telemetry · updates).
- **Simple / Advanced switch** in the header menu. *Simple*: presets + one master switch per
  section + the risky-flag review — click-and-go. *Advanced*: every grid, every flag —
  click-and-select. Same state underneath, switching views never loses staging.
- **Reboot banner** — after an apply containing boot-time flags: "N changes take effect after
  reboot" with a Reboot-now button.
- **Undo** — per-section "remove this drop-in" button (§8): delete the file, re-run the
  reload command, section is stock again.
- **First-run wizard** — the §1.2 flow: Preset / Capture / Scratch, one screen, skippable.
- Keyboard: arrows move between cards, Space toggles, Enter opens the multi-value dropdown.

**Review changes** — literal unified diff per target file, plus the exact `ufw`/`systemctl`
command list, plus a grouped risk summary ("2 one-way flags, 1 breaks snaps") that must be
scrolled past before Apply enables when one-way flags are staged.

Import/export the toggled set as a TOML preset (§5.5) — that's how config moves between
machines.

## 8. Apply

```
Toggled flags
  → build file contents
  → show diff  (cancellable)
  → pkexec helper  ← single password prompt
       cp each target to .bak
       validate: sshd -t · visudo -c · mount -o remount test · auditctl -R dry run
       write files
       sysctl --system · depmod -a · update-grub (check exit code)
       systemctl daemon-reload · restart affected units
       ufw commands
       on failure: restore .bak, re-run update-grub, report
  → read each value back, compare to intended
  → report: applied / needs reboot / failed / didn't take
```

**Undo is file deletion.** Every section is one drop-in file — delete it (in-app button or by
hand from recovery mode) and that section is stock again. The two exceptions keep their own
records as before: fstab (`.bak`) and permissions (`perms.json`, §2). Nothing fancier needed.

The read-back matters: invalid sysctl keys fail silently. `kernel.exec-shield` and
`security.bprm_checkIP` in the current config on this machine are examples — neither has ever
done anything. Without a read-back the app reports success for them.

Validators before write are the same idea for the new sections — `sshd -t`, `visudo -c`, and a
live `mount -o remount` are what stop §4.7, §4.9 and §4.10 from locking you out.

## 9. Helper security

`/usr/libexec/hardening-gui-helper`, invoked by `pkexec`, polkit action `auth_admin`.

Takes **one argument: a path to a JSON file**. Validates every key against an allowlist compiled
from the same TOML data the GUI uses. No free-form strings, no shell interpolation. Short enough
to audit in one sitting.

## 10. Build order

1. TOML catalogue — §4.1–4.6 first, then the new sections; capture (§5.2) run against this
   machine produces the **stock** preset and the §5.4 findings as a built-in test case
2. Helper + polkit policy
3. GTK window: Overview + sections, grid, toggles, select-all, search, preset picker
4. Review-diff dialog + Apply + read-back + reboot banner
5. GRUB (§4.4) and bootloader password (§4.23)
6. SSH, sudo, PAM (§4.7–4.9) — all three need their validators working first
7. fstab, permissions/SUID (§4.10–4.11) — highest brick risk, do last
8. Remaining sections, Simple mode
9. `.deb` packaging + offline-install test (see below), extras bundle

**Packaging gate (run in CI, every release):** fresh Ubuntu 26.04 VM, network disconnected,
`dpkg -i` the deb → must install with zero errors; launch the GUI, load the stock preset,
open the review diff → must work. That test *is* the §1 promise.

Test destructive paths in a VM snapshot, not the live machine. `fstab`, SUID stripping,
USBGuard, faillock, and `kernel.modules_disabled` especially — each can lock you out of the
machine in a different way.
