# OSS 1.1.0

**26 sections · 689 settings · 304 tests**

A correctness release. Every change here is in the module-blacklisting sections,
and they all come from the same root cause: the app decided whether a module was
blacklisted by asking whether it was *loaded*, which is a different question.

---

## Read this before upgrading from 1.0.0

**The modprobe section will show far fewer settings as applied, and that is the
fix.** On a stock install 1.0.0 reported 159 of its 170 module flags as already
in effect. 134 of those had nothing blacklisting them anywhere on the system.

Nothing about your machine changed when you upgrade — only what the app claims
about it. If a flag stops showing as applied, it was never applied.

**A flag that reads as in effect cannot be switched on**, which is why this also
looked like the section had fewer things to offer. With the state read correctly,
143 of the 170 became selectable again.

---

## Fixed

### "Not loaded" is not "blacklisted"

A stock kernel ships around 6,900 loadable modules and boots using about 130.
Idle is the normal state for almost every module on the system, and an idle
module with no blacklist is one device, one mount or one packet away from
loading — that autoload path is the entire surface this section exists to close.

1.0.0 read that idle state as success. The blacklist is now read from the files
modprobe actually reads, which is the only thing that decides whether a module
can load.

| | 1.0.0 | 1.1.0 |
|---|---|---|
| Module flags reported in effect on a stock install | 159 of 170 | 27 of 170 |
| ...with nothing on disk blacklisting them | 134 | 0 |
| Selectable | 11 | 143 |

### In effect is not the same as *you* set it

A module blacklisted by a file this app did not write now says so, and names the
file. On Ubuntu that is around twenty modules blacklisted by the `kmod` package's
own `blacklist.conf`, `blacklist-firewire.conf`, and the kernel package's
blacklist in `/lib/modprobe.d` — none of which were the user's choice, and all of
which 1.0.0 presented as though they were.

### Three more ways the blacklist was misread

- **`/etc/modprobe.d` was the only directory consulted.** modprobe also reads
  `/run`, `/lib` and `/usr/lib/modprobe.d`, and the kernel package ships a
  blacklist of its own in `/lib`.
- **Hyphens and underscores were compared literally.** modprobe treats
  `blacklist snd-aw2` and `blacklist snd_aw2` as the same module; the app did
  not, and missed the half of a distro's blacklist written with hyphens.
- **Editing `/etc/modprobe.d` by hand changed nothing on screen.** Adding or
  removing a blacklist line is now noticed, because the file is what is read.

### The debloat browser did not know what was already blacklisted

`kmod.py` never read `/etc/modprobe.d` at all, so the browser classified all
6,901 modules purely by whether they were loaded. On a stock install that meant
**107 modules that were already blacklisted were offered as things to go and
blacklist** — including every module the curated section had just applied, and
everything the distro blacklists itself.

Those now report as *already blacklisted*, name the file that did it, and are not
offered again. Staging one wrote a second line saying the same thing.

### The modprobe section reached 170 of 6,901 modules

The curated list is what presets can carry, and it stopped there — the other
~6,700 modules were only reachable from a separate sidebar entry, which is not
where anyone looks for "blacklist a module". The browser now sits above the
curated grid on the modprobe page, the same shape the services section already
used.

### Capture this system captured blacklists that did not exist

"Capture this system" builds a preset from what is in effect, so it inherited the
same fault: on a stock install it captured 159 module blacklists, 134 of them
imaginary. It now captures 27.

---

## Known issues, not fixed in this release

- **The curated modprobe list contains 53 flags harvested from a single
  reference machine**, recorded as such in a comment in `30-modprobe.toml`.
  Around fourteen of them name things that were never Linux kernel modules
  (`intel_me`, `intel_csme`, `lms`, `sol`, `dal`, `icls`, `bmc1500`, `ipmi_bmc`,
  `ipmi_kcs`, `ipmi_rmcp`, `wiman`, `bootp`, `p80211`). `tools/build_presets.py`
  generated the shipped presets from the catalogue, so 50 of those 53 are in
  `recommended`, `laptop`, `server` and `workstation`, and all 53 are in
  `paranoid`. Blacklisting a name that is not a module is inert, not harmful, but
  it does not belong in the catalogue.
- **`probe.ipv6_redundant()` has no callers.** It was written to explain why the
  IPv6 sysctl flags are moot on a machine that disabled IPv6 at boot, and was
  never wired up. Wiring it up naively is not safe: with the sysctl method of
  disabling IPv6 the tree still exists and those settings still apply, so a
  "these are moot" label would suppress flags that still matter.
- **`test_every_key_exists_on_this_kernel` fails on a machine booted with
  `ipv6.disable=1`.** The 39 `net.ipv6.*` keys genuinely do not exist there, so
  the test is reporting the truth about the machine — but it means building the
  RPM or the Arch package on such a machine needs the test step skipped
  (`tools/build-rpm.sh --nocheck`).

---

## Install

| | |
|---|---|
| **Debian · Ubuntu · Mint · Pop!\_OS · elementary · Zorin** | `sudo apt install ./oss_1.1.0_all.deb` |
| **Arch · Manjaro · EndeavourOS · CachyOS** | `sudo pacman -U oss-1.1.0-1-any.pkg.tar.*` |
| **Fedora · Nobara · RHEL · Rocky · Alma** | `sudo dnf install oss-1.1.0-1.noarch.rpm oss-fonts-1.1.0-1.noarch.rpm` |
| **openSUSE Tumbleweed · Leap** | `sudo zypper install oss-1.1.0-1.noarch.rpm oss-fonts-1.1.0-1.noarch.rpm` |

Upgrading in place is enough. This release changes no file on your system and
writes nothing on install — it only changes what the app reads and reports.
