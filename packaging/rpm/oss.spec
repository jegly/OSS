#  RPM package for Fedora / RHEL and openSUSE.
#
#  Layout is deliberately identical to the .deb (tools/build-deb.sh) and the
#  PKGBUILD (packaging/arch/PKGBUILD) — a file added to one and forgotten in
#  the others is the failure mode this app would otherwise ship silently.
#
#  Build from a checkout with tools/build-rpm.sh, which makes the source
#  tarball the Source0 below expects.

Name:           oss
Version:        1.1.0
Release:        1%{?dist}
Summary:        Pick hardening flags, review the diff, apply once

# openSUSE still requires Group:; Fedora dropped it and ignores it.
Group:          System/Management
License:        Apache-2.0
URL:            https://github.com/jegly/OSS
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz#/%{name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires:  python3 >= 3.11

# Depend on the typelib rather than the library package. Both families generate
# typelib() provides from the .typelib files themselves, so this needs no
# conditional, and it states what is actually required: this is a PyGObject app
# that never links against either library.
Requires:       python3 >= 3.11
Requires:       typelib(Gtk) = 4.0
Requires:       typelib(Adw) = 1.0
Requires:       polkit
%if 0%{?suse_version}
Requires:       python3-gobject-Gdk
%else
Requires:       python3-gobject
%endif

# The interface has a font picker; without the fonts it falls back to the
# system default and still works, so this is a Recommends rather than a hard
# dependency.
Recommends:     %{name}-fonts = %{version}-%{release}

# Optional per-section dependencies. Absence is a handled, visible degraded
# state in the UI (Section.requires_pkg), never a failed apply.
Recommends:     firewalld
Suggests:       audit
Suggests:       usbguard
Suggests:       aide
%if 0%{?suse_version}
Suggests:       apparmor-utils
Suggests:       openssh
%else
Suggests:       openssh-server
%endif

%description
A GTK4 control centre for Linux hardening. Choose settings from categorised
grids, review the literal diff of every file that will change, then apply the
whole set through a single authentication.

Every section writes one drop-in file, so undo is deleting it. Changes are
backed up before they are made, validated where a validator exists (sshd -t,
visudo -c, a live mount remount), rolled back as a unit on any failure, and
read back afterwards, because an invalid sysctl key fails silently and would
otherwise be reported as success.

%package fonts
Summary:        Typefaces bundled with the OSS interface
Group:          System/Management
License:        OFL-1.1
BuildArch:      noarch
Requires:       fontconfig

%description fonts
The twelve typefaces the OSS font picker offers, under the SIL Open Font
License 1.1. Split out because they carry a different licence to the
application, and because a font is not something a system tool should force on
you. Without this package OSS uses the system font.

%prep
# -n because the tarball GitHub serves for a tag unpacks to the *repository*
# name, OSS-1.1.0, not to %{name}-%{version}. Without this the build fails on
# COPR and anywhere else that fetches Source0, while passing locally.
%autosetup -n OSS-%{version}

%build
# Pure Python plus TOML data: nothing to compile.

%check
# Skips the GTK tests automatically when there is no display, which is the
# normal case in a build root. See tests/test_cards.py.
python3 -m unittest discover -s tests

%install
# Private application directory. Deliberately not %%{_libdir}: everything here
# is architecture-independent Python source, and %%{_libdir} resolves to
# /usr/lib64 on 64-bit RPM systems, which would be wrong for a noarch package.
install -d %{buildroot}%{_datadir}/oss
cp -r src/ossgui %{buildroot}%{_datadir}/oss/
find %{buildroot} -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || :

install -D -m 0755 oss %{buildroot}%{_bindir}/oss

# Not %%{_libexecdir}: the polkit action pins exec.path to one absolute path and
# polkit matches it literally, so every package must agree on it.
install -D -m 0755 helper/oss-helper %{buildroot}%{_prefix}/libexec/oss-helper

install -D -m 0644 data/polkit/com.jegly.OSS.policy \
    %{buildroot}%{_datadir}/polkit-1/actions/com.jegly.OSS.policy
install -D -m 0644 data/desktop/com.jegly.OSS.desktop \
    %{buildroot}%{_datadir}/applications/com.jegly.OSS.desktop
install -D -m 0644 docs/oss.1 %{buildroot}%{_mandir}/man1/oss.1

cp -r data/catalogue data/presets data/themes %{buildroot}%{_datadir}/oss/

install -d %{buildroot}%{_datadir}/fonts/oss
install -m 0644 data/fonts/*.ttf %{buildroot}%{_datadir}/fonts/oss/

install -d %{buildroot}%{_datadir}/icons
cp -r data/icons/hicolor %{buildroot}%{_datadir}/icons/

# cp -r carries the source tree's modes; normalise rather than trust them.
find %{buildroot}%{_datadir}/oss -type f -exec chmod 644 {} +
find %{buildroot}%{_datadir}/oss -type d -exec chmod 755 {} +
find %{buildroot}%{_datadir}/icons -type f -exec chmod 644 {} +
find %{buildroot}%{_datadir}/icons -type d -exec chmod 755 {} +

%files
%license LICENSE
%doc README.md
%{_bindir}/oss
%{_datadir}/oss/
%{_prefix}/libexec/oss-helper
%{_datadir}/polkit-1/actions/com.jegly.OSS.policy
%{_datadir}/applications/com.jegly.OSS.desktop
%{_mandir}/man1/oss.1*
%{_datadir}/icons/hicolor/*/apps/com.jegly.OSS.png

%files fonts
%{_datadir}/fonts/oss/

%changelog
* Mon Jul 27 2026 Jegly <jjjegly@gmail.com> - 0.1.1-1
- Backup and restore; apply dialog fixes.

* Mon Jul 27 2026 Jegly <jjjegly@gmail.com> - 0.1.0-1
- Initial package.
