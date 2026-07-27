#!/bin/sh
# Build the .deb without debhelper, so it works on a machine that only has
# dpkg-deb — which is the same constraint the package itself is built around.
set -eu
cd "$(dirname "$0")/.."

VERSION=$(head -1 debian/changelog | sed 's/.*(\(.*\)).*/\1/')
STAGE=build/oss
# Only this build's staging directory, not all of build/ — the Arch and RPM
# wrappers keep their output alongside, and wiping the lot meant whichever
# package you built last was the only one you still had.
rm -rf "$STAGE" && mkdir -p "$STAGE/DEBIAN"

install -d "$STAGE/usr/share/oss"
cp -r src/ossgui "$STAGE/usr/share/oss/"
find "$STAGE" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

install -D -m 0755 oss "$STAGE/usr/bin/oss"
install -D -m 0644 debian/copyright "$STAGE/usr/share/doc/oss/copyright"
install -D -m 0755 helper/oss-helper "$STAGE/usr/libexec/oss-helper"
install -D -m 0644 data/polkit/com.jegly.OSS.policy \
        "$STAGE/usr/share/polkit-1/actions/com.jegly.OSS.policy"
install -D -m 0644 data/desktop/com.jegly.OSS.desktop \
        "$STAGE/usr/share/applications/com.jegly.OSS.desktop"
install -D -m 0644 docs/oss.1 "$STAGE/usr/share/man/man1/oss.1"
gzip -9n "$STAGE/usr/share/man/man1/oss.1"

# Native package, so policy wants the Debian changelog under this exact name.
install -D -m 0644 debian/changelog "$STAGE/usr/share/doc/oss/changelog"
gzip -9n "$STAGE/usr/share/doc/oss/changelog"
# The typefaces are part of the app, not a separate thing to go and install.
install -d "$STAGE/usr/share/fonts/oss"
install -m 0644 data/fonts/*.ttf "$STAGE/usr/share/fonts/oss/"

if [ -d data/icons ]; then
    install -d "$STAGE/usr/share/icons"
    cp -r data/icons/hicolor "$STAGE/usr/share/icons/"
fi
install -d "$STAGE/usr/share/oss"
cp -r data/catalogue data/presets data/themes "$STAGE/usr/share/oss/"

# Binary control file. Written out here rather than derived from
# debian/control, because the substitution variables debhelper would expand
# are not available when building this way.
cat > "$STAGE/DEBIAN/control" <<CONTROL
Package: oss
Version: $VERSION
Section: admin
Priority: optional
Architecture: all
Maintainer: Jegly <jjjegly@gmail.com>
Depends: python3 (>= 3.11), python3-gi, gir1.2-gtk-4.0, gir1.2-adw-1, polkitd | policykit-1, fontconfig
Recommends: ufw
Suggests: auditd, usbguard, debsums, apparmor-utils, openssh-server
Description: Pick hardening flags, review the diff, apply once
 A GTK4 control centre for Linux hardening. Choose settings from categorised
 grids, review the literal diff of every file that will change, then apply the
 whole set through a single authentication.
 .
 Every section writes one drop-in file, so undo is deleting it. Changes are
 backed up before they are made, validated where a validator exists, rolled
 back as a unit on any failure, and read back afterwards.
 .
 Everything it needs ships with a stock Ubuntu desktop, so it installs with
 dpkg -i on a machine that has never been online.
CONTROL

cat > "$STAGE/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
# Local calls only. This package never downloads anything, at install or at run.
set -e
if [ "$1" = configure ]; then
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database -q /usr/share/applications || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -qtf /usr/share/icons/hicolor 2>/dev/null || true
    fi
fi
exit 0
POSTINST
chmod 0755 "$STAGE/DEBIAN/postinst"


find "$STAGE" -type d -exec chmod 755 {} +
find "$STAGE/usr/share/oss" "$STAGE/usr/share/icons" "$STAGE/usr/share/fonts" \
     -type f -exec chmod 644 {} +

dpkg-deb --root-owner-group --build "$STAGE" "build/oss_${VERSION}_all.deb" >/dev/null
echo "build/oss_${VERSION}_all.deb"
