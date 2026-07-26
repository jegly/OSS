#!/bin/sh
# Build oss-fonts: the bundled faces, in their own package.
#
# Separate because 17MB of TTFs would be most of the main package's size for
# something entirely optional — the app picks up whichever of these are present
# and leaves the rest out of the font picker.
set -eu
cd "$(dirname "$0")/.."

SOURCE=${1:-/home/askdjlakjsd/Documents/theme port for android apps/fonts}
if [ ! -d "$SOURCE" ]; then
    echo "font source not found: $SOURCE" >&2
    echo "usage: $0 [path-to-fonts-directory]" >&2
    exit 1
fi

VERSION=$(head -1 debian/changelog | sed 's/.*(\(.*\)).*/\1/')
STAGE=build/oss-fonts
rm -rf "$STAGE" && mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/share/fonts/oss"

find "$SOURCE" -name '*.ttf' -exec install -m 0644 {} "$STAGE/usr/share/fonts/oss/" \;
COUNT=$(find "$STAGE/usr/share/fonts/oss" -name '*.ttf' | wc -l)

cat > "$STAGE/DEBIAN/control" <<CONTROL
Package: oss-fonts
Version: $VERSION
Section: fonts
Priority: optional
Architecture: all
Maintainer: OSS <noreply@localhost>
Depends: fontconfig
Enhances: oss
Description: Optional typefaces for the OSS
 $COUNT TrueType faces across 13 families: Nunito, Space Grotesk, Quicksand,
 IBM Plex Mono and Serif, Playfair Display, Cormorant Garamond, Instrument
 Serif, Viaoda Libre, Turret Road, DotGothic16, Press Start 2P and Noto Sans
 Egyptian Hieroglyphs.
 .
 Twelve of the thirteen appear in the appearance picker. Noto Sans Egyptian
 Hieroglyphs is installed for general use but not offered as a UI font, because
 it has no Latin coverage and choosing it would leave every label in the app
 blank.
 .
 Entirely optional. Without this package the app uses the system font and the
 picker simply does not offer the missing faces.
CONTROL

cat > "$STAGE/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
# Local call only — rebuilds the font cache, downloads nothing.
set -e
if [ "$1" = configure ] && command -v fc-cache >/dev/null 2>&1; then
    fc-cache -f /usr/share/fonts/oss >/dev/null 2>&1 || true
fi
exit 0
POSTINST
chmod 0755 "$STAGE/DEBIAN/postinst"

cat > "$STAGE/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
if command -v fc-cache >/dev/null 2>&1; then
    fc-cache -f >/dev/null 2>&1 || true
fi
exit 0
POSTRM
chmod 0755 "$STAGE/DEBIAN/postrm"

dpkg-deb --root-owner-group --build "$STAGE" "build/oss-fonts_${VERSION}_all.deb" >/dev/null
echo "build/oss-fonts_${VERSION}_all.deb  ($COUNT faces)"
