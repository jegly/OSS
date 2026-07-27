#!/bin/sh
# Build the Arch package from this checkout.
#
# The PKGBUILD's source= points at a release tarball, which is right for the
# AUR and useless before there is a tagged release. This makes that tarball out
# of the working tree and drops it where makepkg looks, so makepkg finds it
# already present and skips the download.
#
# Run on an Arch system. Needs base-devel.
set -eu
cd "$(dirname "$0")/.."
ROOT=$(pwd)

VERSION=$(head -1 debian/changelog | sed 's/.*(\(.*\)).*/\1/')
BUILD="$ROOT/build/arch"
STEM="oss-$VERSION"

rm -rf "$BUILD"
mkdir -p "$BUILD"

# git archive would miss uncommitted work, which is exactly what you are
# usually trying to test here, so copy the tree instead.
mkdir -p "$BUILD/$STEM"
tar --exclude=.git --exclude=build --exclude='__pycache__' --exclude='*.pyc' \
    -cf - . | tar -xf - -C "$BUILD/$STEM"

tar -czf "$BUILD/$STEM.tar.gz" -C "$BUILD" "$STEM"
rm -rf "$BUILD/$STEM"

cp packaging/arch/PKGBUILD "$BUILD/"

cd "$BUILD"
# SKIP in sha256sums means the checksum is not verified, which is what we want
# for a locally-made tarball; makepkg still refuses to run without the field.
makepkg --force --noconfirm "$@"

echo
echo "Built in $BUILD:"
ls -1 "$BUILD"/*.pkg.tar.* 2>/dev/null || true
echo
# The extension follows PKGEXT from makepkg.conf — .zst on Arch itself, but
# .gz when makepkg is running on a distro whose defaults differ, so glob for
# it rather than assuming.
for pkg in "$BUILD"/*.pkg.tar.*; do
    [ -e "$pkg" ] && echo "Install with:  sudo pacman -U $pkg"
done
