#!/bin/sh
# Build the RPM from this checkout.
#
# The spec's Source0 points at a release tarball, which is right for COPR and
# useless before there is a tagged release. This makes that tarball out of the
# working tree and points rpmbuild at it, keeping everything under build/rpm
# rather than scattering it through ~/rpmbuild.
#
# Works on any distro with rpmbuild installed, though the resulting package is
# only meaningful on an RPM system.
set -eu
cd "$(dirname "$0")/.."
ROOT=$(pwd)

VERSION=$(head -1 debian/changelog | sed 's/.*(\(.*\)).*/\1/')
BUILD="$ROOT/build/rpm"
STEM="oss-$VERSION"

rm -rf "$BUILD"
mkdir -p "$BUILD/SOURCES" "$BUILD/SPECS" "$BUILD/BUILD" "$BUILD/RPMS" "$BUILD/SRPMS"

# Copy rather than git archive: uncommitted work is usually the thing being
# tested here, and git archive would silently leave it out.
mkdir -p "$BUILD/$STEM"
tar --exclude=.git --exclude=build --exclude='__pycache__' --exclude='*.pyc' \
    -cf - . | tar -xf - -C "$BUILD/$STEM"

tar -czf "$BUILD/SOURCES/$STEM.tar.gz" -C "$BUILD" "$STEM"
rm -rf "$BUILD/$STEM"

cp packaging/rpm/oss.spec "$BUILD/SPECS/"

rpmbuild -bb \
    --define "_topdir $BUILD" \
    "$BUILD/SPECS/oss.spec" "$@"

echo
echo "Built:"
find "$BUILD/RPMS" -name '*.rpm'
echo
echo "Install with:  sudo dnf install \$(find $BUILD/RPMS -name '*.rpm')"
echo "   or on SUSE: sudo zypper --no-gpg-checks install \$(find $BUILD/RPMS -name '*.rpm')"
