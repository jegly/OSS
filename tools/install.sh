#!/bin/sh
# Install OSS using the native package for this distribution.
#
# This exists instead of an AppImage or a Flatpak. Both of those would need a
# privileged first-run bootstrap to install the polkit action and the helper at
# a fixed path, which means root-owned files outside the package manager that
# nothing removes when you delete the app — the sort of thing OSS's own
# integrity section exists to find. So the convenience lives here, in a script
# you can read, and the package itself stays something your distribution can
# verify and uninstall.
#
# It does not download anything. Point it at packages you already have:
#
#     ./tools/install.sh                 # build from this checkout, then install
#     ./tools/install.sh path/to/pkg     # install a package you already built
#
# Nothing is installed without showing you the command first.

set -eu

usage() {
    cat <<'USAGE'
usage: install.sh [package]

  no argument   build the right package for this system, then install it
  package       install this .deb / .rpm / .pkg.tar.* instead of building

  --dry-run     print what would happen and stop
  --help        this text
USAGE
}

DRY_RUN=no
PACKAGE=""
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=yes ;;
        --help|-h) usage; exit 0 ;;
        -*) echo "unknown option: $arg" >&2; usage >&2; exit 2 ;;
        *) PACKAGE="$arg" ;;
    esac
done

# --------------------------------------------------------------------------- #
#  Which distribution is this
# --------------------------------------------------------------------------- #

# Same rule as the application itself: ID first because it is exact, then
# ID_LIKE, which is how a derivative nobody has heard of still resolves to its
# parent. See probe.detect_family().
# OSS_OS_RELEASE overrides the files read, so this can be exercised against a
# real Mint or Rocky os-release without one of those machines to hand. It
# replaces the whole list rather than the first entry: leaving the real
# /usr/lib/os-release in place made an unrecognised test file fall through and
# report this machine's own family.
detect_family() {
    for release in ${OSS_OS_RELEASE:-/etc/os-release /usr/lib/os-release}; do
        [ -r "$release" ] || continue
        # shellcheck disable=SC1090
        . "$release"
        case "${ID:-}" in
            debian|ubuntu)                         echo debian; return ;;
            arch|archarm)                          echo arch;   return ;;
            fedora|rhel|centos)                    echo fedora; return ;;
            opensuse*|sles)                        echo suse;   return ;;
        esac
        for like in ${ID_LIKE:-}; do
            case "$like" in
                debian|ubuntu)      echo debian; return ;;
                arch)               echo arch;   return ;;
                fedora|rhel|centos) echo fedora; return ;;
                suse|opensuse)      echo suse;   return ;;
            esac
        done
    done
    echo unknown
}

FAMILY=$(detect_family)
PRETTY=$( (. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$FAMILY}") || echo "$FAMILY")

echo "System:  $PRETTY"
echo "Family:  $FAMILY"

if [ "$FAMILY" = unknown ]; then
    cat >&2 <<'UNKNOWN'

Could not work out which distribution family this is from /etc/os-release.

OSS builds packages for Debian/Ubuntu, Arch, and Fedora/RHEL/openSUSE. If
yours is derived from one of those, build the matching package by hand:

    ./tools/build-deb.sh
    ./tools/build-arch.sh
    ./tools/build-rpm.sh

and install it with your own package manager.
UNKNOWN
    exit 1
fi

# --------------------------------------------------------------------------- #
#  Build, unless handed a package
# --------------------------------------------------------------------------- #

cd "$(dirname "$0")/.."

if [ -z "$PACKAGE" ]; then
    case "$FAMILY" in
        debian) BUILDER=./tools/build-deb.sh  ;;
        arch)   BUILDER=./tools/build-arch.sh ;;
        fedora|suse) BUILDER=./tools/build-rpm.sh ;;
    esac
    echo "Build:   $BUILDER"
    if [ "$DRY_RUN" = yes ]; then
        echo "(dry run: stopping before building)"
        exit 0
    fi
    "$BUILDER" >/dev/null

    case "$FAMILY" in
        debian) PACKAGE=$(ls -1t build/*.deb 2>/dev/null | head -1) ;;
        arch)   PACKAGE=$(ls -1t build/arch/*.pkg.tar.* 2>/dev/null | head -1) ;;
        fedora|suse)
            # The main package only. oss-fonts is a Recommends and the package
            # manager pulls it in itself if it wants it.
            PACKAGE=$(find build/rpm/RPMS -name 'oss-[0-9]*.rpm' 2>/dev/null | head -1) ;;
    esac
fi

if [ -z "$PACKAGE" ] || [ ! -f "$PACKAGE" ]; then
    echo "no package to install (looked for one built under build/)" >&2
    exit 1
fi

# --------------------------------------------------------------------------- #
#  Install
# --------------------------------------------------------------------------- #

case "$FAMILY" in
    debian)      INSTALL="apt-get install -y ./$PACKAGE" ;;
    arch)        INSTALL="pacman -U --noconfirm $PACKAGE" ;;
    fedora)      INSTALL="dnf install -y $PACKAGE" ;;
    suse)        INSTALL="zypper --non-interactive install --allow-unsigned-rpm $PACKAGE" ;;
esac

# apt wants a path it can recognise as a file rather than a package name.
case "$FAMILY:$PACKAGE" in
    debian:/*) INSTALL="apt-get install -y $PACKAGE" ;;
esac

echo "Package: $PACKAGE"
echo "Command: sudo $INSTALL"

if [ "$DRY_RUN" = yes ]; then
    echo "(dry run: stopping before installing)"
    exit 0
fi

if [ "$(id -u)" -eq 0 ]; then
    # shellcheck disable=SC2086
    $INSTALL
else
    command -v sudo >/dev/null 2>&1 || {
        echo "sudo is not installed; run this as root instead" >&2
        exit 1
    }
    # shellcheck disable=SC2086
    sudo $INSTALL
fi

echo
echo "Installed. Launch it from your applications menu, or run: oss"
echo "Manual page: man oss"
