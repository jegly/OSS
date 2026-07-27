#!/bin/sh
# The BUILD_PLAN §10 packaging gate.
#
# The promise is: dpkg -i on a fresh, offline Ubuntu 26.04 desktop, open the
# app, load a preset, open the review diff. This checks everything that can be
# checked without a VM — every dependency is already satisfied on a stock
# desktop, the package contains what it should, and the app can load its data
# and build a plan from the installed tree with no network.
#
# The parts that genuinely need a fresh VM (dpkg -i itself, and the GUI opening
# on a machine that has never been online) are listed at the end rather than
# pretended to be covered.
set -eu
cd "$(dirname "$0")/.."

DEB=${1:-}
if [ -z "$DEB" ]; then
    DEB=$(./tools/build-deb.sh)
fi
echo "Package: $DEB"
echo

fail=0
check() {
    if [ "$1" = 0 ]; then
        printf '  ok    %s\n' "$2"
    else
        printf '  FAIL  %s\n' "$2"
        fail=1
    fi
}

echo "Dependencies satisfied on this system:"
for pkg in python3 python3-gi gir1.2-gtk-4.0 gir1.2-adw-1; do
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"
    check $? "$pkg installed"
done
if dpkg-query -W -f='${Status}' policykit-1 2>/dev/null | grep -q "install ok installed" ||
   dpkg-query -W -f='${Status}' polkitd 2>/dev/null | grep -q "install ok installed"; then
    check 0 "polkit installed"
else
    check 1 "polkit installed"
fi
echo

echo "Package contents:"
contents=$(dpkg-deb -c "$DEB")
for path in \
    ./usr/bin/oss \
    ./usr/libexec/oss-helper \
    ./usr/share/polkit-1/actions/com.jegly.OSS.policy \
    ./usr/share/applications/com.jegly.OSS.desktop \
    ./usr/share/oss/catalogue/10-sysctl.toml \
    ./usr/share/oss/themes/ptyxis.toml \
    ./usr/share/oss/ossgui/apply.py
do
    echo "$contents" | grep -q " $path\$"
    check $? "$path"
done

echo "$contents" | grep -q '^-rwxr-xr-x.* ./usr/libexec/oss-helper$'
check $? "helper is executable"

# A grep that correctly finds nothing exits 1, so these are inverted
# deliberately rather than run bare under `set -e`.
if echo "$contents" | grep -q '__pycache__'; then
    check 1 "no __pycache__ shipped"
else
    check 0 "no __pycache__ shipped"
fi
echo

echo "Offline behaviour:"
if grep -rqE 'urllib|requests|socket\.create_connection|http://|https://' \
        src/ossgui/ --include='*.py'; then
    check 1 "no network client code in the package"
else
    check 0 "no network client code in the package"
fi

if grep -qE 'apt-get|apt install|wget|curl' build/oss/DEBIAN/postinst; then
    check 1 "postinst makes no network calls"
else
    check 0 "postinst makes no network calls"
fi
echo

echo "The installed tree works:"
STAGE=build/oss
if OSS_DATA="$STAGE/usr/share/oss" \
   PYTHONPATH="$STAGE/usr/share/oss" \
   python3 - <<'PY'
import sys
from ossgui import catalogue, presets, probe, render

cat = catalogue.load()
assert len(cat.flags) > 400, f"only {len(cat.flags)} flags"
assert not [s for s in cat.sections if not s.implemented], "unimplemented sections shipped"

names = [p.key for p in presets.available()]
for required in ("recommended", "paranoid", "stock"):
    assert required in names, f"missing preset {required}"

preset = presets.get("recommended")
selection = {k: v for k, v in presets.selection_for(cat, preset).items() if v is not None}
plan = render.render(cat, selection, current=probe.read_target_files(cat))
assert plan.writes, "recommended preset produced no file writes"
assert not render.validate_commands(plan), "plan contains a command off the allowlist"

print(f"  ok    catalogue loads: {len(cat.flags)} flags, {len(cat.sections)} sections")
print(f"  ok    presets load: {', '.join(sorted(names))}")
print(f"  ok    recommended stages {len(selection)} flags -> {len(plan.writes)} files")
print(f"  ok    every command in the plan is on the helper's allowlist")
PY
then
    check 0 "catalogue, presets and plan building from the installed tree"
else
    check 1 "catalogue, presets and plan building from the installed tree"
fi
echo

if [ "$fail" = 0 ]; then
    echo "PASS — everything checkable outside a VM."
else
    echo "FAIL — see above."
fi
echo
echo "Still needs a fresh 26.04 VM with the network disconnected:"
echo "  1. dpkg -i $DEB   must install with zero errors"
echo "  2. launch the GUI, load the stock preset, open the review diff"
echo "That test is the §1 promise; nothing here substitutes for it."

exit $fail
