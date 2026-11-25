#!/bin/sh
set -eu

bundle=$(realpath "${1:?Pass the Hydrat Windows x64 ZIP}")
output=$(realpath -m "${2:?Pass the destination MSI path}")
version=${3:?Pass the three-part MSI version}
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
wixl=${WIXL:-wixl}

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
unzip -q "$bundle" -d "$stage"
cd "$stage"
if [ "$(cat Hydrat/VERSION)" != "$version" ]; then
    printf 'MSI version must match the version in the ZIP bundle.\n' >&2
    exit 1
fi
python3 "$root/scripts/windows-msi.py" "$version"
"$wixl" -a x64 -o Hydrat.msi Hydrat.wxs
# wixl 0.103 schedules removal before the transaction. Moving it immediately
# after InstallInitialize lets Windows Installer roll back a failed upgrade.
msibuild Hydrat.msi -q "UPDATE \`InstallExecuteSequence\` SET \`Sequence\` = 1501 WHERE \`Action\` = 'RemoveExistingProducts'"
mkdir -p "$(dirname -- "$output")"
mv Hydrat.msi "$output"
printf 'Created %s\n' "$output"
