#!/bin/sh
set -eu

wintun=${1:?Pass the official wintun-0.14.1.zip archive}
tor=${2:?Pass a verified Windows x86_64 Tor Expert Bundle tar.gz}
geo=${3:?Pass a directory containing geoip.dat and geosite.dat}
output=${4:?Pass the destination ZIP path}
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
version=${5:-$(cat "$root/internal/appupdate/version.txt")}
printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){2}$'
native="$root/app/native"
source="$native/cmd/windows"

wintun=$(realpath "$wintun")
tor=$(realpath "$tor")
geo=$(realpath "$geo")
output=$(realpath -m "$output")
for file in "$tor" "$geo/geoip.dat" "$geo/geosite.dat"; do
    test -s "$file" || { printf 'Missing %s\n' "$file" >&2; exit 1; }
done
printf '%s  %s\n' 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51 "$wintun" | sha256sum -c -
if [ ! -d "$native/.xray" ]; then
    "$root/scripts/prepare-app-xray.sh"
fi

stage=$(mktemp -d)
build=$(mktemp -d "$native/.windows-build.XXXXXXXX")
trap 'rm -rf "$stage" "$build"' EXIT
cp "$source"/*.go "$build/"
bundle="$stage/Hydrat"
mkdir -p "$bundle/geo" "$bundle/licenses"
cp "$geo/geoip.dat" "$geo/geosite.dat" "$bundle/geo/"
cp "$root/LICENSE" "$bundle/licenses/Hydrat.txt"
cp "$native/.xray/LICENSE" "$bundle/licenses/Xray.txt"
unzip -p "$wintun" 'wintun/bin/amd64/wintun.dll' > "$bundle/wintun.dll"
unzip -p "$wintun" 'wintun/LICENSE.txt' > "$bundle/licenses/Wintun.txt"
tar -xzf "$tor" -C "$bundle" tor/tor.exe tor/pluggable_transports/lyrebird.exe data docs
mv "$bundle/docs" "$bundle/licenses/Tor"
cp "$source/README.md" "$bundle/README.md"
printf '%s\n' "$version" > "$bundle/VERSION"

cp "$root/app/android/src/main/res/drawable-nodpi/hydrat_launcher_mark.png" "$bundle/icon.png"
go run "$root/scripts/windows-icon.go" "$bundle/icon.png" "$bundle/hydrat.ico"
go -C "$native" run github.com/akavel/rsrc@v0.10.2 -arch amd64 \
    -manifest "$source/Hydrat.manifest" -ico "$bundle/hydrat.ico" -o "$build/Hydrat_windows_amd64.syso"
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go -C "$native" build \
    -trimpath -buildvcs=false -ldflags "-H=windowsgui -s -w -X github.com/only-hydrat/hydrat/internal/appupdate.version=$version" \
    -o "$bundle/Hydrat.exe" "./${build##*/}"

mkdir -p "$(dirname -- "$output")"
(cd "$stage" && zip -q -r "$stage/package.zip" Hydrat)
mv "$stage/package.zip" "$output"
printf 'Created %s\n' "$output"
