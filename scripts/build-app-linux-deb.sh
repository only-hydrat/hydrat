#!/bin/sh
set -eu

tor=$(realpath "${1:?Pass the verified Linux x86-64 Tor Expert Bundle}")
geo=$(realpath "${2:?Pass the directory containing geoip.dat and geosite.dat}")
output=$(realpath -m "${3:?Pass the destination DEB path}")
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
version=${4:-$(cat "$root/internal/appupdate/version.txt")}
dpkg --validate-version "$version"
printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){2}$'
native="$root/app/native"
source="$root/app/linux"
packaging="$source/packaging"

for file in "$tor" "$geo/geoip.dat" "$geo/geosite.dat"; do
    test -s "$file" || { printf 'Missing %s\n' "$file" >&2; exit 1; }
done
if [ ! -d "$native/.xray" ]; then
    "$root/scripts/prepare-app-xray.sh"
fi
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
package="$stage/deb"
app="$package/usr/lib/hydrat-app"
docs="$package/usr/share/doc/hydrat-app"
mkdir -p "$app/geo" "$docs" "$package/DEBIAN" "$package/usr/bin"
printf '%s\n' "$version" > "$app/VERSION"
tar -xzf "$tor" -C "$app" tor/tor tor/libcrypto.so.3 tor/libssl.so.3 tor/libevent-2.1.so.7 \
    tor/pluggable_transports/lyrebird data/geoip data/geoip6 docs
mv "$app/docs" "$docs/tor"
install -m 0644 "$geo/geoip.dat" "$geo/geosite.dat" "$app/geo/"
install -m 0644 "$root/LICENSE" "$docs/copyright"
install -m 0644 "$native/.xray/LICENSE" "$docs/Xray.txt"
install -m 0644 "$source/README.md" "$docs/README.md"
install -m 0644 "$root/app/android/src/main/res/drawable-nodpi/hydrat_launcher_mark.png" "$app/icon.png"
install -m 0644 "$source/theme.css" "$app/theme.css"
install -m 0755 "$source/hydrat.py" "$packaging/tor-runtime" "$app/"
ln -s ../lib/hydrat-app/hydrat.py "$package/usr/bin/hydrat-app"
install -Dm 0644 "$packaging/hydrat-app.service" "$package/lib/systemd/system/hydrat-app.service"
install -Dm 0644 "$packaging/50-hydrat-app.rules" "$package/usr/share/polkit-1/rules.d/50-hydrat-app.rules"
install -Dm 0644 "$packaging/hydrat-app.desktop" "$package/usr/share/applications/hydrat-app.desktop"
install -m 0755 "$packaging/postinst" "$packaging/prerm" "$packaging/postrm" "$package/DEBIAN/"

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go -C "$native" build -trimpath -buildvcs=false \
    -ldflags "-s -w -X github.com/only-hydrat/hydrat/internal/appupdate.version=$version" -o "$app/hydrat-service" ./cmd/linux
cat > "$package/DEBIAN/control" <<CONTROL
Package: hydrat-app
Version: $version
Section: net
Priority: optional
Architecture: amd64
Maintainer: Hydrat <only-hydrat@users.noreply.github.com>
Installed-Size: $(du -sk "$package" | cut -f1)
Depends: adduser, init-system-helpers, systemd, systemd-resolved, polkitd, iproute2, nftables, python3, python3-gi, gir1.2-gtk-3.0, ca-certificates, libc6 (>= 2.34), zlib1g
Homepage: https://github.com/only-hydrat/hydrat
Description: Hydrat desktop VPN client
 GTK desktop client and local system VPN service with automatic VLESS and Tor
 route selection.
CONTROL
mkdir -p "$(dirname -- "$output")"
dpkg-deb --root-owner-group -Zxz --build "$package" "$stage/hydrat.deb"
mv "$stage/hydrat.deb" "$output"
printf 'Created %s\n' "$output"
