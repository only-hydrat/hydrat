#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
target="$root/app/native/.xray"
anet="$root/app/native/.anet"
if [ -e "$target" ] || [ -L "$target" ]; then
    printf 'Build source already exists at %s\n' "$target" >&2
    exit 1
fi
if [ -e "$anet" ]; then
    printf 'Build source already exists at %s\n' "$anet" >&2
    exit 1
fi

read_arg() {
    sed -n "s/^ARG $1=//p" "$root/Dockerfile"
}
commit=$(read_arg XRAY_COMMIT)
checksum=$(read_arg XRAY_SOURCE_SHA256)
stage=$(mktemp -d "$root/app/native/.xray-stage.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT
curl -fsSL --retry 4 --connect-timeout 15 --max-time 180 \
    "https://codeload.github.com/XTLS/Xray-core/zip/$commit" -o "$stage/source.zip"
(
    cd "$stage"
    printf '%s  source.zip\n' "$checksum" | sha256sum -c -
    unzip -q source.zip
    cd "Xray-core-$commit"
    mkdir common/hydratflow
    cp "$root"/internal/xrayflow/*.go common/hydratflow/
    for name in embedded-instance-dialer embedded-unix-socks embedded-tun-reconnect flow-recovery routing-cancellation windows-unix-commander; do
        patch -p1 --fuzz=0 < "$root/patches/xray/$name.patch"
    done
    sed -i 's/c.server = grpc.NewServer()/c.server = grpc.NewServer(grpc.MaxRecvMsgSize(16 * 1024 * 1024))/' app/commander/commander.go
    sed -i '/^[[:space:]]*if requiresTransportSecurity(vlessCfg.Address) {$/,+2d' infra/conf/xray.go
    grep -Fq 'grpc.NewServer(grpc.MaxRecvMsgSize(16 * 1024 * 1024))' app/commander/commander.go
    grep -Fq 'trojan without TLS is prohibited' infra/conf/xray.go
    if grep -Fq 'vless without TLS or other encryption is prohibited' infra/conf/xray.go; then
        exit 1
    fi
)
(
    cd "$root"
    go mod download github.com/wlynxg/anet@v0.0.5
    cached="$(go env GOMODCACHE)/github.com/wlynxg/anet@v0.0.5"
    cp -R "$cached" "$stage/anet"
    chmod -R u+w "$stage/anet"
    cd "$stage/anet"
    patch -p1 --fuzz=0 < "$root/patches/android/anet-zone-cache.patch"
)
mv "$stage/anet" "$anet"
mv "$stage/Xray-core-$commit" "$target"
