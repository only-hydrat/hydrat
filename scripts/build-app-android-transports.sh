#!/bin/sh
set -eu

: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to Android NDK r28c}"
output=${1:?Pass an absolute directory for libtor.so and liblyrebird.so}
case "$output" in /*) ;; *) exit 2 ;; esac
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
stage=${HYDRAT_ANDROID_BUILD_DIR:-$(mktemp -d)}
mkdir -p "$output" "$stage"
if [ -z "${HYDRAT_ANDROID_BUILD_DIR:-}" ]; then
    trap 'rm -rf "$stage"' EXIT
fi
jobs=${HYDRAT_BUILD_JOBS:-4}
ndk="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64"
export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
export PATH="$ndk/bin:$PATH"
cc="$ndk/bin/aarch64-linux-android29-clang"
prefix="$stage/prefix"
export AR="$ndk/bin/llvm-ar"
export RANLIB="$ndk/bin/llvm-ranlib"
export LDFLAGS="-Wl,-z,max-page-size=16384"

download() {
    name=$1
    url=$2
    expected=$3
    if [ ! -f "$stage/$name" ]; then
        curl --retry 4 --connect-timeout 15 --max-time 240 -fsSL "$url" -o "$stage/$name.part"
        mv "$stage/$name.part" "$stage/$name"
    fi
    (cd "$stage" && printf '%s  %s\n' "$expected" "$name" | sha256sum -c -)
}

download tor.tar.gz https://dist.torproject.org/tor-0.4.9.17.tar.gz \
    ff372c41ee7013557fe5b7acd96c909950b27a7959c59fcb87c02591682fabe2
download openssl.tar.gz https://codeload.github.com/openssl/openssl/tar.gz/refs/tags/openssl-3.5.4 \
    758b69feed5787dc12d34b0eb29b60d3c9d73d5a64760c62d93a6d26b344d65d
download libevent.tar.gz https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz \
    92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb

for source in tor openssl libevent; do tar -xzf "$stage/$source.tar.gz" -C "$stage"; done
(
    cd "$stage/openssl-openssl-3.5.4"
    perl Configure android-arm64 -D__ANDROID_API__=29 no-tests no-shared \
        --prefix="$prefix" --libdir=lib
    make -j "$jobs" build_sw
    make install_dev
)
(
    cd "$stage/libevent-2.1.12-stable"
    CC="$cc" ./configure --host=aarch64-linux-android --prefix="$prefix" \
        --enable-static --disable-shared --disable-openssl --disable-samples --disable-libevent-regress
    make -j "$jobs"
    make install
)
(
    cd "$stage/tor-0.4.9.17"
    CC="$cc" ./configure --host=aarch64-linux-android --disable-tool-name-check --disable-asciidoc --disable-systemd \
        --disable-module-relay --disable-lzma --disable-zstd \
        --enable-static-openssl --with-openssl-dir="$prefix" \
        --enable-static-libevent --with-libevent-dir="$prefix"
    make -j "$jobs" src/app/tor
    "$ndk/bin/llvm-strip" -o "$output/libtor.so" src/app/tor
    chmod 755 "$output/libtor.so"
)
transport=gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird
version=$(sed -n 's/^ARG LYREBIRD_VERSION=//p' "$root/Dockerfile")
checksum=$(sed -n 's/^ARG LYREBIRD_SOURCE_SHA256=//p' "$root/Dockerfile")
download lyrebird.zip "https://proxy.golang.org/$transport/@v/$version.zip" "$checksum"
if [ ! -d "$root/app/native/.anet" ]; then
    "$root/scripts/prepare-app-xray.sh"
fi
(
    cd "$stage"
    unzip -oq lyrebird.zip
    cd "$transport@$version"
    go get github.com/pion/interceptor@v0.1.39 golang.org/x/crypto@v0.52.0 golang.org/x/net@v0.55.0
    go mod edit -replace "github.com/wlynxg/anet=$root/app/native/.anet"
    go mod tidy
    GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC="$cc" \
        go build -trimpath -buildvcs=false -ldflags '-s -w -extldflags=-Wl,-z,max-page-size=16384' \
        -o "$output/liblyrebird.so" ./cmd/lyrebird
)
