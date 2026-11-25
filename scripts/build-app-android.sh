#!/bin/sh
set -eu
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to Android NDK r28c}"
geo=${1:?Pass a directory containing geoip.dat and geosite.dat}
transport=${2:?Pass a directory with Tor and Lyrebird Android executables}
case "${3:-debug}" in
    debug) task=assembleDebug ;;
    release) task=assembleRelease ;;
    *) printf 'Expected debug or release build variant\n' >&2; exit 1 ;;
esac
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
jni="$root/app/android/build/hydrat/jni/arm64-v8a"
assets="$root/app/android/build/hydrat/assets"
ndk="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64"
if [ ! -d "$root/app/native/.xray" ]; then
    "$root/scripts/prepare-app-xray.sh"
fi

for file in "$geo/geoip.dat" "$geo/geosite.dat" "$transport/libtor.so" "$transport/liblyrebird.so"; do
    test -s "$file" || { printf 'Missing %s\n' "$file" >&2; exit 1; }
done

mkdir -p "$jni" "$assets"
install -m 0644 "$geo/geosite.dat" "$geo/geoip.dat" "$assets/"
install -m 0755 "$transport/libtor.so" "$transport/liblyrebird.so" "$jni/"
(
    cd "$root/app/native"
    GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC="$ndk/bin/aarch64-linux-android29-clang" \
        go build -trimpath -buildvcs=false -buildmode=c-shared \
        -ldflags '-s -w -extldflags=-Wl,-z,max-page-size=16384' \
        -o "$jni/libhydrat.so" ./cmd/android
    rm -f "$jni/libhydrat.h"
)
for binary in "$jni"/*.so; do
    "$ndk/bin/llvm-readelf" -h "$binary" | grep -Eq 'Machine:.*AArch64'
    "$ndk/bin/llvm-readelf" -lW "$binary" | awk '
        $1 == "LOAD" { count++; if ($NF != "0x4000") invalid = 1 }
        END { exit (count == 0 || invalid) }
    ' || { printf 'Invalid ELF page alignment for %s\n' "$binary" >&2; exit 1; }
done
gradle -p "$root/app/android" "$task"
