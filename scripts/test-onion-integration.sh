#!/bin/sh
# Local Linux/Docker test only. All VPN and Tor traffic stays in an isolated
# container (--network none); no production configuration or peers are used.
set -eu
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LAB_DIR=$(mktemp -d /tmp/hydrat-onion-lab.XXXXXX)
LAB_NAME="hydrat-onion-test-$$"
LAB_IMAGE="hydrat:onion-test-$$"
CHUTNEY_REV=62b54a55215c94eb14adc22c5acd17b2ada04b76
cleanup() {
  # Stop writers before removing root-owned Chutney state. Removing it while
  # Tor is still alive lets shutdown recreate files after cleanup.
  docker rm -f "$LAB_NAME" >/dev/null 2>&1 || true
  docker run --rm --network none --user 0:0 -v "$LAB_DIR/chutney:/chutney" \
    --entrypoint rm "$LAB_IMAGE" -rf /chutney/net >/dev/null 2>&1 || true
  docker image rm "$LAB_IMAGE" >/dev/null 2>&1 || true
  rm -rf -- "$LAB_DIR"
}
trap cleanup EXIT HUP INT TERM
command -v docker >/dev/null
command -v go >/dev/null
command -v git >/dev/null
git init -q "$LAB_DIR/chutney"
git -C "$LAB_DIR/chutney" remote add origin https://github.com/torproject/chutney.git
git -C "$LAB_DIR/chutney" fetch -q --depth 1 origin "$CHUTNEY_REV"
git -C "$LAB_DIR/chutney" checkout -q --detach FETCH_HEAD
test "$(git -C "$LAB_DIR/chutney" rev-parse HEAD)" = "$CHUTNEY_REV"
cat > "$LAB_DIR/Dockerfile" <<'DOCKERFILE'
ARG BASE=ghcr.io/only-hydrat/hydrat:1.2.0
FROM ${BASE}
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
DOCKERFILE
docker build -q --build-arg "BASE=${HYDRAT_ONION_TEST_IMAGE:-ghcr.io/only-hydrat/hydrat:1.2.0}" -t "$LAB_IMAGE" "$LAB_DIR"
cd "$REPO"
CGO_ENABLED=0 GOOS=linux GOARCH=$(docker version --format '{{.Server.Arch}}') go test -c -o "$LAB_DIR/onion-test" ./internal/xrayapi
docker run -d --privileged --network none -e PYTHONDONTWRITEBYTECODE=1 --name "$LAB_NAME" -v "$LAB_DIR/chutney:/chutney" --entrypoint sleep "$LAB_IMAGE" infinity >/dev/null
docker cp "$LAB_DIR/onion-test" "$LAB_NAME:/onion-test"
docker exec -w /chutney -e CHUTNEY_TOR_SANDBOX=0 "$LAB_NAME" ./chutney configure networks/hs-v3-min
# Only the two client profiles receive the production control/mapping settings.
docker exec -i "$LAB_NAME" python3 - <<'PY'
from pathlib import Path
for node, port in [('006c', 19050), ('007h', 19051)]:
    path = Path('/chutney/net/nodes') / node / 'torrc'
    lines = [line for line in path.read_text().splitlines()
             if not line.startswith(('SocksPort ', 'ControlSocket ', 'CookieAuthFile '))]
    lines += [f'SocksPort 127.0.0.1:{port} IsolateSOCKSAuth',
              f'ControlSocket /chutney/net/nodes/{node}/control.sock',
              f'CookieAuthFile /chutney/net/nodes/{node}/control_auth_cookie',
              'VirtualAddrNetworkIPv4 198.18.0.0/15']
    path.write_text('\n'.join(lines) + '\n')
PY
for phase in 1 2; do
  docker exec -w /chutney -e CHUTNEY_TOR_SANDBOX=0 -e "CHUTNEY_LAUNCH_PHASE=$phase" "$LAB_NAME" ./chutney start networks/hs-v3-min
  docker exec -w /chutney -e CHUTNEY_TOR_SANDBOX=0 -e "CHUTNEY_LAUNCH_PHASE=$phase" -e CHUTNEY_START_TIME=120 "$LAB_NAME" ./chutney wait_for_bootstrap networks/hs-v3-min
done
docker exec -e HYDRAT_ONION_LAB=1 "$LAB_NAME" /onion-test -test.run '^TestOnionVPNIntegration$' -test.v -test.timeout 5m
