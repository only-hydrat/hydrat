#!/bin/sh
# Opt-in PUBLIC I2P test. Opens a fixed public I2P site; no transit, host ports,
# production clients or volumes. Requires Docker, Go, and Internet access.
set -eu
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LAB_DIR=$(mktemp -d /tmp/hydrat-i2p-lab.XXXXXX)
LAB_NAME="hydrat-i2p-test-$$"
LAB_DATA="$LAB_NAME-data"
LAB_RUN="$LAB_NAME-run"
LAB_IMAGE="hydrat:i2p-test-$$"
cleanup() {
  lab_result=$?
  if [ "$lab_result" -ne 0 ]; then docker logs --tail 100 "$LAB_NAME" >&2 2>/dev/null || true; fi
  docker rm -f "$LAB_NAME-client" "$LAB_NAME" >/dev/null 2>&1 || true
  docker volume rm "$LAB_DATA" "$LAB_RUN" >/dev/null 2>&1 || true
  docker image rm "$LAB_IMAGE" >/dev/null 2>&1 || true
  rm -rf -- "$LAB_DIR"
}
trap cleanup EXIT HUP INT TERM
cd "$REPO"
docker build -f Dockerfile.i2p -t "$LAB_IMAGE" .
CGO_ENABLED=0 GOOS=linux GOARCH=$(docker version --format '{{.Server.Arch}}') go test -c -o "$LAB_DIR/i2p-test" ./internal/i2p
docker run -d --name "$LAB_NAME" --read-only --cap-drop ALL \
  --security-opt no-new-privileges --cpus 0.5 --memory 384m --pids-limit 64 \
  --tmpfs /tmp:size=16m,mode=1777 \
  -v "$LAB_DATA:/data/i2p" -v "$LAB_RUN:/run/hydrat-i2p" "$LAB_IMAGE" >/dev/null
for attempt in $(seq 1 20); do
  if docker exec "$LAB_NAME" curl -fsS --unix-socket /run/hydrat-i2p/control.sock http://localhost/status >/dev/null 2>&1; then break; fi
  sleep 1
done
docker run --rm --name "$LAB_NAME-client" --network "container:$LAB_NAME" \
  --user 10001:10001 --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:size=16m,mode=1777 -v "$LAB_DIR/i2p-test:/i2p-test:ro" \
  -v "$LAB_RUN:/run/hydrat-i2p:ro" \
  -e HYDRAT_I2P_BRIDGE_TEST=1 -e HYDRAT_I2P_XRAY_BINARY=/usr/local/bin/xray \
  --entrypoint /i2p-test "${HYDRAT_I2P_TEST_XRAY_IMAGE:-ghcr.io/only-hydrat/hydrat:1.2.0}" \
  -test.run '^TestPublicI2PBridge$' -test.v -test.timeout 7m
docker stats --no-stream --format '{{.Name}} CPU={{.CPUPerc}} memory={{.MemUsage}} PIDs={{.PIDs}}' "$LAB_NAME"
