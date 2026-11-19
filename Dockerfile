ARG TOR_PACKAGE_VERSION=0.4.9.17-1~d12.bookworm+1

FROM --platform=$BUILDPLATFORM golang:1.26.5-bookworm AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
      go build -trimpath -ldflags="-s -w" -o /out/hydrat ./cmd/hydrat

FROM --platform=$BUILDPLATFORM golang:1.26.5-bookworm AS lyrebird-build

ARG TARGETOS
ARG TARGETARCH
ARG LYREBIRD_COMMIT=fc105a03c0e0acc2479301c361c012ffed359c43
ARG LYREBIRD_VERSION=v0.0.0-20260312101154-fc105a03c0e0
ARG LYREBIRD_SOURCE_SHA256=e460a90a67c8831d5e8f70b652b39cba0bc05190412c7034bbb8c90fb1b9baff

ENV GOTOOLCHAIN=local \
    GOPROXY=https://proxy.golang.org,direct \
    GOSUMDB=sum.golang.org

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN set -eu; \
    archive="lyrebird-${LYREBIRD_COMMIT}.zip"; \
    curl --retry 5 --connect-timeout 15 -fsSL \
      "https://proxy.golang.org/gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/@v/${LYREBIRD_VERSION}.zip" \
      -o "$archive"; \
    printf '%s  %s\n' "$LYREBIRD_SOURCE_SHA256" "$archive" | sha256sum -c -; \
    unzip -q "$archive"; \
    mv "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird@${LYREBIRD_VERSION}" lyrebird; \
    rm "$archive"

WORKDIR /src/lyrebird
RUN go get \
      github.com/pion/interceptor@v0.1.39 \
      golang.org/x/crypto@v0.52.0 \
      golang.org/x/net@v0.55.0 \
    && go mod tidy \
    && go test ./... \
    && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
      go build -trimpath -ldflags="-s -w" -o /out/lyrebird ./cmd/lyrebird

FROM --platform=$BUILDPLATFORM golang:1.27.1-bookworm AS xray-build

ARG TARGETOS
ARG TARGETARCH
# XTLS/Xray-core v26.11.9
ARG XRAY_COMMIT=676eaf66f8f05d4d558ee7a74b4736623d3feeb9
ARG XRAY_SOURCE_SHA256=05623c5394d82870edcfdd9355169b05453da133544355012b2cd1874e67f100

ENV GOTOOLCHAIN=local \
    GOPROXY=https://proxy.golang.org,direct \
    GOSUMDB=sum.golang.org

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN set -eu; \
    archive="xray-${XRAY_COMMIT}.zip"; \
    curl --retry 5 --connect-timeout 15 -fsSL \
      "https://codeload.github.com/XTLS/Xray-core/zip/${XRAY_COMMIT}" \
      -o "$archive"; \
    printf '%s  %s\n' "$XRAY_SOURCE_SHA256" "$archive" | sha256sum -c -; \
    unzip -q "$archive"; \
    mv "Xray-core-${XRAY_COMMIT}" xray; \
    rm "$archive"

WORKDIR /src/xray
COPY internal/xrayflow/ ./common/hydratflow/
COPY patches/xray/flow-recovery.patch /tmp/hydrat-flow-recovery.patch
COPY patches/xray/routing-cancellation.patch /tmp/hydrat-routing-cancellation.patch
RUN git apply --check /tmp/hydrat-flow-recovery.patch /tmp/hydrat-routing-cancellation.patch \
    && git apply /tmp/hydrat-flow-recovery.patch /tmp/hydrat-routing-cancellation.patch \
    && go test ./common/hydratflow \
    && go test ./app/router ./app/router/command -run '^TestCanceled(AddRule|Reload)'
RUN sed -i \
      's/c.server = grpc.NewServer()/c.server = grpc.NewServer(grpc.MaxRecvMsgSize(16 * 1024 * 1024))/' \
      app/commander/commander.go \
    && sed -i \
      '/^[[:space:]]*if requiresTransportSecurity(vlessCfg.Address) {$/,+2d' \
      infra/conf/xray.go \
    && grep -Fq 'grpc.NewServer(grpc.MaxRecvMsgSize(16 * 1024 * 1024))' \
      app/commander/commander.go \
    && ! grep -Fq 'vless without TLS or other encryption is prohibited' \
      infra/conf/xray.go \
    && grep -Fq 'trojan without TLS is prohibited' infra/conf/xray.go \
    && go mod download \
    && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
      go build -buildvcs=false -trimpath \
        -ldflags="-s -w -buildid= -X github.com/xtls/xray-core/core.build=$(printf '%.7s' "$XRAY_COMMIT")-hydrat4" \
        -o /out/xray ./main

FROM --platform=$BUILDPLATFORM golang:1.26.5-bookworm AS probe-runtime-test

ARG TARGETOS
ARG TARGETARCH
ARG XRAY_STRESS_SKIP_EPOCH_RESET=0

COPY --from=xray-build /out/xray /usr/local/bin/xray
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY config ./config
COPY cmd ./cmd
COPY internal ./internal
ENV HYDRAT_XRAY_BINARY=/usr/local/bin/xray \
    HYDRAT_XRAY_STRESS_SKIP_EPOCH_RESET=$XRAY_STRESS_SKIP_EPOCH_RESET
RUN go test -tags=xrayintegration -count=1 -v ./internal/proberuntime

FROM --platform=$BUILDPLATFORM golang:1.26.5-bookworm AS xray-feasibility-test

COPY --from=xray-build /out/xray /usr/local/bin/xray
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY config ./config
COPY internal ./internal
ENV HYDRAT_XRAY_BINARY=/usr/local/bin/xray
RUN CGO_ENABLED=0 go test -tags=xrayintegration -count=1 -v \
      ./internal/dataplane ./internal/xrayapi
ENTRYPOINT ["go", "test", "-tags=xrayintegration", "-count=1", "-v", "./internal/dataplane", "./internal/xrayapi"]

# Tor Project Bookworm packages, with hashes from its signed package indexes.
FROM scratch AS tor-amd64
ARG TOR_PACKAGE_VERSION
ADD --chmod=0644 --checksum=sha256:0a8745352f01acc630b8ce0122f15e37c01fc8ec98fcd791be5fa37b675484d3 https://deb.torproject.org/torproject.org/pool/main/t/tor/tor_${TOR_PACKAGE_VERSION}_amd64.deb /tor.deb

FROM scratch AS tor-arm64
ARG TOR_PACKAGE_VERSION
ADD --chmod=0644 --checksum=sha256:120aeb1578d88bf87bde41874b112e9471a4510587597700c2cbb9401cf378c2 https://deb.torproject.org/torproject.org/pool/main/t/tor/tor_${TOR_PACKAGE_VERSION}_arm64.deb /tor.deb

FROM tor-${TARGETARCH} AS tor-package

FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    XRAY_LOCATION_ASSET=/data/geo

RUN --mount=type=bind,from=tor-package,source=/tor.deb,target=/tmp/tor.deb \
    apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl dnsmasq-base iproute2 nftables procps wireguard-tools /tmp/tor.deb \
    && rm -rf /var/lib/apt/lists/*

# Lyrebird is built from pinned upstream source for obfs4 and WebTunnel.
RUN groupadd --gid 10001 hydrat \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent hydrat \
    && install -d -m 0755 /etc/hydrat /run/hydrat /usr/local/share/xray /data/geo \
    && ln -sf /data/geo/geoip.dat /usr/local/share/xray/geoip.dat \
    && ln -sf /data/geo/geosite.dat /usr/local/share/xray/geosite.dat

COPY --from=build /out/hydrat /usr/local/bin/hydrat
COPY --from=lyrebird-build /out/lyrebird /usr/local/bin/lyrebird
COPY --from=xray-build /out/xray /usr/local/bin/xray
COPY config/xray/main.json /etc/hydrat/xray-main.json
COPY config/xray/probe.json /etc/hydrat/xray-probe.json
COPY config/xray/active.json /etc/hydrat/xray-active.json
COPY config/nftables/hydrat.nft /etc/hydrat/nftables.nft
COPY config/config.yml /etc/hydrat/config.yml
COPY docker-compose.yml docker-compose.i2p.yml docker-compose.updates.yml /usr/local/share/hydrat/release/

ENTRYPOINT ["/usr/local/bin/hydrat"]
