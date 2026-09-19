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
ARG XRAY_COMMIT=52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120
ARG XRAY_SOURCE_SHA256=0159e934d908cd176fed51dc61209e546046351928af685b143cad2ebe704831

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
RUN sed -i \
      's/c.server = grpc.NewServer()/c.server = grpc.NewServer(grpc.MaxRecvMsgSize(16 * 1024 * 1024))/' \
      app/commander/commander.go \
    && grep -Fq 'grpc.NewServer(grpc.MaxRecvMsgSize(16 * 1024 * 1024))' \
      app/commander/commander.go \
    && go mod download \
    && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
      go build -buildvcs=false -trimpath \
        -ldflags="-s -w -buildid= -X github.com/xtls/xray-core/core.build=52a412d-hydrat1" \
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

FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    XRAY_LOCATION_ASSET=/data/geo

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl dnsmasq-base iproute2 nftables procps tor wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

# Debian's Tor package provides the runtime. Lyrebird is built from pinned
# upstream source for obfs4 and WebTunnel transports.
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

ENTRYPOINT ["/usr/local/bin/hydrat"]
