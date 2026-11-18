<p align="center"><a href="../i2p.md">Русский</a> · <b>English</b> · <a href="../zh-CN/i2p.md">简体中文</a></p>

# Accessing .i2p websites through Hydrat

I2P is an optional, separate service for `.i2p` websites. It does not compete with VLESS/Tor routes for ordinary internet traffic. Access is granted per WireGuard client and is disabled by default.

## Installation

Version 1.2.0 provides prebuilt amd64 and arm64 images. The optional service uses `ghcr.io/only-hydrat/hydrat:1.2.0-i2p`. From the project root with `.env` configured:

```sh
docker compose -f docker-compose.yml -f docker-compose.i2p.yml pull
docker compose -f docker-compose.yml -f docker-compose.i2p.yml up -d
```

Use the same version for the gateway, controller and I2P service. Set `HYDRAT_I2P_IMAGE` in `.env` to use another compatible image. Keep `-f docker-compose.i2p.yml` in your Compose command when updating.

For development and source builds, add both dev files:

```sh
docker compose -f docker-compose.yml -f docker-compose.dev.yml \
  -f docker-compose.i2p.yml -f docker-compose.i2p.dev.yml up -d --build
```

Enable I2P access for a client under Clients. System → I2P websites and address book provides status, manual warmup, idle duration and address management. Granting access prewarms I2P.

## Browser setup

1. Connect through WireGuard and keep the DNS supplied in the Hydrat configuration.
2. Disable browser DNS over HTTPS for this connection if it bypasses the gateway. System private DNS must also use the gateway's resolver.
3. Enter a complete URL such as `http://name.i2p/` to avoid sending it to a search engine. Named sites need address book entries; standard public `.b32.i2p` addresses work without one.

No separate I2P application or browser proxy is needed. This feature supports websites over TCP, not arbitrary I2P applications, hosted services or UDP. Your regular browser still retains its cookies and fingerprint.

## Sleep and warmup

By default, i2pd stays running for two hours after use, then its process stops. The idle duration can be set from 15 minutes to 24 hours. Active client connections keep it running; closing them starts a new idle period. Status checks, ordinary VPN traffic and background subscriptions do not extend it.

A small supervisor remains running while i2pd sleeps. An authorized `.i2p` DNS request or a connection to a previously assigned IP wakes i2pd. Stored network information helps restart, but tunnels must be rebuilt. Opening a site immediately after sleep is not guaranteed; wait for warmup and reload if necessary. “Warm” describes the client tunnels, not the availability of every website.

## Address book

On first gateway startup, Hydrat seeds 71 names once from the [official I2P hosts.txt](https://github.com/i2p/i2p.i2p/blob/53002765a300547a2c663ac3c8d50a1b7c56cf1e/installer/resources/hosts.txt). The snapshot is bundled, so startup needs no GitHub connection. The forum address in this list is `http://i2pforum.i2p/`, not `forum.i2p`. Existing entries take precedence and deleted defaults stay deleted after restart. If the book is full, only entries that fit are added. A listed name does not guarantee that the site is currently online.

- Manual entries accept an `.i2p` name and either a public Destination or a standard `.b32.i2p` address.
- Preview `hosts.txt` before importing. Replacing a known destination requires confirmation.
- Export preserves the original public Destination when supplied. B32-only entries use `name=B32`, a Hydrat extension that other I2P clients may not accept.
- Subscriptions accept public HTTPS on port 443 or HTTP(S) inside I2P. Background refresh happens at most once every six hours while I2P is running. Manual refresh can wake I2P and runs in the background.
- New names are accepted automatically. Changed destinations enter conflict review. Manual records take precedence; removing a subscription leaves accepted records in place.

Import and subscription bodies are limited to 1 MiB, the book to 1,024 names, and subscriptions to ten. New virtual addresses have a per-client allocation budget; existing addresses remain usable when that budget is exhausted. A destination change allocates a new virtual IP and closes connections to the old address. Retired IPs are never reused. Back up the book with gateway data; deleting it is not a safe reset procedure.

Addresses and conflicts are paginated; search covers the entire book. Stored conflicts have a shared 1 MiB budget. An update that exceeds it is rejected with an error, preserving existing data. Resolve accumulated conflicts and refresh again.

If I2P bridge port `19447` overlaps configured Xray or Tor ports, only I2P is disabled; ordinary VPN services keep their ports. The gateway log records the reason.

## No third-party transit

i2pd runs with `notransit=true`, `floodfill=false` and `share=0`. UPnP, the public console, internet outproxy and hosted I2P services are disabled. No container ports are published and no Docker socket is mounted. Hydrat monitors participating tunnel counts and stops I2P if the count is nonzero or verification fails. Tor remains a client, without relay/bridge duties.

This prevents third-party transit but does not hide I2P participation: neighboring peers see the gateway IP. Your own traffic still uses other network participants. Disabling transit does not itself impose a fixed speed penalty; performance depends on tunnels, sites, network conditions and container resources. Default limits are 0.5 CPU and 384 MiB RAM.

## Isolation and diagnostics

`.i2p` queries never reach external DNS, including AAAA/HTTPS/SVCB. Ordinary DNS, onion and I2P requests use separate queues. I2P uses `198.19.0.0/16`; newly allocated onion addresses use the lower half of the original range. If an existing onion mapping occupies the I2P range, I2P stays unavailable while existing onion access is preserved.

```sh
docker compose -f docker-compose.yml -f docker-compose.i2p.yml logs --tail 100 i2pd
docker compose -f docker-compose.yml -f docker-compose.i2p.yml exec i2pd \
  curl --fail --silent --unix-socket /run/hydrat-i2p/control.sock http://localhost/status
```

If verification stops I2P, inspect the logs first. After resolving the cause, restart only the `i2pd` service. Hydrat does not continue blindly when the transit counter cannot be checked.

Sleeping I2P does not make the main `/api/ready` unhealthy. A failed I2P website does not change the client's ordinary route. Checks include Go/Node tests, `scripts/test-onion-integration.sh` (a VPN lab including an I2P bridge with a local SOCKS backend), and `scripts/test-i2p-integration.sh`, an explicit public-network test through real Xray and i2pd. The latter contacts a public I2P site and removes its temporary containers after testing. The local backend alone is not proof of public I2P connectivity.

Router settings: [i2pd documentation](https://docs.i2pd.website/en/latest/user-guide/configuration/).
