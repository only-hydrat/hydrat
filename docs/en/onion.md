<p align="center"><a href="../onion.md">Русский</a> · <b>English</b> · <a href="../zh-CN/onion.md">简体中文</a></p>

# Accessing .onion sites

In the portal, open **Clients → Access .onion through Tor** for the intended device. Access is off by default and only an administrator can enable it. Users can see the status under their connection and read the guide without signing in as an administrator.

“Pending” means the permission has been saved but not applied by the gateway. “Route ready” confirms an applied Tor route, not the availability of a particular website. “No ready Tor route” calls for checking the Tor pool. When disabling access, wait until the status changes from “Disabling” to “Disabled”.

Public v3 names, subdomains and TCP are supported. UDP, v2 names and services requiring client authorization are not supported. One unavailable onion site does not disqualify an entire Tor profile. If a profile fails, another ready profile can take over; existing connections need to reconnect.

## Browsers

The dashboard guide is under System. The “How to open .onion” button in My connection opens it directly.

### Android: Firefox Nightly

1. Enable “Access .onion through Tor” for your client in Hydrat. Ask the administrator if you lack permission. Enable WireGuard and wait for “Route ready”.
2. Open Firefox Nightly from Mozilla. Regular Firefox for Android restricts access to `about:config`.
3. Open `about:config` in the address bar, find `network.dns.blockDotOnion` and set it to `false`.
4. In Firefox settings, find DNS over HTTPS and choose Off so the VPN DNS is used.
5. If Android has a custom Private DNS provider configured, temporarily turn it off. Keep the Hydrat DNS in your WireGuard configuration, usually `10.44.0.1`.
6. Enter the full address with `http://` or `https://` before `.onion` so the browser does not send it to a search engine. Use the address published by the service itself. No browser proxy setup is needed.
7. To undo the changes, set `network.dns.blockDotOnion=true` and restore your previous DNS settings. You can disable access in Hydrat.

There is no confirmed Hydrat configuration for Chrome, Edge, Brave or other Android browsers. Use Firefox Nightly for this method.

### Other devices

| Device and browser | Steps |
| --- | --- |
| Firefox on Windows/macOS/Linux | Enable WireGuard and the Hydrat permission. Set `network.dns.blockDotOnion=false` in `about:config`, turn off DNS over HTTPS, and keep the WireGuard DNS. Open the full onion address published by the service itself. |
| Chrome, Edge, Brave and desktop Safari | There is no universally verified setting: the browser may block onion names before DNS. Use Firefox as described above for Hydrat access. |
| iPhone/iPad | There is no confirmed guide for direct Hydrat access yet. Firefox settings for Android and desktop do not apply to iOS. Ordinary websites work through WireGuard. |

Never disable TLS certificate validation. These instructions follow browser documentation; every combination of physical device and browser has not been tested individually.

## Routing and privacy

The gateway resolves `.onion` locally for authorized clients, assigning persistent virtual IPv4 addresses from `198.18.0.0/15`. These DNS queries, including AAAA and HTTPS/SVCB, are never sent to external resolvers. Ordinary names continue through dnsmasq, now behind the internal `127.0.0.1:1053` listener.

Mappings are installed in serving Tor profiles using `MAPADDRESS` over private Unix control sockets with cookie authentication. Onion readiness follows mapping replay, including when an explorer profile becomes a serving profile. Each client has a separate SOCKS identity; ordinary TCP/UDP assignments remain in place. Virtual-address rules precede GeoRules and direct routing. The range is blocked without permission or a route. No public SOCKS or control listener is needed.

This provides convenient access, not Tor Browser’s privacy protections. Ordinary browsers retain their fingerprints and cookies. Gateway administrators can read onion names in the local mapping file. It is unencrypted, protected with mode `0600`; this module does not log DNS names.

## Persistent state

`onion-mappings.json`, its `.initialized` marker and `.lock` file live beside `applied-plan.json`. Back up the book and marker with gateway/WireGuard state. **`hydrat backup` backs up SQLite, not these files.** Stop the gateway before copying its state directory for a consistent backup. Never delete the book or restore an older copy while devices may retain newer cached addresses.

Addresses are never reused for another name. The book holds at most 1024 names. Exhaustion, corruption or missing state blocks new onion access while ordinary DNS keeps working. Restore current state; do not remove the marker to bypass protection. The WireGuard subnet must not overlap `198.18.0.0/15`.

References: [Firefox DNS](https://support.mozilla.org/kb/firefox-dns-over-https), [Firefox preferences](https://searchfox.org/firefox-main/source/modules/libpref/init/StaticPrefList.yaml), [MAPADDRESS](https://spec.torproject.org/control-spec/commands.html#mapaddress).

New names are rate limited per client: burst 8, refilling one token every 6 seconds. The shared budget allows a burst of 16 and one token per second. Previously allocated names do not consume tokens. Slow Tor queries have a separate budget from ordinary DNS.

Developers can run `scripts/test-onion-integration.sh` on Linux with Docker and Go. It downloads a pinned Tor Chutney revision, builds a test image, and creates a local Tor network plus two WireGuard clients inside a container with no external network. It requires a privileged container; use a development machine. The container and temporary data are cleaned up automatically.

Ordinary DNS queries reach dnsmasq over UDP, with TCP fallback for truncated responses. The primary and reserve onion profiles receive active probes through the supplementary probe lane, preserving the reserved lane for ordinary primary/reserve routes.

## Tor quality checks

When onion access is enabled, the existing QoE monitor checks the official DuckDuckGo and Tor Project onion sites through the serving Tor profiles. Checks share the worker limit; they do not use direct HTTP requests from the VPS or a separate onion throughput download. Onion results do not change ordinary TCP/UDP route quality.

A failed request counts against a profile only when a fresh check reaches the same service through an independent bridge. If both paths fail, the result remains inconclusive. Repeated confirmed failures or consistently slow responses lower the rating through the existing QoE window. Results from a replaced Tor process are discarded.

A healthy primary stays in place to preserve open connections. Reserve selection uses fresh checks; a third ready profile can replace a primary whose quality has deteriorated. Other qualified bridges are explored in sequence within the existing bounded Tor pool. Bridges are not all started at once, and opening an arbitrary onion site for the first time may still require circuit setup. These checks stop when onion access is disabled for every client.
