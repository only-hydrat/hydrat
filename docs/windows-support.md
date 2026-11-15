# Windows build support

The gateway data plane remains Linux-only. Windows commands load and validate
configuration before refusing agent/controller startup. The public API is unchanged.
Windows 7 cannot be supported with the module's current Go requirement; Go 1.21
removed Windows 7/8 support (https://go.dev/doc/go1.21#ports), and the gateway
runtime needs a Linux host anyway. A Windows 7 machine can only act as a
WireGuard client of a Linux-hosted gateway; that client is out of scope here.

## Explicit Windows errors

All errors below have type `*platform.UnsupportedError` (discoverable through
`errors.As`). Each feature string is followed by `: unsupported on windows`.

- `I2P control Unix socket`
- `I2P router process groups`
- `I2P supervisor Unix socket`
- `Linux gateway commands (nftables and ip route)`
- `Tor control Unix socket`
- `Tor process groups`
- `Unix socket transport`
- `WireGuard activity commands`
- `WireGuard configuration commands`
- `Xray flow control Unix socket`
- `Xray gateway API commands`
- `gateway Unix socket`
- `hydrat is a Linux gateway; the controller/agent need WireGuard, nftables and a Linux netns`
- `i2p address book advisory locks`
- `onion address book advisory locks`
- `probe Xray process signals`
- `retained log maintenance`
- `retained log writer (openat)`
- `secure log directory ownership and permissions`

`Writer.Close` remains safe and returns nil. Windows CLI startup uses stderr
instead of opening retained service logs. Direct retained-log operations fail.
Directory fsync is a documented no-op on Windows for portable state persistence;
Unix still syncs directory entries. SQLite file URIs normalize Windows drive paths
without changing Unix DSNs, database schema, or routing/scheduling behavior.

## Added and split files

Production platform files (the matching Unix implementation preserves the previous
code, and the Windows counterpart returns unsupported errors):

- `cmd/hydrat/platform_unix.go`
- `cmd/hydrat/platform_windows.go`
- `cmd/hydrat/service_log_unix.go`
- `cmd/hydrat/service_log_windows.go`
- `cmd/hydrat/socket_unix.go`
- `cmd/hydrat/socket_windows.go`
- `internal/gateway/exec_unix.go`
- `internal/gateway/exec_windows.go`
- `internal/i2p/client_transport_unix.go`
- `internal/i2p/client_transport_windows.go`
- `internal/i2p/lock_unix.go`
- `internal/i2p/lock_windows.go`
- `internal/i2p/process_control_unix.go`
- `internal/i2p/process_control_windows.go`
- `internal/i2p/rpc_unix.go`
- `internal/i2p/rpc_windows.go`
- `internal/i2p/supervisor_unix.go`
- `internal/i2p/supervisor_windows.go`
- `internal/onion/control_transport_unix.go`
- `internal/onion/control_transport_windows.go`
- `internal/onion/lock_unix.go`
- `internal/onion/lock_windows.go`
- `internal/platform/errors.go`
- `internal/platform/socket_unix.go`
- `internal/platform/socket_windows.go`
- `internal/platform/sync_unix.go`
- `internal/platform/sync_windows.go`
- `internal/proberuntime/start_unix.go`
- `internal/proberuntime/start_windows.go`
- `internal/proberuntime/stop_unix.go`
- `internal/proberuntime/stop_windows.go`
- `internal/retainedlog/writer_unix.go`
- `internal/retainedlog/writer_windows.go`
- `internal/store/path_unix.go`
- `internal/store/path_windows.go`
- `internal/torpool/process_unix.go`
- `internal/torpool/process_windows.go`
- `internal/wireguard/exec_unix.go`
- `internal/wireguard/exec_windows.go`
- `internal/wireguard/input_unix.go`
- `internal/wireguard/input_windows.go`
- `internal/xrayapi/exec_unix.go`
- `internal/xrayapi/exec_windows.go`
- `internal/xrayflow/environment_unix.go`
- `internal/xrayflow/environment_windows.go`
- `internal/xrayflow/listener_unix.go`
- `internal/xrayflow/listener_windows.go`

`internal/retainedlog/writer.go` now holds the shared `Config`; its descriptor-based
implementation is in `writer_unix.go`. Shared process types remain with their
original packages. Unix socket dialing is centralized in `platform.DialUnix`.
`store/store.go` and `store/backup.go` use platform path conversion; directory sync
call sites use `platform.SyncDirectory`.

Tests moved into Unix-specific files retain their original bodies and assertions:

- `internal/projectcheck/assets_unix_test.go`

- `cmd/hydrat/service_log_unix_test.go`
- `cmd/hydrat/socket_unix_test.go`
- `internal/controller/runtime_unix_test.go`
- `internal/i2p/admin_unix_test.go`
- `internal/i2p/regression_unix_test.go`
- `internal/i2p/subscriptions_unix_test.go`
- `internal/onion/control_unix_test.go`
- `internal/onion/mappings_unix_test.go`
- `internal/proberuntime/process_unix_test.go`
- `internal/secretbox/secretbox_unix_test.go`
- `internal/supervisor/supervisor_unix_test.go`
- `internal/torpool/manager_unix_test.go`
- `internal/torpool/process_unix_test.go`
- `internal/wireguard/server_config_unix_test.go`
- `internal/xrayapi/adapter_unix_test.go`
- `internal/xrayflow/server_unix_test.go`

Existing tests entirely dependent on Unix sockets, advisory locks, shell execution,
or POSIX permission bits have Unix build tags. Platform-independent tests remain
available on Windows. Two store tests now close their databases before temporary
folder cleanup, as required by Windows file sharing. New Windows tests cover typed
unsupported errors and configuration validation before runtime refusal:

- `cmd/hydrat/platform_windows_test.go`
- `internal/platform/facilities_windows_test.go`

## Verification

All six requested checks pass (Go 1.27.1 installed on Linux):

| Command | Result |
| --- | --- |
| `GOOS=windows GOARCH=amd64 go build ./...` | exit 0, no output |
| `GOOS=darwin GOARCH=arm64 go build ./...` | exit 0, no output |
| `go build ./...` | exit 0, no output |
| `TMPDIR=/tmp go test ./...` | all packages pass |
| `node --test internal/portal/web_app_test.mjs` | 21 passed, 0 failed |
| `go vet ./...` | exit 0, no output |

The CI workflow additionally runs `go build ./...` and `go test ./...` on
`windows-latest`. This job has been added but has not been run remotely here.
Windows test binaries also run locally through Wine. Its Winsock shim returns
`WSAEOPNOTSUPP` (10045) for six loopback UDP tests; those tests are preserved and
remain enabled in native Windows CI. The Wine verification excludes only:

- `TestForwardOrdinaryDNSUsesUDPThenTCPOnlyOnTruncation`
- `TestForwardRejectsUnrelatedResponseAndHonorsCancellation`
- `TestDNSListenerUDPAndTCPAndShutdown`
- `TestOnionConcurrencyCannotConsumeOrdinaryDNSBudget`
- `TestCheckQUICResolvesThroughClientDNSBeforeCandidateSOCKS`
- `TestDialerPacketConnRelaysUDPAndPreservesPeerAddress`

With those six Wine-only exclusions, all 30 Windows test packages pass (exit 0).
All 30 Linux test packages pass without exclusions. A compiled Windows executable
was also started under Wine with the repository config; controller startup exited
1 with the expected message:

```text
hydrat is a Linux gateway; the controller/agent need WireGuard, nftables and a Linux netns: unsupported on windows
```

No existing test was removed. Test bodies and assertions are unchanged except for
the two database-close cleanups described above.
