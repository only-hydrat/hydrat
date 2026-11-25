//go:build linux && !android

package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/only-hydrat/hydrat/internal/xrayapi"
)

const (
	linuxTunnel       = "hydrat-app"
	linuxDNS          = "10.231.90.1"
	linuxRouteTable   = "28481"
	linuxRulePriority = 11893
)

type routingCommand func(context.Context, string, ...string) error

func invokeRouting(ctx context.Context, program string, args ...string) error {
	if output, err := exec.CommandContext(ctx, program, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w (%s)", program, err, output)
	}
	return nil
}

func installLinuxRouting(ctx context.Context, uid int, run routingCommand) (func() error, error) {
	if uid <= 0 {
		return nil, errors.New("the tunnel service needs a dedicated non-root UID with CAP_NET_ADMIN")
	}
	type operation struct {
		add []string
		del []string
	}
	uidRange := fmt.Sprintf("%d-%d", uid, uid)
	table := linuxRouteTable
	priority := fmt.Sprint(linuxRulePriority)
	operations := []operation{}
	for _, family := range []struct{ flag, address string }{
		{"-4", xrayapi.DeviceTunnelAddress + "/30"},
		{"-6", "fd24:6b91:e70d::2/126"},
	} {
		operations = append(operations, operation{
			[]string{family.flag, "address", "add", family.address, "dev", linuxTunnel},
			[]string{family.flag, "address", "del", family.address, "dev", linuxTunnel},
		})
	}
	for _, family := range []string{"-4", "-6"} {
		// If Xray exits, the kernel deletes its interface and device route.
		// Keep this fallback until the session explicitly restores routing.
		operations = append(operations, operation{
			[]string{family, "route", "add", "unreachable", "default", "table", table, "metric", "32760"},
			[]string{family, "route", "del", "unreachable", "default", "table", table, "metric", "32760"},
		})
	}
	for _, family := range []string{"-4", "-6"} {
		operations = append(operations, operation{
			[]string{family, "route", "add", "table", table, "default", "dev", linuxTunnel},
			[]string{family, "route", "del", "table", table, "default", "dev", linuxTunnel},
		})
	}
	for _, family := range []string{"-4", "-6"} {
		selector := []string{"priority", priority, "not", "uidrange", uidRange, "table", table}
		operations = append(operations, operation{
			append([]string{family, "rule", "add"}, selector...),
			append([]string{family, "rule", "del"}, selector...),
		})
	}
	var installed []operation
	var closeOnce sync.Once
	var cleanupErr error
	close := func() error {
		closeOnce.Do(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for i := len(installed) - 1; i >= 0; i-- {
				cleanupErr = errors.Join(cleanupErr, run(cleanup, "ip", installed[i].del...))
			}
		})
		return cleanupErr
	}
	for _, operation := range operations {
		if err := run(ctx, "ip", operation.add...); err != nil {
			return nil, errors.Join(err, close())
		}
		installed = append(installed, operation)
	}
	return close, nil
}

func checkLinuxRoutingAvailable(ctx context.Context) error {
	for _, family := range []string{"-4", "-6"} {
		for _, args := range [][]string{{"rule", "show"}, {"route", "show", "table", "all"}} {
			output, err := exec.CommandContext(ctx, "ip", append([]string{"-j", family}, args...)...).Output()
			if err != nil {
				return fmt.Errorf("inspect Linux routing: %w", err)
			}
			var entries []struct {
				Priority int
				Table    json.RawMessage
			}
			if err := json.Unmarshal(output, &entries); err != nil {
				return err
			}
			for _, entry := range entries {
				if (args[0] == "rule" && entry.Priority == linuxRulePriority) || strings.Trim(string(entry.Table), "\"") == linuxRouteTable {
					return errors.New("Linux routing table or rule priority reserved by Hydrat is already in use")
				}
			}
		}
	}
	return nil
}

// ConnectLinux connects through a dedicated service account. Its UID and the
// helper processes it owns keep the physical routes in the main routing table.
func (app *App) ConnectLinux(ctx context.Context, options ProcessOptions) (runErr error) {
	options.GeoRules = true
	return app.connectLinux(ctx, options, func(ctx context.Context, backend TunnelBackend) error {
		return app.Run(ctx, backend)
	})
}

// ConnectLinuxSingleDevice uses the same scheduler as the Android and Windows clients.
func (app *App) ConnectLinuxSingleDevice(ctx context.Context, options ProcessOptions, settings MobileSettings) error {
	settings = settings.Normalized()
	options.CriticalSlots = MobileCriticalSlots
	options.FastProbeWorkers = max(settings.FastWorkers, settings.BackgroundWorkers)
	options.MinVLESSScore = float64(settings.MinVLESSScore)
	return app.connectLinux(ctx, options, func(ctx context.Context, backend TunnelBackend) error {
		return app.RunMobileWithSettings(ctx, backend, settings, options.DNSResolvers...)
	})
}

func (app *App) connectLinux(ctx context.Context, options ProcessOptions, run func(context.Context, TunnelBackend) error) (runErr error) {
	uid := os.Geteuid()
	if uid == 0 {
		return errors.New("run the Linux VPN worker as a dedicated service user with CAP_NET_ADMIN")
	}
	options.AutomaticRoutes = false
	// Claim a table before any listening SOCKS sockets are started.
	if err := invokeRouting(ctx, "nft", "create", "table", "inet", "hydrat_app"); err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		runErr = errors.Join(runErr, invokeRouting(cleanup, "nft", "delete", "table", "inet", "hydrat_app"))
	}()
	if err := checkLinuxRoutingAvailable(ctx); err != nil {
		return err
	}
	criticalSlots := options.CriticalSlots
	if criticalSlots <= 0 {
		criticalSlots = defaultCriticalSlots
	}
	firewall := fmt.Sprintf(`
add chain inet hydrat_app output { type filter hook output priority -15; policy accept; }
add rule inet hydrat_app output meta skuid != %[1]d ip daddr 127.0.0.0/8 tcp dport {28180-28199, 28280-%[2]d, 28450-28451, 28550-28551} reject
add rule inet hydrat_app output meta skuid != %[1]d ip daddr 127.0.0.0/8 udp dport {28180-28199, 28280-%[2]d, 28450-28451, 28550-28551} reject
`, uid, criticalPort+criticalSlots-1)
	install := exec.CommandContext(ctx, "nft", "-f", "-")
	install.Stdin = strings.NewReader(firewall)
	if output, err := install.CombinedOutput(); err != nil {
		return fmt.Errorf("protect private probe sockets: %w (%s)", err, output)
	}

	// Keep the data-plane alive until its OS routes and DNS have been reverted.
	backend, err := StartProcesses(context.WithoutCancel(ctx), options)
	if err != nil {
		return err
	}
	defer func() { runErr = errors.Join(runErr, backend.Close()) }()
	cleanup, err := installLinuxRouting(ctx, uid, invokeRouting)
	if err != nil {
		return err
	}
	defer func() { runErr = errors.Join(runErr, cleanup()) }()

	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		runErr = errors.Join(runErr, invokeRouting(cleanup, "resolvectl", "revert", linuxTunnel))
	}()
	for _, args := range [][]string{
		{"dns", linuxTunnel, linuxDNS},
		{"domain", linuxTunnel, "~."},
		{"default-route", linuxTunnel, "true"},
	} {
		if err := invokeRouting(ctx, "resolvectl", args...); err != nil {
			return err
		}
	}

	session, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-session.Done():
		case <-backend.Done():
			cancel()
		}
	}()
	runErr = run(session, backend)
	if ctx.Err() == nil && session.Err() != nil {
		runErr = errors.Join(runErr, errors.New("serving Xray stopped"))
	}
	return runErr
}
