// Package xraycore hosts the pinned, patched Xray inside Hydrat App.
package xraycore

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	handler "github.com/xtls/xray-core/app/proxyman/command"
	router "github.com/xtls/xray-core/app/router/command"
	stats "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	config "github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var errPrivateAPI = errors.New("embedded Xray control requires a private Unix socket")

type Host struct{}

func (Host) Start(ctx context.Context, path string) (io.Closer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	cfg, err := core.LoadConfig("json", file)
	if err != nil {
		return nil, err
	}
	instance, err := core.New(cfg)
	if err != nil {
		return nil, err
	}
	if err := instance.Start(); err != nil {
		return nil, errors.Join(err, instance.Close())
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, instance.Close())
	}
	return instance, nil
}

func privateAPI(endpoint string) (*grpc.ClientConn, error) {
	path, ok := strings.CutPrefix(endpoint, "unix://")
	if !ok || !filepath.IsAbs(path) {
		return nil, errPrivateAPI
	}
	return grpc.NewClient("passthrough:///hydrat-private",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}))
}

// Run implements the private subset of the Xray CLI used by Hydrat's
// reconciler. The caller's deadlines and cancellation reach the RPC.
func (Host) Run(ctx context.Context, input, _ string, args ...string) error {
	if len(args) < 3 || args[0] != "api" {
		return errors.New("invalid embedded Xray command")
	}
	op := args[1]
	var server, tag string
	timeout := 3 * time.Second
	for _, arg := range args[2:] {
		if addr, ok := strings.CutPrefix(arg, "--server="); ok {
			server = addr
			continue
		}
		if seconds, ok := strings.CutPrefix(arg, "--timeout="); ok {
			var err error
			timeout, err = time.ParseDuration(seconds + "s")
			if err != nil || timeout <= 0 {
				return errors.New("invalid embedded Xray deadline")
			}
			continue
		}
		tag = arg
	}
	conn, err := privateAPI(server)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if op == "rmo" {
		_, err := handler.NewHandlerServiceClient(conn).RemoveOutbound(ctx, &handler.RemoveOutboundRequest{Tag: tag})
		return err
	}
	cfg, err := config.DecodeJSONConfig(strings.NewReader(input))
	if err != nil {
		return err
	}
	switch op {
	case "ado":
		if len(cfg.OutboundConfigs) != 1 {
			return errors.New("embedded Xray requires one outbound")
		}
		outbound, err := cfg.OutboundConfigs[0].Build()
		if err != nil {
			return err
		}
		_, err = handler.NewHandlerServiceClient(conn).AddOutbound(ctx, &handler.AddOutboundRequest{Outbound: outbound})
		return err
	case "adrules":
		if cfg.RouterConfig == nil {
			return errors.New("embedded Xray requires a routing document")
		}
		rules, err := cfg.RouterConfig.Build()
		if err != nil {
			return err
		}
		_, err = router.NewRoutingServiceClient(conn).AddRule(ctx, &router.AddRuleRequest{Config: serial.ToTypedMessage(rules)})
		return err
	default:
		return errors.New("unsupported embedded Xray command")
	}
}

func (Host) Uplink(ctx context.Context, endpoint, pattern string) (int64, error) {
	conn, err := privateAPI(endpoint)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	reply, err := stats.NewStatsServiceClient(conn).QueryStats(ctx, &stats.QueryStatsRequest{Pattern: pattern})
	if err != nil || len(reply.GetStat()) != 1 {
		return 0, err
	}
	return reply.Stat[0].Value, nil
}
