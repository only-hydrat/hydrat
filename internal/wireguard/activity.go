package wireguard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type PeerActivity struct {
	PublicKey       string    `json:"public_key"`
	Endpoint        string    `json:"endpoint,omitempty"`
	AllowedIPs      string    `json:"allowed_ips"`
	LatestHandshake time.Time `json:"latest_handshake,omitempty"`
	LastUserTraffic time.Time `json:"last_user_traffic,omitempty"`
	RXBytes         int64     `json:"rx_bytes"`
	TXBytes         int64     `json:"tx_bytes"`
}

type OutputRunner interface {
	Output(context.Context, string, ...string) ([]byte, error)
}

type Collector struct {
	Runner           OutputRunner
	Interface        string
	TrackUserTraffic bool
}

func (collector Collector) Snapshot(ctx context.Context) ([]PeerActivity, error) {
	if collector.Runner == nil {
		collector.Runner = ExecRunner{}
	}
	if collector.Interface == "" {
		collector.Interface = "wg0"
	}
	output, err := collector.Runner.Output(ctx, "wg", "show", collector.Interface, "dump")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) <= 1 {
		return []PeerActivity{}, nil
	}
	result := make([]PeerActivity, 0, len(lines)-1)
	for lineNumber, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) < 8 {
			return nil, fmt.Errorf("invalid wg dump peer line %d", lineNumber+2)
		}
		handshake, err := strconv.ParseInt(fields[4], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse handshake: %w", err)
		}
		rx, err := strconv.ParseInt(fields[5], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse receive bytes: %w", err)
		}
		tx, err := strconv.ParseInt(fields[6], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse transmit bytes: %w", err)
		}
		activity := PeerActivity{
			PublicKey: fields[0], Endpoint: normalizedOptional(fields[2]), AllowedIPs: fields[3],
			RXBytes: rx, TXBytes: tx,
		}
		if handshake > 0 {
			activity.LatestHandshake = time.Unix(handshake, 0)
		}
		result = append(result, activity)
	}
	if collector.TrackUserTraffic {
		at := time.Now()
		output, err := collector.Runner.Output(ctx, "nft", "-j", "list", "set", "inet", "hydrat", "client_activity")
		if err != nil {
			return nil, fmt.Errorf("read decrypted client activity: %w", err)
		}
		activity, err := parseUserTraffic(output, at)
		if err != nil {
			return nil, err
		}
		for index := range result {
			for _, allowed := range strings.Split(result[index].AllowedIPs, ",") {
				prefix, err := netip.ParsePrefix(strings.TrimSpace(allowed))
				if err == nil && prefix.IsSingleIP() && activity[prefix.Addr().String()].After(result[index].LastUserTraffic) {
					result[index].LastUserTraffic = activity[prefix.Addr().String()]
				}
			}
		}
	}
	return result, nil
}

func parseUserTraffic(output []byte, at time.Time) (map[string]time.Time, error) {
	var snapshot struct {
		NFTables []struct {
			Set *struct {
				Family string `json:"family"`
				Table  string `json:"table"`
				Name   string `json:"name"`
				Elems  []struct {
					Elem struct {
						Val     string `json:"val"`
						Expires *int64 `json:"expires"`
					} `json:"elem"`
				} `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(output, &snapshot); err != nil {
		return nil, fmt.Errorf("invalid client activity snapshot")
	}
	for _, object := range snapshot.NFTables {
		set := object.Set
		if set == nil || set.Family != "inet" || set.Table != "hydrat" || set.Name != "client_activity" {
			continue
		}
		result := make(map[string]time.Time, len(set.Elems))
		for _, item := range set.Elems {
			address, err := netip.ParseAddr(item.Elem.Val)
			if err != nil || !address.Is4() || item.Elem.Expires == nil || *item.Elem.Expires < 0 || *item.Elem.Expires > 300 {
				return nil, fmt.Errorf("invalid client activity element")
			}
			// nft JSON expiration is in seconds; do not refresh presence at
			// collection time or idle devices would remain online twice as long.
			result[address.String()] = at.Add(-time.Duration(300-*item.Elem.Expires) * time.Second)
		}
		return result, nil
	}
	return nil, fmt.Errorf("client activity set is missing")
}

func normalizedOptional(value string) string {
	if value == "(none)" || value == "off" {
		return ""
	}
	return value
}

type ExecRunner struct{}

func (ExecRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return output, nil
}
