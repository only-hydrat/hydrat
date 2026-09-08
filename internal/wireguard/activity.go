package wireguard

import (
	"context"
	"fmt"
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
	RXBytes         int64     `json:"rx_bytes"`
	TXBytes         int64     `json:"tx_bytes"`
}

type OutputRunner interface {
	Output(context.Context, string, ...string) ([]byte, error)
}

type Collector struct {
	Runner    OutputRunner
	Interface string
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
	return result, nil
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
