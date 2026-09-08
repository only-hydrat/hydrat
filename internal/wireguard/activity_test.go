package wireguard

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCollectorParsesWireGuardDumpWithoutChangingInterface(t *testing.T) {
	dump := "server-private\tserver-public\t51820\toff\n" +
		"peer-a\t(none)\t198.51.100.1:50000\t10.44.0.2/32\t1800000000\t1234\t5678\t25\n" +
		"peer-b\t(none)\t(none)\t10.44.0.3/32\t0\t0\t0\toff\n"
	runner := &wgRunner{output: dump}
	peers, err := (Collector{Runner: runner, Interface: "wg0"}).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 || peers[0].PublicKey != "peer-a" || peers[0].RXBytes != 1234 || !peers[0].LatestHandshake.Equal(time.Unix(1_800_000_000, 0)) {
		t.Fatalf("peers=%+v", peers)
	}
	if strings.Join(runner.args, " ") != "show wg0 dump" {
		t.Fatalf("unexpected wg command args=%v", runner.args)
	}
}

type wgRunner struct {
	output string
	args   []string
}

func (runner *wgRunner) Output(_ context.Context, _ string, args ...string) ([]byte, error) {
	runner.args = append([]string(nil), args...)
	return []byte(runner.output), nil
}
