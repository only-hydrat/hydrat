package wireguard

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestCollectorUsesDecryptedTrafficExpiryRatherThanHandshakeBytes(t *testing.T) {
	runner := &activityRunner{}
	before := time.Now().Add(-121 * time.Second)
	peers, err := (Collector{Runner: runner, Interface: "wg0", TrackUserTraffic: true}).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || peers[0].LastUserTraffic.Before(before) || peers[0].LastUserTraffic.After(time.Now().Add(-119*time.Second)) {
		t.Fatalf("set expiry did not preserve actual activity time: %+v", peers)
	}
	runner.empty = true
	peers, err = (Collector{Runner: runner, TrackUserTraffic: true}).Snapshot(context.Background())
	if err != nil || len(peers) != 1 || !peers[0].LastUserTraffic.IsZero() {
		t.Fatalf("handshake/keepalive resurrected expired activity: %+v %v", peers, err)
	}
}

func TestUserTrafficRejectsMissingOrMalformedEvidence(t *testing.T) {
	for _, input := range []string{
		`{`, `{"nftables":[]}`,
		`{"nftables":[{"set":{"family":"inet","table":"hydrat","name":"client_activity","elem":[{"elem":{"val":"10.44.0.2"}}]}}]}`,
		`{"nftables":[{"set":{"family":"inet","table":"hydrat","name":"client_activity","elem":[{"elem":{"val":"10.44.0.2","expires":300000}}]}}]}`,
	} {
		if _, err := parseUserTraffic([]byte(input), time.Now()); err == nil {
			t.Errorf("invalid activity evidence accepted: %s", input)
		}
	}
}

type activityRunner struct{ empty bool }

func (runner *activityRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	if name == "wg" {
		return []byte("private\tpublic\t51820\toff\npeer\t(none)\t(none)\t10.44.0.2/32\t1800000000\t148\t92\t25\n"), nil
	}
	if name != "nft" || strings.Join(args, " ") != "-j list set inet hydrat client_activity" {
		return nil, fmt.Errorf("unexpected activity command")
	}
	elements := `[{"elem":{"val":"10.44.0.2","expires":180}}]`
	if runner.empty {
		elements = "[]"
	}
	return []byte(`{"nftables":[{"set":{"family":"inet","table":"hydrat","name":"client_activity","elem":` + elements + `}}]}`), nil
}

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
