package store

import (
	"context"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/wireguard"
)

func TestPeerActivityDoesNotReviveOnServerTXOrKeepalive(t *testing.T) {
	db, _ := qoeCandidateStore(t)
	ctx := context.Background()
	if err := db.PutClient(ctx, ClientRecord{ID: "alice", Name: "Alice", Address: "10.44.0.2/32"}, "config"); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	for i, peer := range []wireguard.PeerActivity{{}, {TXBytes: 1000}, {TXBytes: 1000, RXBytes: 16}, {TXBytes: 1000, RXBytes: 164, LatestHandshake: now}} {
		if err := db.RecordPeerActivity(ctx, "alice", now.Add(time.Duration(i)*time.Second), peer); err != nil {
			t.Fatal(err)
		}
	}
	clients, _ := db.ListClients(ctx)
	if clients[0].LastTrafficAt != nil {
		t.Fatal("outgoing traffic/keepalive incorrectly marked client online")
	}
	if err := db.RecordPeerActivity(ctx, "alice", now.Add(3*time.Second), wireguard.PeerActivity{RXBytes: 200, TXBytes: 1000, LatestHandshake: now, LastUserTraffic: now.Add(3 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	clients, _ = db.ListClients(ctx)
	if !clients[0].RouteReserved(now.Add(4 * time.Second)) {
		t.Fatal("incoming data did not acquire reservation")
	}
	if clients[0].RouteReserved(now.Add(6 * time.Minute)) {
		t.Fatal("idle client retains reservation")
	}
	if clients[0].LatestHandshake == nil || *clients[0].LatestHandshake != now.Unix() {
		t.Fatal("handshake not persisted")
	}
	if err := db.RecordPeerActivity(ctx, "alice", now.Add(6*time.Minute), wireguard.PeerActivity{RXBytes: 200, TXBytes: 2000, LastUserTraffic: now.Add(3 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	clients, _ = db.ListClients(ctx)
	if clients[0].RouteReserved(now.Add(6 * time.Minute)) {
		t.Fatal("server output resurrected idle client")
	}
}
