package metrics

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/only-hydrat/hydrat/internal/store"
)

// Handler exports persisted WireGuard client counters in Prometheus text format.
func Handler(database *store.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		clients, err := database.ListClients(r.Context())
		if err != nil {
			http.Error(w, "could not read client metrics", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprintln(w, "# HELP hydrat_wireguard_client_receive_bytes_total Total bytes received by the WireGuard server from a client.")
		fmt.Fprintln(w, "# TYPE hydrat_wireguard_client_receive_bytes_total counter")
		fmt.Fprintln(w, "# HELP hydrat_wireguard_client_transmit_bytes_total Total bytes sent by the WireGuard server to a client.")
		fmt.Fprintln(w, "# TYPE hydrat_wireguard_client_transmit_bytes_total counter")
		fmt.Fprintln(w, "# HELP hydrat_wireguard_client_receive_bytes Current WireGuard receive counter.")
		fmt.Fprintln(w, "# TYPE hydrat_wireguard_client_receive_bytes gauge")
		fmt.Fprintln(w, "# HELP hydrat_wireguard_client_transmit_bytes Current WireGuard transmit counter.")
		fmt.Fprintln(w, "# TYPE hydrat_wireguard_client_transmit_bytes gauge")
		fmt.Fprintln(w, "# HELP hydrat_wireguard_client_connected Whether client has recent decrypted traffic (1/0).")
		fmt.Fprintln(w, "# TYPE hydrat_wireguard_client_connected gauge")
		for _, c := range clients {
			labels := fmt.Sprintf(`client_name="%s",public_key="%s"`, escape(c.Name), escape(c.PublicKey))
			fmt.Fprintf(w, "hydrat_wireguard_client_receive_bytes_total{%s} %d\n", labels, c.RXBytesTotal)
			fmt.Fprintf(w, "hydrat_wireguard_client_transmit_bytes_total{%s} %d\n", labels, c.TXBytesTotal)
			fmt.Fprintf(w, "hydrat_wireguard_client_receive_bytes{%s} %d\n", labels, c.RXBytes)
			fmt.Fprintf(w, "hydrat_wireguard_client_transmit_bytes{%s} %d\n", labels, c.TXBytes)
			connected := 0
			if c.LastTrafficAt != nil && time.Now().Unix()-*c.LastTrafficAt < int64(store.ClientInactiveAfter.Seconds()) {
				connected = 1
			}
			fmt.Fprintf(w, "hydrat_wireguard_client_connected{%s} %s\n", labels, strconv.Itoa(connected))
		}
	})
}
func escape(v string) string { return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(v) }
