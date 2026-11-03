package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// WireGuardRXBytes is the cumulative number of bytes received by each
	// WireGuard client, as reported by `wg show ... dump`.
	WireGuardRXBytes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "hydrat_wireguard_rx_bytes",
		Help: "Total received bytes for a WireGuard client",
	}, []string{"client", "public_key"})

	// WireGuardTXBytes is the cumulative number of bytes transmitted by each
	// WireGuard client, as reported by `wg show ... dump`.
	WireGuardTXBytes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "hydrat_wireguard_tx_bytes",
		Help: "Total transmitted bytes for a WireGuard client",
	}, []string{"client", "public_key"})
)
