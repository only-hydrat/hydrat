package device

import (
	"context"
	"strings"
	"time"
	"unicode"

	"github.com/only-hydrat/hydrat/internal/sources"
	"github.com/only-hydrat/hydrat/internal/store"
)

type Status struct {
	Running          bool
	Connected        bool
	Recovering       bool
	Sources          int
	Candidates       int
	Checked          int
	Qualified        int
	Saved            int
	Search           SearchStatus
	SearchingSeconds int64
	TCP              bool
	UDP              bool
	TCPReserve       bool
	UDPReserve       bool
	TCPReserveStatus string
	UDPReserveStatus string
	Nodes            []NodeStatus
	Inventory        []SourceStatus
}

type NodeStatus struct {
	Role           string
	Label          string
	Source         string
	Protocol       string
	State          string
	LatencyMS      float64
	ThroughputMbps float64
	Score          float64
	MeasuredAt     int64
}

type SourceStatus struct {
	ID         string
	Label      string
	Kind       string
	Enabled    bool
	Failed     bool
	Candidates int
	UpdatedAt  int64
	CustomHWID bool
}

func (app *App) Status(ctx context.Context) (Status, error) {
	status := Status{Running: app.running.Load()}
	sourceRows, err := app.database.ListSources(ctx)
	if err != nil {
		return status, err
	}
	labels := make(map[string]string, len(sourceRows))
	for _, source := range sourceRows {
		label := statusLabel(source.Label)
		labels[source.ID] = label
		if source.PendingDelete {
			continue
		}
		details := SourceStatus{
			ID: source.ID, Label: label, Kind: string(source.Kind), Enabled: source.Enabled && !source.PendingDelete,
			Failed: source.LastRefreshError != "", Candidates: source.CandidateCount, CustomHWID: source.CustomHWID,
		}
		if source.LastRefreshAt != nil {
			details.UpdatedAt = *source.LastRefreshAt
		}
		status.Inventory = append(status.Inventory, details)
	}
	candidateRows, err := app.database.ListCandidates(ctx, "")
	if err != nil {
		return status, err
	}
	status.Sources, status.Candidates = len(status.Inventory), len(candidateRows)
	route := app.route.Load()
	if !status.Running {
		return status, nil
	}
	var working map[string]bool
	if started := app.mobileStartedAt.Load(); started > 0 {
		if route == nil || route.BlockTCP && route.BlockUDP {
			status.SearchingSeconds = max(0, time.Now().Unix()-started)
		}
		if search := app.search.Load(); search != nil {
			status.Search = *search
		}
		states, err := app.database.ListCandidateProbeStates(ctx)
		if err != nil {
			return status, err
		}
		working = make(map[string]bool)
		current := make(map[string]bool, len(candidateRows))
		for _, candidate := range candidateRows {
			current[candidate.ID] = true
		}
		for _, state := range states {
			if !current[state.CandidateID] {
				continue
			}
			if !state.LastFastProbeAt.IsZero() || !state.LastFullProbeAt.IsZero() {
				status.Checked++
			}
			if state.Status == store.CandidateQualified && state.FullSuccessStreak >= 2 && !state.Stale {
				if state.InWorkingPool {
					status.Qualified++
					if !state.Draining {
						working[state.CandidateID] = true
					}
				} else {
					status.Saved++
				}
			}
		}
	}
	if route == nil {
		return status, nil
	}
	status.TCP = !route.BlockTCP && route.TCPOutbound != ""
	status.UDP = !route.BlockUDP && route.UDPOutbound != ""
	status.TCPReserve = route.TCPReserveOutbound != ""
	status.UDPReserve = route.UDPReserveOutbound != ""
	status.Connected = status.TCP || status.UDP
	candidates := make(map[string]store.Candidate, len(candidateRows))
	for _, candidate := range candidateRows {
		candidates[candidate.ID] = candidate
	}
	healthRows, err := app.database.ListCandidateHealth(ctx)
	if err != nil {
		return status, err
	}
	health := make(map[string]store.CandidateHealth, len(healthRows))
	for _, row := range healthRows {
		health[row.CandidateID] = row
	}
	if working != nil {
		status.TCPReserveStatus = reserveStatus(route.ClientID, route.TCPOutbound, status.TCPReserve, false, working, candidates, health)
		status.UDPReserveStatus = reserveStatus(route.ClientID, route.UDPOutbound, status.UDPReserve, true, working, candidates, health)
	}
	for _, selection := range []struct {
		role, outbound string
		selected       bool
	}{
		{"tcp", route.TCPOutbound, status.TCP},
		{"udp", route.UDPOutbound, status.UDP},
		{"tcp_reserve", route.TCPReserveOutbound, status.TCPReserve},
		{"udp_reserve", route.UDPReserveOutbound, status.UDPReserve},
	} {
		if !selection.selected {
			continue
		}
		id := sources.CandidateIDFromHandler(selection.outbound, route.ClientID)
		candidate := candidates[id]
		node := NodeStatus{
			Role: selection.role, Label: statusLabel(candidate.Label), Source: labels[candidate.SourceID],
			Protocol: string(candidate.Kind), State: "unknown",
		}
		if row, ok := health[id]; ok {
			node.State = "unavailable"
			if row.Available && !row.ActiveHardFailure {
				node.State = "available"
			} else if selection.role == "tcp" || selection.role == "udp" {
				status.Recovering = true
			}
			node.LatencyMS, node.ThroughputMbps, node.Score = row.LatencyMS, row.ThroughputMbps, row.Score
			node.MeasuredAt = row.UpdatedAt.Unix()
		}
		status.Nodes = append(status.Nodes, node)
	}
	return status, nil
}

func reserveStatus(client, outbound string, assigned, udp bool, working map[string]bool, candidates map[string]store.Candidate, health map[string]store.CandidateHealth) string {
	if assigned {
		return "assigned"
	}
	if outbound == "" {
		return "no_primary"
	}
	primaryID := sources.CandidateIDFromHandler(outbound, client)
	primary := candidates[primaryID]
	for id := range working {
		candidate, h := candidates[id], health[id]
		if id == primaryID || (primary.RouteKey != "" && primary.RouteKey == candidate.RouteKey) ||
			!h.Available || h.ActiveHardFailure || !h.TCPQualified {
			continue
		}
		if !udp || (candidate.Kind == sources.KindVLESS && h.UDPQualified) {
			return "checking"
		}
	}
	return "missing"
}

// Names are display metadata. Never pass a pasted endpoint or a URL in a
// provider-supplied label through the app status interface.
func statusLabel(label string) string {
	if strings.Contains(label, "://") || strings.Contains(label, "@") {
		return ""
	}
	var clean strings.Builder
	for _, r := range label {
		if clean.Len() >= 128 {
			break
		}
		if !unicode.IsControl(r) && !unicode.Is(unicode.Cf, r) {
			clean.WriteRune(r)
		}
	}
	return strings.TrimSpace(clean.String())
}
