package config

import (
	"errors"
	"fmt"
	"time"

	"go.yaml.in/yaml/v3"
)

func (q *QoEConfig) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return errors.New("qoe must be a mapping")
	}
	allowed := map[string]bool{
		"enabled": true, "active_interval": true, "idle_interval": true,
		"degraded_interval": true, "deadline": true, "workers": true,
		"standby_candidates": true, "sample_bytes": true, "window_size": true,
		"bad_samples": true, "recovery_good_samples": true,
		"availability_window": true, "availability_failures": true,
		"initial_ttfb_limit": true, "ttfb_floor": true, "ttfb_multiplier": true,
		"initial_throughput_mbps": true, "throughput_ratio": true,
		"alternative_speedup": true, "retention": true,
	}
	for index := 0; index < len(node.Content); index += 2 {
		key := node.Content[index].Value
		if !allowed[key] {
			return fmt.Errorf("field %s not found in type config.QoEConfig", key)
		}
	}
	type rawQoE struct {
		Enabled               *bool    `yaml:"enabled"`
		ActiveInterval        *string  `yaml:"active_interval"`
		IdleInterval          *string  `yaml:"idle_interval"`
		DegradedInterval      *string  `yaml:"degraded_interval"`
		Deadline              *string  `yaml:"deadline"`
		Workers               *int     `yaml:"workers"`
		StandbyCandidates     *int     `yaml:"standby_candidates"`
		SampleBytes           *int64   `yaml:"sample_bytes"`
		WindowSize            *int     `yaml:"window_size"`
		BadSamples            *int     `yaml:"bad_samples"`
		RecoveryGoodSamples   *int     `yaml:"recovery_good_samples"`
		AvailabilityWindow    *int     `yaml:"availability_window"`
		AvailabilityFailures  *int     `yaml:"availability_failures"`
		InitialTTFBLimit      *string  `yaml:"initial_ttfb_limit"`
		TTFBFloor             *string  `yaml:"ttfb_floor"`
		TTFBMultiplier        *float64 `yaml:"ttfb_multiplier"`
		InitialThroughputMbps *float64 `yaml:"initial_throughput_mbps"`
		ThroughputRatio       *float64 `yaml:"throughput_ratio"`
		AlternativeSpeedup    *float64 `yaml:"alternative_speedup"`
		Retention             *string  `yaml:"retention"`
	}
	var raw rawQoE
	if err := node.Decode(&raw); err != nil {
		return err
	}
	if raw.Enabled != nil {
		q.Enabled = *raw.Enabled
	}
	if raw.Workers != nil {
		q.Workers = *raw.Workers
	}
	if raw.StandbyCandidates != nil {
		q.StandbyCandidates = *raw.StandbyCandidates
	}
	if raw.SampleBytes != nil {
		q.SampleBytes = *raw.SampleBytes
	}
	if raw.WindowSize != nil {
		q.WindowSize = *raw.WindowSize
	}
	if raw.BadSamples != nil {
		q.BadSamples = *raw.BadSamples
	}
	if raw.RecoveryGoodSamples != nil {
		q.RecoveryGoodSamples = *raw.RecoveryGoodSamples
	}
	if raw.AvailabilityWindow != nil {
		q.AvailabilityWindow = *raw.AvailabilityWindow
	}
	if raw.AvailabilityFailures != nil {
		q.AvailabilityFailures = *raw.AvailabilityFailures
	}
	if raw.TTFBMultiplier != nil {
		q.TTFBMultiplier = *raw.TTFBMultiplier
	}
	if raw.InitialThroughputMbps != nil {
		q.InitialThroughputMbps = *raw.InitialThroughputMbps
	}
	if raw.ThroughputRatio != nil {
		q.ThroughputRatio = *raw.ThroughputRatio
	}
	if raw.AlternativeSpeedup != nil {
		q.AlternativeSpeedup = *raw.AlternativeSpeedup
	}
	durations := []struct {
		name   string
		raw    *string
		target *time.Duration
	}{
		{name: "active_interval", raw: raw.ActiveInterval, target: &q.ActiveInterval},
		{name: "idle_interval", raw: raw.IdleInterval, target: &q.IdleInterval},
		{name: "degraded_interval", raw: raw.DegradedInterval, target: &q.DegradedInterval},
		{name: "deadline", raw: raw.Deadline, target: &q.Deadline},
		{name: "initial_ttfb_limit", raw: raw.InitialTTFBLimit, target: &q.InitialTTFBLimit},
		{name: "ttfb_floor", raw: raw.TTFBFloor, target: &q.TTFBFloor},
		{name: "retention", raw: raw.Retention, target: &q.Retention},
	}
	for _, item := range durations {
		if item.raw == nil {
			continue
		}
		duration, err := time.ParseDuration(*item.raw)
		if err != nil {
			return fmt.Errorf("%s: %w", item.name, err)
		}
		*item.target = duration
	}
	return nil
}

func (p *ProbesConfig) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return errors.New("probes must be a mapping")
	}
	allowed := map[string]bool{
		"fast_workers": true, "full_workers": true, "active_workers": true,
		"active_route_limit": true, "active_overlap": true,
		"fast_deadline": true, "full_deadline": true,
		"tor_fast_deadline": true, "tor_full_deadline": true,
		"active_interval": true, "active_deadline": true,
		"active_response_slack": true, "active_proof_grace": true,
		"gate_endpoints": true, "custom_gates": true,
	}
	for index := 0; index < len(node.Content); index += 2 {
		key := node.Content[index].Value
		if !allowed[key] {
			return fmt.Errorf("field %s not found in type config.ProbesConfig", key)
		}
	}
	type rawProbes struct {
		FastWorkers         *int                 `yaml:"fast_workers"`
		FullWorkers         *int                 `yaml:"full_workers"`
		ActiveWorkers       *int                 `yaml:"active_workers"`
		ActiveRouteLimit    *int                 `yaml:"active_route_limit"`
		ActiveOverlap       *int                 `yaml:"active_overlap"`
		FastDeadline        *string              `yaml:"fast_deadline"`
		FullDeadline        *string              `yaml:"full_deadline"`
		TorFastDeadline     *string              `yaml:"tor_fast_deadline"`
		TorFullDeadline     *string              `yaml:"tor_full_deadline"`
		ActiveInterval      *string              `yaml:"active_interval"`
		ActiveDeadline      *string              `yaml:"active_deadline"`
		ActiveResponseSlack *string              `yaml:"active_response_slack"`
		ActiveProofGrace    *string              `yaml:"active_proof_grace"`
		GateEndpoints       *GateEndpointsConfig `yaml:"gate_endpoints"`
		CustomGates         []CustomGateConfig   `yaml:"custom_gates"`
	}
	raw := rawProbes{
		GateEndpoints: &p.GateEndpoints,
		CustomGates:   p.CustomGates,
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	if raw.FastWorkers != nil {
		p.FastWorkers = *raw.FastWorkers
	}
	if raw.FullWorkers != nil {
		p.FullWorkers = *raw.FullWorkers
	}
	if raw.ActiveWorkers != nil {
		p.ActiveWorkers = *raw.ActiveWorkers
	}
	if raw.ActiveRouteLimit != nil {
		p.ActiveRouteLimit = *raw.ActiveRouteLimit
	}
	if raw.ActiveOverlap != nil {
		p.ActiveOverlap = *raw.ActiveOverlap
	}
	if raw.FastDeadline != nil {
		duration, err := time.ParseDuration(*raw.FastDeadline)
		if err != nil {
			return fmt.Errorf("fast_deadline: %w", err)
		}
		p.FastDeadline = duration
	}
	if raw.FullDeadline != nil {
		duration, err := time.ParseDuration(*raw.FullDeadline)
		if err != nil {
			return fmt.Errorf("full_deadline: %w", err)
		}
		p.FullDeadline = duration
	}
	if raw.TorFastDeadline != nil {
		duration, err := time.ParseDuration(*raw.TorFastDeadline)
		if err != nil {
			return fmt.Errorf("tor_fast_deadline: %w", err)
		}
		p.TorFastDeadline = duration
	}
	if raw.TorFullDeadline != nil {
		duration, err := time.ParseDuration(*raw.TorFullDeadline)
		if err != nil {
			return fmt.Errorf("tor_full_deadline: %w", err)
		}
		p.TorFullDeadline = duration
	}
	if raw.ActiveInterval != nil {
		duration, err := time.ParseDuration(*raw.ActiveInterval)
		if err != nil {
			return fmt.Errorf("active_interval: %w", err)
		}
		p.ActiveInterval = duration
	}
	if raw.ActiveDeadline != nil {
		duration, err := time.ParseDuration(*raw.ActiveDeadline)
		if err != nil {
			return fmt.Errorf("active_deadline: %w", err)
		}
		p.ActiveDeadline = duration
	}
	if raw.ActiveResponseSlack != nil {
		duration, err := time.ParseDuration(*raw.ActiveResponseSlack)
		if err != nil {
			return fmt.Errorf("active_response_slack: %w", err)
		}
		p.ActiveResponseSlack = duration
	}
	if raw.ActiveProofGrace != nil {
		duration, err := time.ParseDuration(*raw.ActiveProofGrace)
		if err != nil {
			return fmt.Errorf("active_proof_grace: %w", err)
		}
		p.ActiveProofGrace = duration
	}
	if raw.GateEndpoints != nil {
		p.GateEndpoints = *raw.GateEndpoints
	}
	if raw.CustomGates != nil {
		p.CustomGates = raw.CustomGates
	}
	return nil
}

func (c *ControllerConfig) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return errors.New("controller must be a mapping")
	}
	allowed := map[string]bool{
		"cycle_seconds": true, "source_refresh_seconds": true,
		"probe_seconds": true, "hard_failover_budget": true,
		"placement_preempt_timeout": true,
	}
	for index := 0; index < len(node.Content); index += 2 {
		key := node.Content[index].Value
		if !allowed[key] {
			return fmt.Errorf("field %s not found in type config.ControllerConfig", key)
		}
	}
	type rawController struct {
		CycleSeconds            *int    `yaml:"cycle_seconds"`
		SourceRefreshSeconds    *int    `yaml:"source_refresh_seconds"`
		ProbeSeconds            *int    `yaml:"probe_seconds"`
		HardFailoverBudget      *string `yaml:"hard_failover_budget"`
		PlacementPreemptTimeout *string `yaml:"placement_preempt_timeout"`
	}
	var raw rawController
	if err := node.Decode(&raw); err != nil {
		return err
	}
	if raw.CycleSeconds != nil {
		c.CycleSeconds = *raw.CycleSeconds
	}
	if raw.SourceRefreshSeconds != nil {
		c.SourceRefreshSeconds = *raw.SourceRefreshSeconds
	}
	if raw.ProbeSeconds != nil {
		c.ProbeSeconds = *raw.ProbeSeconds
	}
	for _, item := range []struct {
		name   string
		raw    *string
		target *time.Duration
	}{
		{name: "hard_failover_budget", raw: raw.HardFailoverBudget, target: &c.HardFailoverBudget},
		{name: "placement_preempt_timeout", raw: raw.PlacementPreemptTimeout, target: &c.PlacementPreemptTimeout},
	} {
		if item.raw == nil {
			continue
		}
		duration, err := time.ParseDuration(*item.raw)
		if err != nil {
			return fmt.Errorf("%s: %w", item.name, err)
		}
		*item.target = duration
	}
	return nil
}

func (t *TournamentConfig) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return errors.New("tournament must be a mapping")
	}
	for index := 0; index < len(node.Content); index += 2 {
		switch node.Content[index].Value {
		case "reset_window", "promotion_ratio":
		default:
			return fmt.Errorf("field %s not found in type config.TournamentConfig", node.Content[index].Value)
		}
	}
	type rawTournament struct {
		ResetWindow    *string  `yaml:"reset_window"`
		PromotionRatio *float64 `yaml:"promotion_ratio"`
	}
	var raw rawTournament
	if err := node.Decode(&raw); err != nil {
		return err
	}
	if raw.ResetWindow != nil {
		duration, err := time.ParseDuration(*raw.ResetWindow)
		if err != nil {
			return fmt.Errorf("reset_window: %w", err)
		}
		t.ResetWindow = duration
	}
	if raw.PromotionRatio != nil {
		t.PromotionRatio = *raw.PromotionRatio
	}
	return nil
}

func (r *RoutingConfig) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return errors.New("routing must be a mapping")
	}
	allowed := map[string]bool{
		"fail_policy": true, "direct_suffixes": true,
		"direct_domains": true, "disallow_ru_egress": true, "geo_rules": true,
	}
	for index := 0; index < len(node.Content); index += 2 {
		key := node.Content[index].Value
		if !allowed[key] {
			return fmt.Errorf("field %s not found in type config.RoutingConfig", key)
		}
	}
	type rawRouting struct {
		FailPolicy       *FailPolicy     `yaml:"fail_policy"`
		DirectSuffixes   []string        `yaml:"direct_suffixes"`
		DirectDomains    []string        `yaml:"direct_domains"`
		DisallowRUEgress *bool           `yaml:"disallow_ru_egress"`
		GeoRules         *GeoRulesConfig `yaml:"geo_rules"`
	}
	raw := rawRouting{
		GeoRules: &r.GeoRules,
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	if raw.FailPolicy != nil {
		r.FailPolicy = *raw.FailPolicy
	}
	if raw.DirectSuffixes != nil {
		r.DirectSuffixes = raw.DirectSuffixes
	}
	if raw.DirectDomains != nil {
		r.DirectDomains = raw.DirectDomains
	}
	if raw.DisallowRUEgress != nil {
		r.DisallowRUEgress = *raw.DisallowRUEgress
	}
	if raw.GeoRules != nil {
		r.GeoRules = *raw.GeoRules
	}
	return nil
}

func (g *GeoRulesConfig) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return errors.New("geo_rules must be a mapping")
	}
	allowed := map[string]bool{
		"enabled": true, "auto_update": true,
		"geoip_url": true, "geosite_url": true,
		"update_interval": true,
	}
	for index := 0; index < len(node.Content); index += 2 {
		key := node.Content[index].Value
		if !allowed[key] {
			return fmt.Errorf("field %s not found in type config.GeoRulesConfig", key)
		}
	}
	type rawGeoRules struct {
		Enabled        *bool   `yaml:"enabled"`
		AutoUpdate     *bool   `yaml:"auto_update"`
		GeoIPURL       *string `yaml:"geoip_url"`
		GeoSiteURL     *string `yaml:"geosite_url"`
		UpdateInterval *string `yaml:"update_interval"`
	}
	var raw rawGeoRules
	if err := node.Decode(&raw); err != nil {
		return err
	}
	if raw.Enabled != nil {
		g.Enabled = *raw.Enabled
	}
	if raw.AutoUpdate != nil {
		g.AutoUpdate = *raw.AutoUpdate
	}
	if raw.GeoIPURL != nil {
		g.GeoIPURL = *raw.GeoIPURL
	}
	if raw.GeoSiteURL != nil {
		g.GeoSiteURL = *raw.GeoSiteURL
	}
	if raw.UpdateInterval != nil {
		duration, err := time.ParseDuration(*raw.UpdateInterval)
		if err != nil {
			return fmt.Errorf("update_interval: %w", err)
		}
		g.UpdateInterval = duration
	}
	return nil
}

func (g *GateEndpointsConfig) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return errors.New("gate_endpoints must be a mapping")
	}
	allowed := map[string]bool{
		"youtube": true, "chatgpt": true, "openai": true, "telegram": true, "instagram": true,
	}
	for index := 0; index < len(node.Content); index += 2 {
		key := node.Content[index].Value
		if !allowed[key] {
			return fmt.Errorf("field %s not found in type config.GateEndpointsConfig", key)
		}
	}
	type rawGateEndpoints struct {
		YouTube  *string `yaml:"youtube"`
		ChatGPT  *string `yaml:"chatgpt"`
		OpenAI   *string `yaml:"openai"`
		Telegram  *string `yaml:"telegram"`
		Instagram *string `yaml:"instagram"`
	}
	var raw rawGateEndpoints
	if err := node.Decode(&raw); err != nil {
		return err
	}
	if raw.YouTube != nil {
		g.YouTube = *raw.YouTube
	}
	if raw.ChatGPT != nil {
		g.ChatGPT = *raw.ChatGPT
	}
	if raw.OpenAI != nil {
		g.OpenAI = *raw.OpenAI
	}
	if raw.Telegram != nil {
		g.Telegram = *raw.Telegram
	}
	if raw.Instagram != nil {
		g.Instagram = *raw.Instagram
	}
	return nil
}

func (c *CustomGateConfig) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return errors.New("custom_gate must be a mapping")
	}
	allowed := map[string]bool{
		"name": true, "url": true, "acceptable_statuses": true,
	}
	for index := 0; index < len(node.Content); index += 2 {
		key := node.Content[index].Value
		if !allowed[key] {
			return fmt.Errorf("field %s not found in type config.CustomGateConfig", key)
		}
	}
	type rawCustomGate struct {
		Name               *string `yaml:"name"`
		URL                *string `yaml:"url"`
		AcceptableStatuses []int   `yaml:"acceptable_statuses"`
	}
	var raw rawCustomGate
	if err := node.Decode(&raw); err != nil {
		return err
	}
	if raw.Name != nil {
		c.Name = *raw.Name
	}
	if raw.URL != nil {
		c.URL = *raw.URL
	}
	if raw.AcceptableStatuses != nil {
		c.AcceptableStatuses = raw.AcceptableStatuses
	}
	return nil
}
