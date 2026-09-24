package config

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/only-hydrat/hydrat/internal/dataplane"
	"github.com/only-hydrat/hydrat/internal/failoverbudget"
	"github.com/only-hydrat/hydrat/internal/probetimeout"
	"github.com/only-hydrat/hydrat/internal/qoe"
	"go.yaml.in/yaml/v3"
)

type FailPolicy string

const FailClosed FailPolicy = "closed"

type Config struct {
	Portal       PortalConfig       `yaml:"portal"`
	Inventory    InventoryConfig    `yaml:"inventory"`
	Tournament   TournamentConfig   `yaml:"tournament"`
	Probes       ProbesConfig       `yaml:"probes"`
	ProbeRuntime ProbeRuntimeConfig `yaml:"probe_runtime"`
	QoE          QoEConfig          `yaml:"qoe"`
	Tor          TorConfig          `yaml:"tor"`
	Routing      RoutingConfig      `yaml:"routing"`
	Paths        PathsConfig        `yaml:"paths"`
	Scheduler    SchedulerConfig    `yaml:"scheduler"`
	WireGuard    WireGuardConfig    `yaml:"wireguard"`
	Xray         XrayConfig         `yaml:"xray"`
	Controller   ControllerConfig   `yaml:"controller"`
}

type PortalConfig struct {
	Bind              string `yaml:"bind"`
	GatewayBind       string `yaml:"gateway_bind"`
	ControllerURL     string `yaml:"controller_url"`
	InternalTokenPath string `yaml:"internal_token_path"`
	AdminPassword     string `yaml:"admin_password"`
}

type InventoryConfig struct {
	MaxCandidates    int           `yaml:"max_candidates"`
	WorkingPoolSize  int           `yaml:"working_pool_size"`
	RetirementGrace  time.Duration `yaml:"retirement_grace"`
	RetiredRetention time.Duration `yaml:"retired_retention"`
	HWID             string        `yaml:"hwid,omitempty"`
}

type CustomGateConfig struct {
	Name               string `yaml:"name"`
	URL                string `yaml:"url"`
	AcceptableStatuses []int  `yaml:"acceptable_statuses,omitempty"`
}

type GateEndpointsConfig struct {
	YouTube   string `yaml:"youtube"`
	ChatGPT   string `yaml:"chatgpt"`
	OpenAI    string `yaml:"openai"`
	Telegram  string `yaml:"telegram"`
	Instagram string `yaml:"instagram"`
}

type ProbesConfig struct {
	FastWorkers         int
	FullWorkers         int
	ActiveWorkers       int
	ActiveRouteLimit    int
	ActiveOverlap       int
	FastDeadline        time.Duration
	FullDeadline        time.Duration
	TorFastDeadline     time.Duration
	TorFullDeadline     time.Duration
	ActiveInterval      time.Duration
	ActiveDeadline      time.Duration
	ActiveResponseSlack time.Duration
	ActiveProofGrace    time.Duration
	GateEndpoints       GateEndpointsConfig `yaml:"gate_endpoints"`
	CustomGates         []CustomGateConfig  `yaml:"custom_gates"`
}

type ProbeRuntimeConfig struct {
	MaxProbes        uint64        `yaml:"max_probes"`
	MaxRSSMiB        int64         `yaml:"max_rss_mib"`
	MaxFDs           int           `yaml:"max_fds"`
	DrainTimeout     time.Duration `yaml:"drain_timeout"`
	StopTimeout      time.Duration `yaml:"stop_timeout"`
	ReadinessTimeout time.Duration `yaml:"readiness_timeout"`
	CleanupTimeout   time.Duration `yaml:"cleanup_timeout"`
}

type QoEConfig struct {
	Enabled               bool          `yaml:"enabled"`
	ActiveInterval        time.Duration `yaml:"active_interval"`
	IdleInterval          time.Duration `yaml:"idle_interval"`
	DegradedInterval      time.Duration `yaml:"degraded_interval"`
	Deadline              time.Duration `yaml:"deadline"`
	Workers               int           `yaml:"workers"`
	StandbyCandidates     int           `yaml:"standby_candidates"`
	SampleBytes           int64         `yaml:"sample_bytes"`
	WindowSize            int           `yaml:"window_size"`
	BadSamples            int           `yaml:"bad_samples"`
	RecoveryGoodSamples   int           `yaml:"recovery_good_samples"`
	AvailabilityWindow    int           `yaml:"availability_window"`
	AvailabilityFailures  int           `yaml:"availability_failures"`
	InitialTTFBLimit      time.Duration `yaml:"initial_ttfb_limit"`
	TTFBFloor             time.Duration `yaml:"ttfb_floor"`
	TTFBMultiplier        float64       `yaml:"ttfb_multiplier"`
	InitialThroughputMbps float64       `yaml:"initial_throughput_mbps"`
	ThroughputRatio       float64       `yaml:"throughput_ratio"`
	AlternativeSpeedup    float64       `yaml:"alternative_speedup"`
	Retention             time.Duration `yaml:"retention"`
}

type TournamentConfig struct {
	ResetWindow    time.Duration
	PromotionRatio float64 `yaml:"promotion_ratio"`
}

type TorConfig struct {
	WarmProfiles       int    `yaml:"warm_profiles"`
	ExplorerProfiles   int    `yaml:"explorer_profiles"`
	Binary             string `yaml:"binary"`
	LyrebirdBinary     string `yaml:"lyrebird_binary"`
	DataDir            string `yaml:"data_dir"`
	SocksPortBase      int    `yaml:"socks_port_base"`
	ProbeDataDir       string `yaml:"probe_data_dir"`
	ProbeSocksPortBase int    `yaml:"probe_socks_port_base"`
}

type WireGuardConfig struct {
	Interface  string `yaml:"interface"`
	Config     string `yaml:"config"`
	Endpoint   string `yaml:"endpoint"`
	Network    string `yaml:"network"`
	ListenPort int    `yaml:"listen_port"`
	DNS        string `yaml:"dns"`
	MTU        int    `yaml:"mtu"`
}

type XrayConfig struct {
	Binary              string   `yaml:"binary"`
	APIAddress          string   `yaml:"api_address"`
	ProbeAPIAddress     string   `yaml:"probe_api_address"`
	ProbeSocksPortBase  int      `yaml:"probe_socks_port_base"`
	ActiveAPIAddress    string   `yaml:"active_api_address"`
	ActiveSocksPortBase int      `yaml:"active_socks_port_base"`
	DNSResolver         string   `yaml:"dns_resolver"`
	DNSResolvers        []string `yaml:"dns_resolvers"`
	MainConfig          string   `yaml:"main_config"`
	ProbeConfig         string   `yaml:"probe_config"`
	ActiveConfig        string   `yaml:"active_config"`
}

func (config XrayConfig) EffectiveDNSResolvers() []string {
	if len(config.DNSResolvers) > 0 {
		return append([]string(nil), config.DNSResolvers...)
	}
	if config.DNSResolver == "" {
		return nil
	}
	return []string{config.DNSResolver}
}

type ControllerConfig struct {
	CycleSeconds            int           `yaml:"cycle_seconds"`
	SourceRefreshSeconds    int           `yaml:"source_refresh_seconds"`
	ProbeSeconds            int           `yaml:"probe_seconds"`
	HardFailoverBudget      time.Duration `yaml:"hard_failover_budget"`
	PlacementPreemptTimeout time.Duration `yaml:"placement_preempt_timeout"`
}

type GeoRulesConfig struct {
	Enabled        bool          `yaml:"enabled"`
	AutoUpdate     bool          `yaml:"auto_update"`
	GeoIPURL       string        `yaml:"geoip_url"`
	GeoSiteURL     string        `yaml:"geosite_url"`
	UpdateInterval time.Duration `yaml:"update_interval"`
}

type RoutingConfig struct {
	FailPolicy       FailPolicy     `yaml:"fail_policy"`
	DirectSuffixes   []string       `yaml:"direct_suffixes"`
	DirectDomains    []string       `yaml:"direct_domains"`
	DisallowRUEgress bool           `yaml:"disallow_ru_egress"`
	GeoRules         GeoRulesConfig `yaml:"geo_rules"`
}

type PathsConfig struct {
	Database    string `yaml:"database"`
	MasterKey   string `yaml:"master_key"`
	AgentSock   string `yaml:"agent_socket"`
	AppliedPlan string `yaml:"applied_plan"`
	NFTConfig   string `yaml:"nft_config"`
}

type SchedulerConfig struct {
	InactiveAfter time.Duration `yaml:"-"`
	MinDwell      time.Duration `yaml:"-"`
	ImproveRatio  float64       `yaml:"improve_ratio"`
	MaxMoves      int           `yaml:"max_moves"`
}

const maxDuration = time.Duration(1<<63 - 1)
const xrayBackgroundProbeSlots = 20

func checkedDurationSum(parts ...time.Duration) (time.Duration, bool) {
	var total time.Duration
	for _, part := range parts {
		if part < 0 || part > maxDuration-total {
			return 0, false
		}
		total += part
	}
	return total, true
}

func checkedDurationProduct(value time.Duration, count int) (time.Duration, bool) {
	if value < 0 || count < 0 || (count > 0 && value > maxDuration/time.Duration(count)) {
		return 0, false
	}
	return value * time.Duration(count), true
}

// ActiveFailureFreshness spans the complete pipelined detection, observation,
// and hard-placement window. Validate rejects an overflowing or over-budget
// result before controller startup.
func (c Config) ActiveFailureFreshness() time.Duration {
	detection, ok := checkedDurationProduct(
		c.Probes.ActiveInterval, failoverbudget.ActiveAvailabilityConfirmations,
	)
	if !ok {
		return maxDuration
	}
	freshness, ok := checkedDurationSum(
		detection,
		c.Probes.ActiveDeadline,
		c.Probes.ActiveResponseSlack,
		failoverbudget.ActiveTargetPlanning,
		c.Controller.HardFailoverBudget,
	)
	if !ok {
		return maxDuration
	}
	return freshness
}

// QoEPromotionWindowFreshness bounds the oldest sample in the complete clean
// promotion window. One extra cadence tolerates scheduler/probe phase skew.
func (c Config) QoEPromotionWindowFreshness() time.Duration {
	cadences, ok := checkedDurationProduct(c.QoE.ActiveInterval, c.QoE.WindowSize)
	if !ok {
		return maxDuration
	}
	freshness, ok := checkedDurationSum(cadences, c.QoE.Deadline)
	if !ok {
		return maxDuration
	}
	return freshness
}

func (c Config) QoEPromotionMaximumSampleGap() time.Duration {
	gap, ok := checkedDurationSum(c.QoE.ActiveInterval, c.QoE.Deadline)
	if !ok {
		return maxDuration
	}
	return gap
}

func (c Config) ActiveProofFreshness() time.Duration {
	return max(c.ActiveFailureFreshness(), c.Probes.ActiveProofGrace)
}

// QoEPromotionFreshness keeps only observations gathered close enough to the
// active standby cadence to prove that an optional promotion target is still
// stable. The full clean window is checked separately by the controller.
func (c Config) QoEPromotionFreshness() time.Duration {
	freshness, ok := checkedDurationSum(
		c.QoE.ActiveInterval,
		c.QoE.ActiveInterval,
		c.QoE.Deadline,
	)
	if !ok {
		return maxDuration
	}
	return freshness
}

func Defaults() Config {
	qoePolicy := qoe.DefaultPolicy()
	return Config{
		Portal: PortalConfig{
			Bind: "0.0.0.0:8080", GatewayBind: "10.44.0.1:80",
			ControllerURL: "http://controller:8080", InternalTokenPath: "/run/hydrat/portal.token",
		},
		Inventory: InventoryConfig{
			MaxCandidates: 10_000, WorkingPoolSize: 200,
			RetirementGrace: 15 * time.Minute, RetiredRetention: time.Minute,
		},
		Probes: ProbesConfig{
			FastWorkers:         8,
			FullWorkers:         4,
			ActiveWorkers:       32,
			ActiveRouteLimit:    16,
			ActiveOverlap:       2,
			FastDeadline:        6 * time.Second,
			FullDeadline:        20 * time.Second,
			TorFastDeadline:     5 * time.Minute,
			TorFullDeadline:     6 * time.Minute,
			ActiveInterval:      2 * time.Second,
			ActiveDeadline:      1900 * time.Millisecond,
			ActiveResponseSlack: 75 * time.Millisecond,
			ActiveProofGrace:    15 * time.Second,
			GateEndpoints: GateEndpointsConfig{
				YouTube:   "https://www.youtube.com/generate_204",
				ChatGPT:   "https://chatgpt.com/",
				OpenAI:    "https://api.openai.com/v1/models",
				Telegram:  "https://web.telegram.org/",
				Instagram: "https://www.instagram.com/",
			},
		},
		ProbeRuntime: ProbeRuntimeConfig{
			MaxProbes:        250,
			MaxRSSMiB:        256,
			MaxFDs:           2048,
			DrainTimeout:     25 * time.Second,
			StopTimeout:      5 * time.Second,
			ReadinessTimeout: 60 * time.Second,
			CleanupTimeout:   3 * time.Second,
		},
		QoE: QoEConfig{
			Enabled:               true,
			ActiveInterval:        30 * time.Second,
			IdleInterval:          5 * time.Minute,
			DegradedInterval:      time.Minute,
			Deadline:              qoePolicy.Deadline,
			Workers:               qoe.MaxProbeWorkers,
			StandbyCandidates:     3,
			SampleBytes:           qoePolicy.SampleBytes,
			WindowSize:            qoePolicy.WindowSize,
			BadSamples:            qoePolicy.BadSamples,
			RecoveryGoodSamples:   qoePolicy.RecoveryGoodSamples,
			AvailabilityWindow:    qoePolicy.AvailabilityWindow,
			AvailabilityFailures:  qoePolicy.AvailabilityFailures,
			InitialTTFBLimit:      qoePolicy.InitialTTFBLimit,
			TTFBFloor:             qoePolicy.TTFBFloor,
			TTFBMultiplier:        qoePolicy.TTFBMultiplier,
			InitialThroughputMbps: qoePolicy.InitialThroughputMbps,
			ThroughputRatio:       qoePolicy.ThroughputRatio,
			AlternativeSpeedup:    qoe.MinimumAlternativeSpeedup,
			Retention:             168 * time.Hour,
		},
		Tournament: TournamentConfig{ResetWindow: 5 * time.Hour, PromotionRatio: 0.15},
		Tor: TorConfig{
			WarmProfiles: 3, ExplorerProfiles: 1, Binary: "/usr/bin/tor",
			LyrebirdBinary: "/usr/local/bin/lyrebird", DataDir: "/data/tor/profiles", SocksPortBase: 19050,
			ProbeDataDir: "/data/tor/probe-profiles", ProbeSocksPortBase: 19150,
		},
		Routing: RoutingConfig{
			FailPolicy:       FailClosed,
			DirectSuffixes:   []string{".ru", ".su", ".xn--p1ai"},
			DirectDomains:    []string{"thecode.media", "habr.com"},
			DisallowRUEgress: true,
			GeoRules: GeoRulesConfig{
				Enabled:        true,
				AutoUpdate:     true,
				GeoIPURL:       "https://raw.githubusercontent.com/runetfreedom/russia-blocked-geoip/release/geoip.dat",
				GeoSiteURL:     "https://raw.githubusercontent.com/runetfreedom/russia-blocked-geosite/release/geosite.dat",
				UpdateInterval: 24 * time.Hour,
			},
		},
		Paths: PathsConfig{
			Database:    "/data/hydrat.db",
			MasterKey:   "/data/secrets/master.key",
			AgentSock:   "/run/hydrat/agent.sock",
			AppliedPlan: "/data/applied-plan.json",
			NFTConfig:   "/etc/hydrat/nftables.nft",
		},
		Scheduler: SchedulerConfig{
			InactiveAfter: 2 * time.Minute,
			MinDwell:      30 * time.Minute,
			ImproveRatio:  0.30,
			MaxMoves:      1,
		},
		WireGuard: WireGuardConfig{
			Interface: "wg0", Config: "/data/wireguard/wg0.conf", Network: "10.44.0.0/24",
			ListenPort: 51820, DNS: "10.44.0.1", MTU: 1420,
		},
		Xray: XrayConfig{
			Binary: "/usr/local/bin/xray", APIAddress: "127.0.0.1:10085", ProbeAPIAddress: "127.0.0.1:10086", ProbeSocksPortBase: 11080,
			ActiveAPIAddress: "127.0.0.1:10087", ActiveSocksPortBase: 12080,
			DNSResolver: "1.1.1.1", MainConfig: "/etc/hydrat/xray-main.json", ProbeConfig: "/etc/hydrat/xray-probe.json",
			ActiveConfig: "/etc/hydrat/xray-active.json",
		},
		Controller: ControllerConfig{
			CycleSeconds: 300, SourceRefreshSeconds: 3600, ProbeSeconds: 300,
			HardFailoverBudget:      800 * time.Millisecond,
			PlacementPreemptTimeout: 100 * time.Millisecond,
		},
	}
}

func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	cfg := Defaults()
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("decode config: multiple YAML documents are not allowed")
		}
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.Portal.Bind) == "" {
		return errors.New("portal.bind must not be empty")
	}
	if strings.TrimSpace(c.Portal.GatewayBind) == "" ||
		strings.TrimSpace(c.Portal.ControllerURL) == "" ||
		strings.TrimSpace(c.Portal.InternalTokenPath) == "" {
		return errors.New("portal gateway bind, controller URL and internal token path are required")
	}
	if c.Inventory.MaxCandidates <= 0 {
		return errors.New("inventory.max_candidates must be positive")
	}
	if c.Inventory.WorkingPoolSize <= 0 || c.Inventory.WorkingPoolSize > c.Inventory.MaxCandidates {
		return errors.New("inventory.working_pool_size must be positive and not exceed max_candidates")
	}
	if c.Inventory.RetirementGrace < time.Second {
		return errors.New("inventory.retirement_grace must be at least 1s")
	}
	if c.Inventory.RetiredRetention < time.Second {
		return errors.New("inventory.retired_retention must be at least 1s")
	}
	if c.Probes.FastWorkers <= 0 || c.Probes.FullWorkers <= 0 || c.Probes.ActiveWorkers <= 0 {
		return errors.New("probe worker counts must be positive")
	}
	if strings.TrimSpace(c.Xray.APIAddress) == "" ||
		strings.TrimSpace(c.Xray.ProbeAPIAddress) == "" ||
		strings.TrimSpace(c.Xray.ActiveAPIAddress) == "" ||
		c.Xray.ProbeSocksPortBase <= 0 || c.Xray.ActiveSocksPortBase <= 0 ||
		strings.TrimSpace(c.Xray.ActiveConfig) == "" {
		return errors.New("Xray API addresses, probe SOCKS bases and active config are required")
	}
	if c.Xray.APIAddress == c.Xray.ProbeAPIAddress ||
		c.Xray.ActiveAPIAddress == c.Xray.APIAddress ||
		c.Xray.ActiveAPIAddress == c.Xray.ProbeAPIAddress {
		return errors.New("active Xray endpoints must be isolated")
	}
	if c.Xray.ProbeSocksPortBase > 65535 ||
		xrayBackgroundProbeSlots > 65535-c.Xray.ProbeSocksPortBase+1 ||
		c.Xray.ActiveSocksPortBase > 65535 ||
		c.Probes.ActiveWorkers > 65535-c.Xray.ActiveSocksPortBase+1 {
		return errors.New("Xray probe SOCKS port ranges must be valid")
	}
	if portRangesOverlap(
		c.Xray.ProbeSocksPortBase, xrayBackgroundProbeSlots,
		c.Xray.ActiveSocksPortBase, c.Probes.ActiveWorkers,
	) {
		return errors.New("background and active Xray probe SOCKS ranges must be distinct")
	}
	xrayAPIAddresses := []string{
		c.Xray.APIAddress, c.Xray.ProbeAPIAddress, c.Xray.ActiveAPIAddress,
	}
	xrayAPIPorts := make([]int, 0, len(xrayAPIAddresses))
	for _, address := range xrayAPIAddresses {
		port, err := tcpListenerPort(address)
		if err != nil {
			return fmt.Errorf("invalid Xray API address %q: %w", address, err)
		}
		xrayAPIPorts = append(xrayAPIPorts, port)
		if portRangesOverlap(c.Xray.ProbeSocksPortBase, xrayBackgroundProbeSlots, port, 1) ||
			portRangesOverlap(c.Xray.ActiveSocksPortBase, c.Probes.ActiveWorkers, port, 1) {
			return errors.New("an Xray probe SOCKS range overlaps an Xray API listener")
		}
	}
	if c.Probes.FastDeadline <= 0 || c.Probes.FullDeadline <= 0 ||
		c.Probes.TorFastDeadline <= 0 || c.Probes.TorFullDeadline <= 0 ||
		c.Probes.ActiveInterval <= 0 || c.Probes.ActiveDeadline <= 0 {
		return errors.New("probe durations must be positive")
	}
	if c.Probes.ActiveRouteLimit <= 0 || c.Probes.ActiveOverlap <= 0 ||
		c.Probes.ActiveResponseSlack <= 0 {
		return errors.New("active failover route limit, overlap and response slack must be positive")
	}
	activeWindow, activeWindowOK := checkedDurationSum(
		c.Probes.ActiveDeadline, c.Probes.ActiveResponseSlack,
	)
	if !activeWindowOK || activeWindow <= 0 {
		return errors.New("active failover observation window overflowed")
	}
	if activeWindow > failoverbudget.EndToEnd-failoverbudget.ActiveTargetPlanning {
		return fmt.Errorf("active target planning and observation exceed the %s cycle budget", failoverbudget.EndToEnd)
	}
	activeRunWindow, activeRunWindowOK := checkedDurationSum(
		activeWindow, failoverbudget.ActiveTargetPlanning,
	)
	if !activeRunWindowOK {
		return errors.New("active failover runtime window overflowed")
	}
	requiredOverlap := int((activeRunWindow-1)/c.Probes.ActiveInterval + 1)
	if c.Probes.ActiveOverlap < requiredOverlap {
		return fmt.Errorf("probes.active_overlap must be at least %d", requiredOverlap)
	}
	if c.Probes.ActiveRouteLimit > c.Probes.ActiveWorkers/c.Probes.ActiveOverlap {
		return errors.New("probes.active_workers cannot cover active_route_limit * active_overlap")
	}
	if c.Controller.HardFailoverBudget <= 0 ||
		c.Controller.PlacementPreemptTimeout <= 0 ||
		c.Controller.PlacementPreemptTimeout >= c.Controller.HardFailoverBudget {
		return errors.New("controller hard failover and preemption budgets are unsafe")
	}
	proofFreshness := c.ActiveFailureFreshness()
	if proofFreshness > failoverbudget.EndToEnd {
		return fmt.Errorf("pipelined active detection and hard placement exceed the %s failover budget", failoverbudget.EndToEnd)
	}
	if c.Probes.ActiveProofGrace <= 0 ||
		c.Probes.ActiveProofGrace < c.ActiveFailureFreshness() {
		return errors.New("probes.active_proof_grace must cover the active failure pipeline")
	}
	probeDeadlines := []struct {
		name  string
		value time.Duration
	}{
		{name: "fast_deadline", value: c.Probes.FastDeadline},
		{name: "full_deadline", value: c.Probes.FullDeadline},
		{name: "tor_fast_deadline", value: c.Probes.TorFastDeadline},
		{name: "tor_full_deadline", value: c.Probes.TorFullDeadline},
		{name: "active_deadline", value: c.Probes.ActiveDeadline},
	}
	for _, deadline := range probeDeadlines {
		if deadline.value > probetimeout.MaxProbeServerDeadline {
			return fmt.Errorf(
				"probes.%s must not exceed %s to reserve %s response slack",
				deadline.name,
				probetimeout.MaxProbeServerDeadline,
				probetimeout.ProbeResponseSlack,
			)
		}
	}
	requiredProbeRuntime := ProbeRuntimeConfig{
		MaxProbes:        250,
		MaxRSSMiB:        256,
		MaxFDs:           2048,
		DrainTimeout:     25 * time.Second,
		StopTimeout:      5 * time.Second,
		ReadinessTimeout: 60 * time.Second,
		CleanupTimeout:   3 * time.Second,
	}
	if c.ProbeRuntime.MaxProbes != requiredProbeRuntime.MaxProbes {
		return fmt.Errorf("probe_runtime.max_probes must be %d", requiredProbeRuntime.MaxProbes)
	}
	if c.ProbeRuntime.MaxRSSMiB != requiredProbeRuntime.MaxRSSMiB {
		return fmt.Errorf("probe_runtime.max_rss_mib must be %d", requiredProbeRuntime.MaxRSSMiB)
	}
	if c.ProbeRuntime.MaxFDs != requiredProbeRuntime.MaxFDs {
		return fmt.Errorf("probe_runtime.max_fds must be %d", requiredProbeRuntime.MaxFDs)
	}
	if c.ProbeRuntime.DrainTimeout != requiredProbeRuntime.DrainTimeout {
		return fmt.Errorf("probe_runtime.drain_timeout must be %s", requiredProbeRuntime.DrainTimeout)
	}
	if c.ProbeRuntime.StopTimeout != requiredProbeRuntime.StopTimeout {
		return fmt.Errorf("probe_runtime.stop_timeout must be %s", requiredProbeRuntime.StopTimeout)
	}
	if c.ProbeRuntime.ReadinessTimeout != requiredProbeRuntime.ReadinessTimeout {
		return fmt.Errorf("probe_runtime.readiness_timeout must be %s", requiredProbeRuntime.ReadinessTimeout)
	}
	if c.ProbeRuntime.CleanupTimeout != requiredProbeRuntime.CleanupTimeout {
		return fmt.Errorf("probe_runtime.cleanup_timeout must be %s", requiredProbeRuntime.CleanupTimeout)
	}
	if c.QoE.ActiveInterval <= 0 {
		return errors.New("qoe.active_interval must be positive")
	}
	if c.QoE.IdleInterval <= 0 {
		return errors.New("qoe.idle_interval must be positive")
	}
	if c.QoE.DegradedInterval <= 0 {
		return errors.New("qoe.degraded_interval must be positive")
	}
	if c.QoE.Deadline <= 0 {
		return errors.New("qoe.deadline must be positive")
	}
	if c.QoE.Workers <= 0 {
		return errors.New("qoe.workers must be positive")
	}
	if c.QoE.Workers > qoe.MaxProbeWorkers {
		return fmt.Errorf("qoe.workers must not exceed %d", qoe.MaxProbeWorkers)
	}
	if c.QoE.StandbyCandidates <= 0 {
		return errors.New("qoe.standby_candidates must be positive")
	}
	if c.QoE.SampleBytes <= 0 || c.QoE.SampleBytes > 1048576 {
		return errors.New("qoe.sample_bytes must be between 1 and 1048576")
	}
	if c.QoE.WindowSize < 1 || c.QoE.WindowSize > qoe.MaxWindowSize {
		return fmt.Errorf("qoe.window_size must be between 1 and %d", qoe.MaxWindowSize)
	}
	if c.QoE.BadSamples <= 0 || c.QoE.BadSamples > c.QoE.WindowSize {
		return errors.New("qoe.bad_samples must be positive and not exceed qoe.window_size")
	}
	if c.QoE.RecoveryGoodSamples <= 0 || c.QoE.RecoveryGoodSamples > c.QoE.WindowSize {
		return errors.New("qoe.recovery_good_samples must be positive and not exceed qoe.window_size")
	}
	if c.QoE.AvailabilityWindow < 1 || c.QoE.AvailabilityWindow > qoe.MaxWindowSize {
		return fmt.Errorf("qoe.availability_window must be between 1 and %d", qoe.MaxWindowSize)
	}
	if c.QoE.AvailabilityFailures <= 0 ||
		c.QoE.AvailabilityFailures > c.QoE.AvailabilityWindow {
		return errors.New("qoe.availability_failures must be positive and not exceed qoe.availability_window")
	}
	if c.QoE.InitialTTFBLimit <= 0 {
		return errors.New("qoe.initial_ttfb_limit must be positive")
	}
	if c.QoE.TTFBFloor <= 0 {
		return errors.New("qoe.ttfb_floor must be positive")
	}
	if math.IsNaN(c.QoE.TTFBMultiplier) || math.IsInf(c.QoE.TTFBMultiplier, 0) || c.QoE.TTFBMultiplier <= 0 {
		return errors.New("qoe.ttfb_multiplier must be finite and positive")
	}
	if math.IsNaN(c.QoE.InitialThroughputMbps) || math.IsInf(c.QoE.InitialThroughputMbps, 0) || c.QoE.InitialThroughputMbps <= 0 {
		return errors.New("qoe.initial_throughput_mbps must be finite and positive")
	}
	if math.IsNaN(c.QoE.ThroughputRatio) || math.IsInf(c.QoE.ThroughputRatio, 0) ||
		c.QoE.ThroughputRatio <= 0 || c.QoE.ThroughputRatio > 1 {
		return errors.New("qoe.throughput_ratio must be finite, greater than zero, and at most one")
	}
	if math.IsNaN(c.QoE.AlternativeSpeedup) || math.IsInf(c.QoE.AlternativeSpeedup, 0) ||
		c.QoE.AlternativeSpeedup < qoe.MinimumAlternativeSpeedup {
		return fmt.Errorf("qoe.alternative_speedup must be finite and at least %.1f", qoe.MinimumAlternativeSpeedup)
	}
	if c.QoE.Retention <= 0 {
		return errors.New("qoe.retention must be positive")
	}
	if c.Tournament.ResetWindow <= 0 || c.Tournament.PromotionRatio < 0 {
		return errors.New("invalid tournament policy")
	}
	if c.Tor.WarmProfiles < 0 || c.Tor.ExplorerProfiles < 0 {
		return errors.New("tor profile counts must not be negative")
	}
	if c.Tor.WarmProfiles+c.Tor.ExplorerProfiles > 4 {
		return errors.New("Tor profile budget must not exceed four")
	}
	torProfiles := c.Tor.WarmProfiles + c.Tor.ExplorerProfiles
	if torProfiles == 0 {
		return errors.New("at least one Tor profile is required")
	}
	if strings.TrimSpace(c.Tor.DataDir) == "" ||
		strings.TrimSpace(c.Tor.ProbeDataDir) == "" ||
		filepath.Clean(c.Tor.DataDir) == filepath.Clean(c.Tor.ProbeDataDir) {
		return errors.New("serving and probe Tor data directories must be distinct")
	}
	if c.Tor.SocksPortBase <= 0 || c.Tor.SocksPortBase > 65535 ||
		c.Tor.ProbeSocksPortBase <= 0 || c.Tor.ProbeSocksPortBase > 65535 ||
		c.Tor.SocksPortBase+torProfiles-1 > 65535 ||
		c.Tor.ProbeSocksPortBase+torProfiles-1 > 65535 {
		return errors.New("Tor SOCKS port ranges must be valid")
	}
	servingLast := c.Tor.SocksPortBase + torProfiles - 1
	probeLast := c.Tor.ProbeSocksPortBase + torProfiles - 1
	if c.Tor.SocksPortBase <= probeLast && c.Tor.ProbeSocksPortBase <= servingLast {
		return errors.New("serving and probe Tor SOCKS port ranges must be distinct")
	}
	for _, torRange := range []struct {
		name string
		base int
	}{
		{name: "serving", base: c.Tor.SocksPortBase},
		{name: "probe", base: c.Tor.ProbeSocksPortBase},
	} {
		if portRangesOverlap(
			torRange.base, torProfiles,
			c.Xray.ProbeSocksPortBase, xrayBackgroundProbeSlots,
		) || portRangesOverlap(
			torRange.base, torProfiles,
			c.Xray.ActiveSocksPortBase, c.Probes.ActiveWorkers,
		) {
			return fmt.Errorf("%s Tor SOCKS range overlaps an Xray probe range", torRange.name)
		}
		for _, port := range xrayAPIPorts {
			if portRangesOverlap(torRange.base, torProfiles, port, 1) {
				return fmt.Errorf("%s Tor SOCKS range overlaps an Xray API listener", torRange.name)
			}
		}
	}
	if c.WireGuard.Interface == "" || c.WireGuard.Config == "" || c.WireGuard.Network == "" {
		return errors.New("WireGuard interface, config and network are required")
	}
	if c.WireGuard.ListenPort <= 0 || c.WireGuard.ListenPort > 65535 {
		return errors.New("WireGuard listen_port must be between 1 and 65535")
	}
	if err := validateWireGuardDNS(c.WireGuard.Network, c.WireGuard.DNS); err != nil {
		return err
	}
	if c.Xray.Binary == "" || c.Xray.APIAddress == "" || c.Xray.MainConfig == "" {
		return errors.New("Xray binary, API address and main config are required")
	}
	if err := validateXrayDNSResolvers(c.Xray.EffectiveDNSResolvers(), c.WireGuard.DNS); err != nil {
		return err
	}
	if c.Controller.CycleSeconds <= 0 || c.Controller.SourceRefreshSeconds <= 0 || c.Controller.ProbeSeconds <= 0 {
		return errors.New("controller intervals must be positive")
	}
	if c.Routing.FailPolicy != FailClosed {
		return fmt.Errorf("routing.fail_policy must be %q", FailClosed)
	}
	if len(c.Routing.DirectSuffixes) == 0 {
		return errors.New("routing.direct_suffixes must contain at least one suffix")
	}
	for _, suffix := range c.Routing.DirectSuffixes {
		s := strings.TrimSpace(suffix)
		if s == "" || !strings.HasPrefix(s, ".") || len(s) < 2 {
			return fmt.Errorf("routing.direct_suffixes entry %q must start with '.' and be at least 2 characters", suffix)
		}
	}
	for _, domain := range c.Routing.DirectDomains {
		d := strings.TrimSpace(domain)
		if d == "" {
			return errors.New("routing.direct_domains entry must not be empty")
		}
		if strings.Contains(d, "://") || strings.Contains(d, "/") || strings.Contains(d, ":") {
			return fmt.Errorf("routing.direct_domains entry %q must be a clean domain name without scheme, port, or path", domain)
		}
	}
	if c.Routing.GeoRules.Enabled {
		if c.Routing.GeoRules.AutoUpdate {
			if strings.TrimSpace(c.Routing.GeoRules.GeoIPURL) == "" {
				return errors.New("routing.geo_rules.geoip_url must not be empty when auto_update is enabled")
			}
			u, err := url.Parse(c.Routing.GeoRules.GeoIPURL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("routing.geo_rules.geoip_url %q must be a valid http or https URL", c.Routing.GeoRules.GeoIPURL)
			}
			if strings.TrimSpace(c.Routing.GeoRules.GeoSiteURL) == "" {
				return errors.New("routing.geo_rules.geosite_url must not be empty when auto_update is enabled")
			}
			u, err = url.Parse(c.Routing.GeoRules.GeoSiteURL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("routing.geo_rules.geosite_url %q must be a valid http or https URL", c.Routing.GeoRules.GeoSiteURL)
			}
			if c.Routing.GeoRules.UpdateInterval <= 0 {
				return errors.New("routing.geo_rules.update_interval must be positive when auto_update is enabled")
			}
		}
	}
	for _, ep := range []struct {
		name string
		val  string
	}{
		{"youtube", c.Probes.GateEndpoints.YouTube},
		{"chatgpt", c.Probes.GateEndpoints.ChatGPT},
		{"openai", c.Probes.GateEndpoints.OpenAI},
		{"telegram", c.Probes.GateEndpoints.Telegram},
		{"instagram", c.Probes.GateEndpoints.Instagram},
	} {
		if strings.TrimSpace(ep.val) == "" {
			return fmt.Errorf("probes.gate_endpoints.%s must not be empty", ep.name)
		}
		u, err := url.Parse(ep.val)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("probes.gate_endpoints.%s %q must be a valid http or https URL", ep.name, ep.val)
		}
	}
	for _, gate := range c.Probes.CustomGates {
		if strings.TrimSpace(gate.Name) == "" {
			return errors.New("probes.custom_gates entry must have a non-empty name")
		}
		if strings.TrimSpace(gate.URL) == "" {
			return fmt.Errorf("probes.custom_gates %q must have a non-empty URL", gate.Name)
		}
		u, err := url.Parse(gate.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("probes.custom_gates %q URL %q must be a valid http or https URL", gate.Name, gate.URL)
		}
		for _, status := range gate.AcceptableStatuses {
			if status < 100 || status > 599 {
				return fmt.Errorf("probes.custom_gates %q has invalid acceptable status %d", gate.Name, status)
			}
		}
	}
	if c.Scheduler.ImproveRatio < 0 || c.Scheduler.MaxMoves <= 0 {
		return errors.New("invalid scheduler policy")
	}
	return nil
}

func portRangesOverlap(leftBase, leftCount, rightBase, rightCount int) bool {
	if leftBase <= 0 || leftCount <= 0 || rightBase <= 0 || rightCount <= 0 {
		return false
	}
	leftLast := leftBase + leftCount - 1
	rightLast := rightBase + rightCount - 1
	return leftBase <= rightLast && rightBase <= leftLast
}

func tcpListenerPort(address string) (int, error) {
	_, value, err := net.SplitHostPort(address)
	if err != nil {
		return 0, err
	}
	port, err := strconv.Atoi(value)
	if err != nil || port <= 0 || port > 65535 {
		return 0, errors.New("port must be between 1 and 65535")
	}
	return port, nil
}

func validateWireGuardDNS(networkCIDR, dnsAddress string) error {
	network, err := netip.ParsePrefix(networkCIDR)
	if err != nil || !network.Addr().Is4() {
		return errors.New("wireguard.network must be a canonical private IPv4 CIDR")
	}
	if network != network.Masked() {
		return errors.New("wireguard.network must use its canonical network address")
	}
	if network.Bits() > 30 {
		return errors.New("wireguard.network must have at least two usable IPv4 host addresses")
	}
	privateBlocks := [...]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	contained := false
	for _, block := range privateBlocks {
		if network.Bits() >= block.Bits() && block.Contains(network.Addr()) {
			contained = true
			break
		}
	}
	if !contained {
		return errors.New("wireguard.network must be fully contained in one RFC1918 IPv4 block")
	}

	dnsIP, err := netip.ParseAddr(dnsAddress)
	if err != nil || !dnsIP.Is4() {
		return errors.New("wireguard.dns must be a canonical IPv4 address")
	}
	firstUsable := network.Addr().Next()
	if dnsIP != firstUsable {
		return fmt.Errorf("wireguard.dns must be the first usable IPv4 address %s of wireguard.network", firstUsable)
	}
	return nil
}

func validateXrayDNSResolver(resolverAddress, clientDNSAddress string) error {
	resolver, err := netip.ParseAddr(resolverAddress)
	if err != nil || !resolver.Is4() || !resolver.IsGlobalUnicast() {
		return errors.New("xray.dns_resolver must be a canonical usable unicast IPv4 address")
	}
	clientDNS, err := netip.ParseAddr(clientDNSAddress)
	if err == nil && resolver == clientDNS {
		return errors.New("xray.dns_resolver must not target the WireGuard client gateway DNS")
	}
	return nil
}

func validateXrayDNSResolvers(resolvers []string, clientDNSAddress string) error {
	if err := dataplane.ValidateDNSResolverPool(resolvers); err != nil {
		return fmt.Errorf("xray.dns_resolvers: %w", err)
	}
	for _, resolver := range resolvers {
		if err := validateXrayDNSResolver(resolver, clientDNSAddress); err != nil {
			return err
		}
	}
	return nil
}

func (q QoEConfig) Policy() qoe.Policy {
	return qoe.Policy{
		WindowSize:            q.WindowSize,
		BadSamples:            q.BadSamples,
		RecoveryGoodSamples:   q.RecoveryGoodSamples,
		AvailabilityWindow:    q.AvailabilityWindow,
		AvailabilityFailures:  q.AvailabilityFailures,
		SampleBytes:           q.SampleBytes,
		Deadline:              q.Deadline,
		InitialTTFBLimit:      q.InitialTTFBLimit,
		TTFBFloor:             q.TTFBFloor,
		TTFBMultiplier:        q.TTFBMultiplier,
		InitialThroughputMbps: q.InitialThroughputMbps,
		ThroughputRatio:       q.ThroughputRatio,
		EWMAWeight:            0.1,
	}
}
