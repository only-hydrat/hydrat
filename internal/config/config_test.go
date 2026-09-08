package config

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/only-hydrat/hydrat/internal/probetimeout"
	"github.com/only-hydrat/hydrat/internal/qoe"
)

func TestQoEDefaultsMatchApprovedPolicy(t *testing.T) {
	cfg := Defaults()
	if !cfg.QoE.Enabled || cfg.QoE.ActiveInterval != 15*time.Second ||
		cfg.QoE.IdleInterval != 5*time.Minute || cfg.QoE.DegradedInterval != time.Minute ||
		cfg.QoE.Deadline != 10*time.Second || cfg.QoE.Workers != 4 ||
		cfg.QoE.StandbyCandidates != 3 || cfg.QoE.SampleBytes != 65536 ||
		cfg.QoE.WindowSize != 5 || cfg.QoE.BadSamples != 3 ||
		cfg.QoE.RecoveryGoodSamples != 4 || cfg.QoE.AvailabilityWindow != 20 ||
		cfg.QoE.AvailabilityFailures != 2 || cfg.QoE.InitialTTFBLimit != 3*time.Second ||
		cfg.QoE.TTFBFloor != 1500*time.Millisecond || cfg.QoE.TTFBMultiplier != 2.5 ||
		cfg.QoE.InitialThroughputMbps != 0.256 || cfg.QoE.ThroughputRatio != 0.35 ||
		cfg.QoE.AlternativeSpeedup != 1.3 || cfg.QoE.Retention != 168*time.Hour {
		t.Fatalf("qoe defaults=%+v", cfg.QoE)
	}
	if policy := cfg.QoE.Policy(); policy != qoe.DefaultPolicy() {
		t.Fatalf("qoe policy=%+v, want %+v", policy, qoe.DefaultPolicy())
	}
}

func TestLoadOverridesQoEPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	body := "qoe:\n" +
		"  enabled: false\n" +
		"  active_interval: 20s\n" +
		"  idle_interval: 6m\n" +
		"  degraded_interval: 90s\n" +
		"  deadline: 8s\n" +
		"  workers: 2\n" +
		"  standby_candidates: 2\n" +
		"  sample_bytes: 32768\n" +
		"  window_size: 7\n" +
		"  bad_samples: 4\n" +
		"  recovery_good_samples: 6\n" +
		"  availability_window: 12\n" +
		"  availability_failures: 3\n" +
		"  initial_ttfb_limit: 2500ms\n" +
		"  ttfb_floor: 1s\n" +
		"  ttfb_multiplier: 3.0\n" +
		"  initial_throughput_mbps: 0.5\n" +
		"  throughput_ratio: 0.4\n" +
		"  alternative_speedup: 1.75\n" +
		"  retention: 72h\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.QoE.Enabled || loaded.QoE.ActiveInterval != 20*time.Second ||
		loaded.QoE.IdleInterval != 6*time.Minute || loaded.QoE.DegradedInterval != 90*time.Second ||
		loaded.QoE.Retention != 72*time.Hour || loaded.QoE.AlternativeSpeedup != 1.75 {
		t.Fatalf("qoe overrides=%+v", loaded.QoE)
	}
	wantPolicy := qoe.Policy{
		WindowSize: 7, BadSamples: 4, RecoveryGoodSamples: 6,
		AvailabilityWindow: 12, AvailabilityFailures: 3,
		SampleBytes: 32768, Deadline: 8 * time.Second,
		InitialTTFBLimit: 2500 * time.Millisecond, TTFBFloor: time.Second,
		TTFBMultiplier: 3.0, InitialThroughputMbps: 0.5,
		ThroughputRatio: 0.4, EWMAWeight: 0.1,
	}
	if policy := loaded.QoE.Policy(); policy != wantPolicy {
		t.Fatalf("qoe policy=%+v, want %+v", policy, wantPolicy)
	}
}

func TestLoadRejectsUnknownQoEField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("qoe:\n  unknown: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("error=%v", err)
	}
}

func TestQoERejectsInconsistentWindow(t *testing.T) {
	tests := map[string]func(*QoEConfig){
		"bad_samples": func(cfg *QoEConfig) { cfg.BadSamples = cfg.WindowSize + 1 },
		"recovery_good_samples": func(cfg *QoEConfig) {
			cfg.RecoveryGoodSamples = cfg.WindowSize + 1
		},
		"availability_failures": func(cfg *QoEConfig) {
			cfg.AvailabilityFailures = cfg.AvailabilityWindow + 1
		},
	}
	for field, mutate := range tests {
		t.Run(field, func(t *testing.T) {
			cfg := Defaults()
			mutate(&cfg.QoE)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "qoe."+field) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestQoERejectsWindowSizeAboveMaximum(t *testing.T) {
	t.Run("default config validation", func(t *testing.T) {
		cfg := Defaults()
		cfg.QoE.WindowSize = 101
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "qoe.window_size") {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("YAML", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yml")
		if err := os.WriteFile(path, []byte("qoe:\n  window_size: 101\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "qoe.window_size") {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestQoERejectsInvalidBounds(t *testing.T) {
	tests := map[string]func(*QoEConfig){
		"active_interval":         func(cfg *QoEConfig) { cfg.ActiveInterval = 0 },
		"idle_interval":           func(cfg *QoEConfig) { cfg.IdleInterval = -time.Second },
		"degraded_interval":       func(cfg *QoEConfig) { cfg.DegradedInterval = 0 },
		"deadline":                func(cfg *QoEConfig) { cfg.Deadline = 0 },
		"workers":                 func(cfg *QoEConfig) { cfg.Workers = 0 },
		"workers_max":             func(cfg *QoEConfig) { cfg.Workers = 5 },
		"standby_candidates":      func(cfg *QoEConfig) { cfg.StandbyCandidates = 0 },
		"sample_bytes_zero":       func(cfg *QoEConfig) { cfg.SampleBytes = 0 },
		"sample_bytes_max":        func(cfg *QoEConfig) { cfg.SampleBytes = 1048577 },
		"window_size":             func(cfg *QoEConfig) { cfg.WindowSize = 0 },
		"bad_samples":             func(cfg *QoEConfig) { cfg.BadSamples = 0 },
		"recovery_good_samples":   func(cfg *QoEConfig) { cfg.RecoveryGoodSamples = 0 },
		"availability_window":     func(cfg *QoEConfig) { cfg.AvailabilityWindow = 0 },
		"availability_window_max": func(cfg *QoEConfig) { cfg.AvailabilityWindow = 101 },
		"availability_failures":   func(cfg *QoEConfig) { cfg.AvailabilityFailures = 0 },
		"initial_ttfb_limit":      func(cfg *QoEConfig) { cfg.InitialTTFBLimit = 0 },
		"ttfb_floor":              func(cfg *QoEConfig) { cfg.TTFBFloor = 0 },
		"ttfb_multiplier":         func(cfg *QoEConfig) { cfg.TTFBMultiplier = 0 },
		"initial_throughput_mbps": func(cfg *QoEConfig) { cfg.InitialThroughputMbps = 0 },
		"throughput_ratio":        func(cfg *QoEConfig) { cfg.ThroughputRatio = 0 },
		"throughput_ratio_max":    func(cfg *QoEConfig) { cfg.ThroughputRatio = 1.01 },
		"alternative_speedup":     func(cfg *QoEConfig) { cfg.AlternativeSpeedup = 1.29 },
		"retention":               func(cfg *QoEConfig) { cfg.Retention = 0 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := Defaults()
			mutate(&cfg.QoE)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestLoadRejectsQoEPolicyBelowProductSafetyBounds(t *testing.T) {
	for name, body := range map[string]string{
		"workers":             "qoe:\n  workers: 5\n",
		"alternative_speedup": "qoe:\n  alternative_speedup: 1.299\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "qoe."+name) {
				t.Fatalf("Load() error=%v, want qoe.%s validation error", err, name)
			}
		})
	}
}

func TestLoadRejectsNonFiniteQoEValues(t *testing.T) {
	fields := []string{
		"ttfb_multiplier",
		"initial_throughput_mbps",
		"throughput_ratio",
		"alternative_speedup",
	}
	values := []string{".nan", ".inf", "-.inf"}
	for _, field := range fields {
		for _, value := range values {
			t.Run(field+"/"+value, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "config.yml")
				body := fmt.Sprintf("qoe:\n  %s: %s\n", field, value)
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}

				if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "qoe."+field) {
					t.Fatalf("Load() error=%v, want qoe.%s validation error", err, field)
				}
			})
		}
	}
}

func TestLoadAppliesHydratV2Defaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("portal:\n  bind: 10.44.0.1:80\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Inventory.MaxCandidates != 10_000 || loaded.Inventory.WorkingPoolSize != 200 {
		t.Fatalf("inventory defaults = %+v", loaded.Inventory)
	}
	if loaded.Inventory.RetirementGrace != 15*time.Minute ||
		loaded.Inventory.RetiredRetention != time.Minute {
		t.Fatalf("inventory lifecycle defaults = %+v", loaded.Inventory)
	}
	if loaded.Probes.FastWorkers != 8 || loaded.Probes.FullWorkers != 4 ||
		loaded.Probes.ActiveWorkers != 32 || loaded.Probes.ActiveRouteLimit != 16 ||
		loaded.Probes.ActiveOverlap != 2 {
		t.Fatalf("probe defaults = %+v", loaded.Probes)
	}
	if loaded.Probes.FastDeadline != 6*time.Second || loaded.Probes.FullDeadline != 20*time.Second {
		t.Fatalf("background probe defaults = %+v", loaded.Probes)
	}
	if loaded.Probes.TorFastDeadline != 5*time.Minute ||
		loaded.Probes.TorFullDeadline != 6*time.Minute {
		t.Fatalf("Tor deadlines=%s/%s", loaded.Probes.TorFastDeadline, loaded.Probes.TorFullDeadline)
	}
	if loaded.Probes.ActiveInterval != 2*time.Second ||
		loaded.Probes.ActiveDeadline != 1900*time.Millisecond ||
		loaded.Probes.ActiveResponseSlack != 75*time.Millisecond ||
		loaded.Probes.ActiveProofGrace != 15*time.Second {
		t.Fatalf("active probe defaults = %+v", loaded.Probes)
	}
	if loaded.Xray.ActiveAPIAddress != "127.0.0.1:10087" ||
		loaded.Xray.ActiveSocksPortBase != 12080 ||
		loaded.Xray.ActiveConfig != "/etc/hydrat/xray-active.json" {
		t.Fatalf("active Xray defaults=%+v", loaded.Xray)
	}
	if loaded.Controller.HardFailoverBudget != 800*time.Millisecond ||
		loaded.Controller.PlacementPreemptTimeout != 100*time.Millisecond {
		t.Fatalf("hard failover defaults = %+v", loaded.Controller)
	}
	if loaded.Tournament.ResetWindow != 5*time.Hour || loaded.Tournament.PromotionRatio != 0.15 {
		t.Fatalf("tournament defaults = %+v", loaded.Tournament)
	}
	if loaded.Tor.WarmProfiles != 3 || loaded.Tor.ExplorerProfiles != 1 {
		t.Fatalf("tor defaults = %+v", loaded.Tor)
	}
	if loaded.Tor.ProbeDataDir != "/data/tor/probe-profiles" ||
		loaded.Tor.ProbeSocksPortBase != 19150 {
		t.Fatalf("isolated Tor probe defaults = %+v", loaded.Tor)
	}
	if loaded.Routing.FailPolicy != FailClosed ||
		!reflect.DeepEqual(loaded.Routing.DirectSuffixes, []string{".ru", ".su", ".xn--p1ai"}) ||
		!reflect.DeepEqual(loaded.Routing.DirectDomains, []string{"thecode.media", "habr.com"}) ||
		!loaded.Routing.GeoRules.Enabled || !loaded.Routing.GeoRules.AutoUpdate ||
		loaded.Routing.GeoRules.UpdateInterval != 24*time.Hour {
		t.Fatalf("routing defaults = %+v", loaded.Routing)
	}
	if loaded.Probes.GateEndpoints.YouTube != "https://www.youtube.com/generate_204" ||
		loaded.Probes.GateEndpoints.ChatGPT != "https://chatgpt.com/" ||
		loaded.Probes.GateEndpoints.OpenAI != "https://api.openai.com/v1/models" ||
		loaded.Probes.GateEndpoints.Telegram != "https://web.telegram.org/" ||
		loaded.Probes.GateEndpoints.Instagram != "https://www.instagram.com/" {
		t.Fatalf("gate endpoint defaults = %+v", loaded.Probes.GateEndpoints)
	}
}

func TestFailoverConfigRejectsUnsafeBudgetAndCapacity(t *testing.T) {
	tests := map[string]func(*Config){
		"route limit": func(cfg *Config) { cfg.Probes.ActiveRouteLimit = 0 },
		"overlap":     func(cfg *Config) { cfg.Probes.ActiveOverlap = 1 },
		"planning overlap": func(cfg *Config) {
			cfg.Probes.ActiveOverlap = 3
		},
		"workers":         func(cfg *Config) { cfg.Probes.ActiveWorkers = 31 },
		"response slack":  func(cfg *Config) { cfg.Probes.ActiveResponseSlack = 0 },
		"hard budget":     func(cfg *Config) { cfg.Controller.HardFailoverBudget = 0 },
		"preempt timeout": func(cfg *Config) { cfg.Controller.PlacementPreemptTimeout = 0 },
		"preempt exceeds hard budget": func(cfg *Config) {
			cfg.Controller.PlacementPreemptTimeout = cfg.Controller.HardFailoverBudget
		},
		"end-to-end budget": func(cfg *Config) {
			cfg.Controller.HardFailoverBudget = 3 * time.Second
		},
		"planning and observation budget": func(cfg *Config) {
			cfg.Probes.ActiveDeadline = 5 * time.Second
		},
		"proof window overflow": func(cfg *Config) {
			cfg.Probes.ActiveInterval = time.Duration(math.MaxInt64)
			cfg.Controller.HardFailoverBudget = time.Duration(math.MaxInt64)
		},
		"proof grace missing": func(cfg *Config) {
			cfg.Probes.ActiveProofGrace = 0
		},
		"proof grace shorter than pipeline": func(cfg *Config) {
			cfg.Probes.ActiveProofGrace = time.Second
		},
		"Tor probe data collision": func(cfg *Config) {
			cfg.Tor.ProbeDataDir = cfg.Tor.DataDir
		},
		"Tor probe port collision": func(cfg *Config) {
			cfg.Tor.ProbeSocksPortBase = cfg.Tor.SocksPortBase + 1
		},
		"Tor probe port overflow": func(cfg *Config) {
			cfg.Tor.ProbeSocksPortBase = int(^uint(0) >> 1)
		},
		"Tor probe overlaps background Xray": func(cfg *Config) {
			cfg.Tor.ProbeSocksPortBase = cfg.Xray.ProbeSocksPortBase + 19
		},
		"Tor probe overlaps active Xray": func(cfg *Config) {
			cfg.Tor.ProbeSocksPortBase = cfg.Xray.ActiveSocksPortBase + cfg.Probes.ActiveWorkers - 1
		},
		"background Xray base zero": func(cfg *Config) {
			cfg.Xray.ProbeSocksPortBase = 0
		},
		"background and active Xray ranges overlap": func(cfg *Config) {
			cfg.Xray.ActiveSocksPortBase = cfg.Xray.ProbeSocksPortBase + xrayBackgroundProbeSlots - 1
		},
		"Tor probe overlaps Xray API listener": func(cfg *Config) {
			cfg.Tor.ProbeSocksPortBase = 10085
		},
		"Xray probe overlaps API listener": func(cfg *Config) {
			cfg.Xray.ProbeSocksPortBase = 10085
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := Defaults()
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("unsafe failover config was accepted")
			}
		})
	}
}

func TestActiveFailureFreshnessCoversValidatedFailoverPipeline(t *testing.T) {
	cfg := Defaults()
	if got := cfg.ActiveFailureFreshness(); got != 7775*time.Millisecond {
		t.Fatalf("active failure freshness=%s want=7.775s", got)
	}
}

func TestActiveProofFreshnessUsesConfiguredGrace(t *testing.T) {
	cfg := Defaults()
	if got := cfg.ActiveProofFreshness(); got != 15*time.Second {
		t.Fatalf("active proof freshness=%s want=15s", got)
	}
	cfg.Probes.ActiveProofGrace = 20 * time.Second
	if got := cfg.ActiveProofFreshness(); got != 20*time.Second {
		t.Fatalf("overridden active proof freshness=%s want=20s", got)
	}
}

func TestQoEPromotionFreshnessCoversTwoCadencesAndProbe(t *testing.T) {
	cfg := Defaults()
	if got := cfg.QoEPromotionFreshness(); got != 40*time.Second {
		t.Fatalf("QoE promotion freshness=%s want=40s", got)
	}
	if got := cfg.QoEPromotionWindowFreshness(); got != 85*time.Second {
		t.Fatalf("QoE promotion window freshness=%s want=85s", got)
	}
	if got := cfg.QoEPromotionMaximumSampleGap(); got != 25*time.Second {
		t.Fatalf("QoE promotion maximum sample gap=%s want=25s", got)
	}
	cfg.QoE.ActiveInterval = time.Duration(math.MaxInt64)
	if got := cfg.QoEPromotionFreshness(); got != maxDuration {
		t.Fatalf("overflowing QoE promotion freshness=%s want=%s", got, maxDuration)
	}
	if got := cfg.QoEPromotionWindowFreshness(); got != maxDuration {
		t.Fatalf("overflowing QoE promotion window freshness=%s want=%s", got, maxDuration)
	}
	if got := cfg.QoEPromotionMaximumSampleGap(); got != maxDuration {
		t.Fatalf("overflowing QoE promotion sample gap=%s want=%s", got, maxDuration)
	}
}

func TestActiveProofFreshnessUsesLongerComputedPipeline(t *testing.T) {
	cfg := Defaults()
	cfg.Probes.ActiveInterval = 20 * time.Second
	want := 43775 * time.Millisecond
	if got := cfg.ActiveFailureFreshness(); got != want {
		t.Fatalf("active failure freshness=%s want=%s", got, want)
	}
	if got := cfg.ActiveProofFreshness(); got != want {
		t.Fatalf("active proof freshness=%s want=%s", got, want)
	}
}

func TestActiveProofFreshnessSaturatesBothWindowsOnOverflow(t *testing.T) {
	cfg := Defaults()
	cfg.Probes.ActiveInterval = time.Duration(math.MaxInt64)
	cfg.Controller.HardFailoverBudget = time.Duration(math.MaxInt64)
	if got := cfg.ActiveFailureFreshness(); got != maxDuration {
		t.Fatalf("overflowing active failure freshness=%s want saturation=%s", got, maxDuration)
	}
	if got := cfg.ActiveProofFreshness(); got != maxDuration {
		t.Fatalf("overflowing active proof freshness=%s want saturation=%s", got, maxDuration)
	}
}

func TestLoadOverridesFailoverDurationsWithoutLegacyFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	body := "probes:\n" +
		"  active_route_limit: 8\n" +
		"  active_overlap: 8\n" +
		"  active_workers: 64\n" +
		"  active_interval: 200ms\n" +
		"  active_deadline: 500ms\n" +
		"  active_response_slack: 50ms\n" +
		"  active_proof_grace: 17s\n" +
		"controller:\n" +
		"  hard_failover_budget: 750ms\n" +
		"  placement_preempt_timeout: 80ms\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Probes.ActiveRouteLimit != 8 || loaded.Probes.ActiveOverlap != 8 ||
		loaded.Probes.ActiveWorkers != 64 ||
		loaded.Probes.ActiveInterval != 200*time.Millisecond ||
		loaded.Probes.ActiveDeadline != 500*time.Millisecond ||
		loaded.Probes.ActiveResponseSlack != 50*time.Millisecond ||
		loaded.Probes.ActiveProofGrace != 17*time.Second ||
		loaded.Controller.HardFailoverBudget != 750*time.Millisecond ||
		loaded.Controller.PlacementPreemptTimeout != 80*time.Millisecond {
		t.Fatalf("failover overrides=%+v controller=%+v", loaded.Probes, loaded.Controller)
	}
}

func TestLoadOverridesTorProbeDeadlines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("probes:\n  tor_fast_deadline: 50s\n  tor_full_deadline: 90s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Probes.TorFastDeadline != 50*time.Second || loaded.Probes.TorFullDeadline != 90*time.Second {
		t.Fatalf("Tor deadlines=%+v", loaded.Probes)
	}
}

func TestLoadRejectsSubsecondCandidateLifecycleDurations(t *testing.T) {
	for _, field := range []string{"retirement_grace", "retired_retention"} {
		for _, value := range []string{"1ns", "999ms"} {
			t.Run(field+"/"+value, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "config.yml")
				if err := os.WriteFile(
					path,
					[]byte("inventory:\n  "+field+": "+value+"\n"),
					0o600,
				); err != nil {
					t.Fatal(err)
				}
				if _, err := Load(path); err == nil {
					t.Fatalf("accepted inventory.%s=%s", field, value)
				}
			})
		}
		t.Run(field+"/1s", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			if err := os.WriteFile(
				path,
				[]byte("inventory:\n  "+field+": 1s\n"),
				0o600,
			); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err != nil {
				t.Fatalf("rejected inventory.%s=1s: %v", field, err)
			}
		})
	}
}

func TestLoadAcceptsMaximumProbeServerDeadline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	body := fmt.Sprintf(
		"probes:\n  fast_deadline: %s\n  full_deadline: %s\n  tor_fast_deadline: %s\n  tor_full_deadline: %s\n",
		probetimeout.MaxProbeServerDeadline,
		probetimeout.MaxProbeServerDeadline,
		probetimeout.MaxProbeServerDeadline,
		probetimeout.MaxProbeServerDeadline,
	)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	deadlines := []time.Duration{
		loaded.Probes.FastDeadline,
		loaded.Probes.FullDeadline,
		loaded.Probes.TorFastDeadline,
		loaded.Probes.TorFullDeadline,
	}
	for _, deadline := range deadlines {
		if deadline != probetimeout.MaxProbeServerDeadline {
			t.Fatalf("deadline=%s, want %s", deadline, probetimeout.MaxProbeServerDeadline)
		}
		controllerTimeout := probetimeout.RequestTimeout(deadline)
		if controllerTimeout != deadline+probetimeout.ProbeResponseSlack ||
			controllerTimeout <= deadline {
			t.Fatalf("controller timeout=%s, want %s plus strict slack", controllerTimeout, deadline)
		}
	}
}

func TestLoadRejectsProbeDeadlinesWithoutResponseSlackRoom(t *testing.T) {
	const unsafeDeadline = probetimeout.MaxProbeServerDeadline + 1
	fields := []string{
		"fast_deadline",
		"full_deadline",
		"tor_fast_deadline",
		"tor_full_deadline",
	}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			body := fmt.Sprintf("probes:\n  %s: %s\n", field, unsafeDeadline)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}

			_, err := Load(path)
			if err == nil {
				t.Fatalf("accepted unsafe probes.%s", field)
			}
			if !strings.Contains(err.Error(), "probes."+field) ||
				!strings.Contains(err.Error(), "must not exceed") {
				t.Fatalf("error=%q, want field-specific maximum", err)
			}
		})
	}
}

func TestLoadRejectsUnknownAndUnsafeValues(t *testing.T) {
	tests := map[string]string{
		"unknown field":          "unknown: true\n",
		"open failure":           "routing:\n  fail_policy: open\n",
		"zero workers":           "probes:\n  full_workers: 0\n",
		"zero Tor deadline":      "probes:\n  tor_fast_deadline: 0s\n",
		"pool exceeds inventory": "inventory:\n  max_candidates: 10\n  working_pool_size: 11\n",
		"zero retirement grace":  "inventory:\n  retirement_grace: 0s\n",
		"zero retired retention": "inventory:\n  retired_retention: 0s\n",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestLoadRuntimeSections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	body := "wireguard:\n  interface: wg0\n  config: /data/wireguard/wg0.conf\n  endpoint: vpn.example.net:51820\n  network: 10.44.0.0/24\n" +
		"xray:\n  binary: /usr/local/bin/xray\n  api_address: 127.0.0.1:10085\n  dns_resolver: 9.9.9.9\n  main_config: /etc/hydrat/xray-main.json\n" +
		"tor:\n  warm_profiles: 3\n  explorer_profiles: 1\n  binary: /usr/bin/tor\n  lyrebird_binary: /usr/local/bin/lyrebird\n  data_dir: /data/tor/profiles\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.WireGuard.Endpoint != "vpn.example.net:51820" ||
		loaded.Xray.APIAddress != "127.0.0.1:10085" ||
		loaded.Xray.DNSResolver != "9.9.9.9" ||
		loaded.Tor.Binary != "/usr/bin/tor" {
		t.Fatalf("runtime config=%+v", loaded)
	}
}

func TestWireGuardDNSDefaultsToGatewayFirstUsableAddress(t *testing.T) {
	cfg := Defaults()
	if cfg.WireGuard.Network != "10.44.0.0/24" {
		t.Fatalf("wireguard network=%q, want 10.44.0.0/24", cfg.WireGuard.Network)
	}
	if cfg.WireGuard.DNS != "10.44.0.1" {
		t.Fatalf("wireguard DNS=%q, want first usable gateway address 10.44.0.1", cfg.WireGuard.DNS)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
}

func TestWireGuardNetworkAndDNSRequireCanonicalPrivateIPv4Boundary(t *testing.T) {
	tests := []struct {
		name      string
		network   string
		dns       string
		wantField string
	}{
		{name: "public resolver", network: "10.44.0.0/24", dns: "1.1.1.1", wantField: "wireguard.dns"},
		{name: "network address", network: "10.44.0.0/24", dns: "10.44.0.0", wantField: "wireguard.dns"},
		{name: "broadcast address", network: "10.44.0.0/24", dns: "10.44.0.255", wantField: "wireguard.dns"},
		{name: "other private address", network: "10.44.0.0/24", dns: "10.44.0.2", wantField: "wireguard.dns"},
		{name: "IPv6 DNS", network: "10.44.0.0/24", dns: "fd00::1", wantField: "wireguard.dns"},
		{name: "mapped IPv6 DNS", network: "10.44.0.0/24", dns: "::ffff:10.44.0.1", wantField: "wireguard.dns"},
		{name: "whitespace DNS", network: "10.44.0.0/24", dns: " 10.44.0.1", wantField: "wireguard.dns"},
		{name: "noncanonical CIDR address", network: "10.44.0.1/24", dns: "10.44.0.1", wantField: "wireguard.network"},
		{name: "public WireGuard network", network: "198.51.100.0/24", dns: "198.51.100.1", wantField: "wireguard.network"},
		{name: "partially public 10 block", network: "10.0.0.0/7", dns: "10.0.0.1", wantField: "wireguard.network"},
		{name: "partially public 172 block", network: "172.0.0.0/11", dns: "172.0.0.1", wantField: "wireguard.network"},
		{name: "mapped IPv6 CIDR", network: "::ffff:10.44.0.0/120", dns: "10.44.0.1", wantField: "wireguard.network"},
		{name: "slash 31", network: "10.44.0.0/31", dns: "10.44.0.1", wantField: "wireguard.network"},
		{name: "slash 32", network: "10.44.0.1/32", dns: "10.44.0.1", wantField: "wireguard.network"},
		{name: "whitespace CIDR", network: " 10.44.0.0/24", dns: "10.44.0.1", wantField: "wireguard.network"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.WireGuard.Network = testCase.network
			cfg.WireGuard.DNS = testCase.dns
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), testCase.wantField) {
				t.Fatalf("Validate() error=%v, want %s boundary error", err, testCase.wantField)
			}
		})
	}

	for _, valid := range []struct {
		network string
		dns     string
	}{
		{network: "10.0.0.0/8", dns: "10.0.0.1"},
		{network: "172.16.0.0/12", dns: "172.16.0.1"},
		{network: "192.168.0.0/16", dns: "192.168.0.1"},
		{network: "10.9.0.0/30", dns: "10.9.0.1"},
	} {
		cfg := Defaults()
		cfg.WireGuard.Network = valid.network
		cfg.WireGuard.DNS = valid.dns
		if err := cfg.Validate(); err != nil {
			t.Fatalf("valid private boundary %s/%s rejected: %v", valid.network, valid.dns, err)
		}
	}
}

func TestXrayDNSResolverIsStrictExternalIPv4AndNotClientGateway(t *testing.T) {
	cfg := Defaults()
	if cfg.Xray.DNSResolver != "1.1.1.1" {
		t.Fatalf("default Xray DNS resolver=%q, want 1.1.1.1", cfg.Xray.DNSResolver)
	}
	for _, resolver := range []string{
		"", "10.44.0.1", "0.0.0.0", "127.0.0.1", "169.254.1.1",
		"224.0.0.1", "255.255.255.255", "::1", "::ffff:1.1.1.1", " 1.1.1.1",
	} {
		t.Run(resolver, func(t *testing.T) {
			testConfig := Defaults()
			testConfig.Xray.DNSResolver = resolver
			if err := testConfig.Validate(); err == nil || !strings.Contains(err.Error(), "xray.dns_resolver") {
				t.Fatalf("Validate() error=%v, want xray.dns_resolver boundary error", err)
			}
		})
	}
	cfg.Xray.DNSResolver = "9.9.9.9"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid external resolver rejected: %v", err)
	}
}

func TestXrayDNSResolverPoolRejectsDuplicatesAndUnsafeAddresses(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		resolvers []string
	}{
		{name: "empty", resolvers: []string{}},
		{name: "duplicate", resolvers: []string{"1.1.1.1", "1.1.1.1"}},
		{name: "client gateway", resolvers: []string{"1.1.1.1", "10.44.0.1"}},
		{name: "special use", resolvers: []string{"1.1.1.1", "198.51.100.1"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Xray.DNSResolver = ""
			cfg.Xray.DNSResolvers = testCase.resolvers
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid DNS resolver pool was accepted")
			}
		})
	}
	cfg := Defaults()
	cfg.Xray.DNSResolvers = []string{"1.1.1.1", "9.9.9.9", "8.8.8.8"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid DNS resolver pool rejected: %v", err)
	}
}

func TestProductionYAMLSeparatesClientAndUpstreamDNS(t *testing.T) {
	loaded, err := Load(filepath.Join("..", "..", "config", "config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.WireGuard.DNS != "10.44.0.1" {
		t.Fatalf("production wireguard DNS=%q, want 10.44.0.1", loaded.WireGuard.DNS)
	}
	if loaded.Xray.DNSResolver != "1.1.1.1" {
		t.Fatalf("production Xray DNS resolver=%q, want external upstream 1.1.1.1", loaded.Xray.DNSResolver)
	}
	wantResolvers := []string{"1.1.1.1", "9.9.9.9", "8.8.8.8"}
	if !reflect.DeepEqual(loaded.Xray.EffectiveDNSResolvers(), wantResolvers) {
		t.Fatalf("production Xray DNS resolver pool=%v want=%v", loaded.Xray.EffectiveDNSResolvers(), wantResolvers)
	}
}

func TestProbeRuntimeDefaultsMatchFixedProductionBoundary(t *testing.T) {
	got := Defaults().ProbeRuntime
	want := ProbeRuntimeConfig{
		MaxProbes:        250,
		MaxRSSMiB:        256,
		MaxFDs:           2048,
		DrainTimeout:     25 * time.Second,
		StopTimeout:      5 * time.Second,
		ReadinessTimeout: 60 * time.Second,
		CleanupTimeout:   3 * time.Second,
	}
	if got != want {
		t.Fatalf("probe runtime defaults=%+v, want %+v", got, want)
	}
}

func TestProbeRuntimeRejectsEveryProductionBoundaryOverride(t *testing.T) {
	tests := map[string]func(*ProbeRuntimeConfig){
		"max_probes_zero":      func(config *ProbeRuntimeConfig) { config.MaxProbes = 0 },
		"max_probes_different": func(config *ProbeRuntimeConfig) { config.MaxProbes = 251 },
		"max_rss_zero":         func(config *ProbeRuntimeConfig) { config.MaxRSSMiB = 0 },
		"max_rss_negative":     func(config *ProbeRuntimeConfig) { config.MaxRSSMiB = -1 },
		"max_rss_different":    func(config *ProbeRuntimeConfig) { config.MaxRSSMiB = 257 },
		"max_fds_zero":         func(config *ProbeRuntimeConfig) { config.MaxFDs = 0 },
		"max_fds_negative":     func(config *ProbeRuntimeConfig) { config.MaxFDs = -1 },
		"max_fds_different":    func(config *ProbeRuntimeConfig) { config.MaxFDs = 2049 },
		"drain_zero":           func(config *ProbeRuntimeConfig) { config.DrainTimeout = 0 },
		"drain_negative":       func(config *ProbeRuntimeConfig) { config.DrainTimeout = -time.Second },
		"drain_different":      func(config *ProbeRuntimeConfig) { config.DrainTimeout = 24 * time.Second },
		"stop_zero":            func(config *ProbeRuntimeConfig) { config.StopTimeout = 0 },
		"stop_negative":        func(config *ProbeRuntimeConfig) { config.StopTimeout = -time.Second },
		"stop_different":       func(config *ProbeRuntimeConfig) { config.StopTimeout = 6 * time.Second },
		"readiness_zero":       func(config *ProbeRuntimeConfig) { config.ReadinessTimeout = 0 },
		"readiness_negative":   func(config *ProbeRuntimeConfig) { config.ReadinessTimeout = -time.Second },
		"readiness_different":  func(config *ProbeRuntimeConfig) { config.ReadinessTimeout = 59 * time.Second },
		"cleanup_zero":         func(config *ProbeRuntimeConfig) { config.CleanupTimeout = 0 },
		"cleanup_negative":     func(config *ProbeRuntimeConfig) { config.CleanupTimeout = -time.Second },
		"cleanup_different":    func(config *ProbeRuntimeConfig) { config.CleanupTimeout = 4 * time.Second },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := Defaults()
			mutate(&config.ProbeRuntime)
			if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "probe_runtime") {
				t.Fatalf("Validate error=%v, want probe_runtime boundary error", err)
			}
		})
	}
}

func TestProductionYAMLUsesFixedProbeRuntimeBoundary(t *testing.T) {
	loaded, err := Load(filepath.Join("..", "..", "config", "config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ProbeRuntime != Defaults().ProbeRuntime {
		t.Fatalf("production YAML probe runtime=%+v, want %+v", loaded.ProbeRuntime, Defaults().ProbeRuntime)
	}
}

func TestLoadRejectsProbeRuntimeBoundaryOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("probe_runtime:\n  max_probes: 500\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "probe_runtime.max_probes") {
		t.Fatalf("Load error=%v, want fixed max_probes boundary error", err)
	}
}

func TestRoutingAndGeoRulesOverridesAndValidation(t *testing.T) {
	t.Run("load valid overrides", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yml")
		body := `
routing:
  fail_policy: closed
  direct_suffixes: [".ru", ".by"]
  direct_domains: ["example.com", "custom.org"]
  geo_rules:
    enabled: true
    auto_update: true
    geoip_url: "https://example.com/geoip.dat"
    geosite_url: "https://example.com/geosite.dat"
    update_interval: 12h
`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		loaded, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(loaded.Routing.DirectSuffixes, []string{".ru", ".by"}) {
			t.Fatalf("suffixes = %v", loaded.Routing.DirectSuffixes)
		}
		if !reflect.DeepEqual(loaded.Routing.DirectDomains, []string{"example.com", "custom.org"}) {
			t.Fatalf("domains = %v", loaded.Routing.DirectDomains)
		}
		if !loaded.Routing.GeoRules.Enabled || !loaded.Routing.GeoRules.AutoUpdate ||
			loaded.Routing.GeoRules.GeoIPURL != "https://example.com/geoip.dat" ||
			loaded.Routing.GeoRules.GeoSiteURL != "https://example.com/geosite.dat" ||
			loaded.Routing.GeoRules.UpdateInterval != 12*time.Hour {
			t.Fatalf("geo_rules = %+v", loaded.Routing.GeoRules)
		}
	})

	t.Run("reject unknown routing field", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yml")
		if err := os.WriteFile(path, []byte("routing:\n  unknown: true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unknown") {
			t.Fatalf("expected unknown field error, got %v", err)
		}
	})

	t.Run("reject invalid direct suffix", func(t *testing.T) {
		tests := [][]string{
			{},
			{""},
			{"ru"},
			{"."},
		}
		for _, suffixes := range tests {
			cfg := Defaults()
			cfg.Routing.DirectSuffixes = suffixes
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected validation error for suffixes %v", suffixes)
			}
		}
	})

	t.Run("reject invalid direct domain", func(t *testing.T) {
		tests := [][]string{
			{""},
			{"https://example.com"},
			{"example.com/path"},
			{"example.com:8080"},
		}
		for _, domains := range tests {
			cfg := Defaults()
			cfg.Routing.DirectDomains = domains
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected validation error for domains %v", domains)
			}
		}
	})

	t.Run("reject invalid geo rules", func(t *testing.T) {
		tests := map[string]func(*GeoRulesConfig){
			"empty_geoip":       func(g *GeoRulesConfig) { g.GeoIPURL = "" },
			"invalid_geoip":     func(g *GeoRulesConfig) { g.GeoIPURL = "ftp://bad.com" },
			"empty_geosite":     func(g *GeoRulesConfig) { g.GeoSiteURL = "" },
			"invalid_geosite":   func(g *GeoRulesConfig) { g.GeoSiteURL = "not-a-url" },
			"negative_interval": func(g *GeoRulesConfig) { g.UpdateInterval = -time.Hour },
		}
		for name, mutate := range tests {
			t.Run(name, func(t *testing.T) {
				cfg := Defaults()
				mutate(&cfg.Routing.GeoRules)
				if err := cfg.Validate(); err == nil {
					t.Fatalf("expected error for %s", name)
				}
			})
		}
	})
}

func TestConfigurableProbesOverridesAndValidation(t *testing.T) {
	t.Run("load valid probe gate overrides", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yml")
		body := `
probes:
  gate_endpoints:
    youtube: "https://custom-yt.com/check"
    telegram: "https://custom-tg.org/status"
  custom_gates:
    - name: "my_api"
      url: "https://api.example.com/health"
      acceptable_statuses: [200, 204]
`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		loaded, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if loaded.Probes.GateEndpoints.YouTube != "https://custom-yt.com/check" ||
			loaded.Probes.GateEndpoints.Telegram != "https://custom-tg.org/status" ||
			loaded.Probes.GateEndpoints.ChatGPT != "https://chatgpt.com/" ||
			loaded.Probes.GateEndpoints.OpenAI != "https://api.openai.com/v1/models" {
			t.Fatalf("gate endpoints = %+v", loaded.Probes.GateEndpoints)
		}
		if len(loaded.Probes.CustomGates) != 1 ||
			loaded.Probes.CustomGates[0].Name != "my_api" ||
			loaded.Probes.CustomGates[0].URL != "https://api.example.com/health" ||
			!reflect.DeepEqual(loaded.Probes.CustomGates[0].AcceptableStatuses, []int{200, 204}) {
			t.Fatalf("custom gates = %+v", loaded.Probes.CustomGates)
		}
	})

	t.Run("reject invalid gate endpoints", func(t *testing.T) {
		cfg := Defaults()
		cfg.Probes.GateEndpoints.YouTube = "not-a-url"
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for invalid youtube url")
		}
	})

	t.Run("reject invalid custom gates", func(t *testing.T) {
		tests := map[string]CustomGateConfig{
			"empty_name":     {Name: "", URL: "https://ok.com"},
			"empty_url":      {Name: "gate", URL: ""},
			"invalid_url":    {Name: "gate", URL: "not-a-url"},
			"invalid_status": {Name: "gate", URL: "https://ok.com", AcceptableStatuses: []int{99}},
		}
		for name, gate := range tests {
			t.Run(name, func(t *testing.T) {
				cfg := Defaults()
				cfg.Probes.CustomGates = []CustomGateConfig{gate}
				if err := cfg.Validate(); err == nil {
					t.Fatalf("expected error for %s", name)
				}
			})
		}
	})

	t.Run("reject unknown field in gate_endpoints", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yml")
		body := "probes:\n  gate_endpoints:\n    unknown_field: https://example.com\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unknown_field") {
			t.Fatalf("expected unknown field error, got %v", err)
		}
	})

	t.Run("reject unknown field in custom_gates", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yml")
		body := "probes:\n  custom_gates:\n    - name: test\n      url: https://example.com\n      unknown_field: true\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unknown_field") {
			t.Fatalf("expected unknown field error, got %v", err)
		}
	})
}
