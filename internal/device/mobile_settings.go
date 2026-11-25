package device

import (
	"context"
	"time"
)

type MobileSettings struct {
	FastWorkers               int
	BackgroundWorkers         int
	MinVLESSScore             int
	BackgroundIntervalSeconds int
	SourceRefreshMinutes      int
	PauseOnScreenOff          bool
}

func (settings MobileSettings) Normalized() MobileSettings {
	settings.FastWorkers = mobileSetting(settings.FastWorkers, MobileFastProbeWorkers, 1, 8)
	settings.BackgroundWorkers = mobileSetting(settings.BackgroundWorkers, 4, 1, 8)
	settings.MinVLESSScore = mobileSetting(settings.MinVLESSScore, MobileMinVLESSScore, 50, 100)
	settings.BackgroundIntervalSeconds = mobileSetting(settings.BackgroundIntervalSeconds, 15, 15, 900)
	settings.SourceRefreshMinutes = mobileSetting(settings.SourceRefreshMinutes, 60, 15, 1440)
	return settings
}

func mobileSetting(value, fallback, minimum, maximum int) int {
	if value == 0 {
		return fallback
	}
	return min(max(value, minimum), maximum)
}

type SearchStatus struct {
	Mode    string
	Workers int
}

func (app *App) SetScreenInteractive(interactive bool) {
	app.screenInteractive.Store(interactive)
}

func (app *App) mobileRouteInstalled() bool {
	route := app.route.Load()
	return route != nil && (!route.BlockTCP && route.TCPOutbound != "" ||
		!route.BlockUDP && route.UDPOutbound != "")
}

func (app *App) mobileScreenOffServing() bool {
	return !app.screenInteractive.Load() && app.mobileRouteInstalled()
}

func (app *App) deferMobileQualification(now, last time.Time, recovery bool) bool {
	return !recovery && app.mobileScreenOffServing() && now.Sub(last) < time.Minute
}

// Keep checking reachability on an idle phone. User traffic, unlocking, or
// a missing route restores the normal cadence at the next scheduler tick.
func (app *App) mobileIdleProbes(
	lastTraffic func() time.Time,
	active, quality func(context.Context, time.Time) error,
) (func(context.Context, time.Time) error, func(context.Context, time.Time) error) {
	const idleAfter = 45 * time.Second
	const activeIdleInterval = 24 * time.Second
	idle := func(now time.Time) bool {
		return app.mobileScreenOffServing() && now.Sub(lastTraffic()) >= idleAfter
	}
	var lastActive time.Time
	return func(ctx context.Context, now time.Time) error {
			if idle(now) && now.Sub(lastActive) < activeIdleInterval {
				return nil
			}
			lastActive = now
			return active(ctx, now)
		}, func(ctx context.Context, now time.Time) error {
			if app.mobileScreenOffServing() {
				return nil
			}
			return quality(ctx, now)
		}
}

// Only the qualification worker invokes this callback. Confirmed route
// failures use the ordinary recovery path outside the background throttle.
func (app *App) mobileBackgroundMode(settings MobileSettings) func(time.Time) string {
	var next time.Time
	return func(now time.Time) string {
		if settings.PauseOnScreenOff && !app.screenInteractive.Load() {
			return "paused"
		}
		if now.Before(next) {
			return "waiting"
		}
		next = now.Add(time.Duration(settings.BackgroundIntervalSeconds) * time.Second)
		return "background"
	}
}
