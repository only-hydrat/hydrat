//go:build linux && !android

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/only-hydrat/hydrat/app/native/xraycore"
	"github.com/only-hydrat/hydrat/internal/device"
	"github.com/only-hydrat/hydrat/internal/xrayflow"
)

func main() {
	state := flag.String("state", "/var/lib/hydrat-app", "private state directory")
	runtime := flag.String("runtime", "/run/hydrat-app", "control socket directory")
	bundle := flag.String("bundle", "/usr/lib/hydrat-app", "installed runtime directory")
	check := flag.Bool("check", false, "verify the installed runtime files")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected positional argument")
	}
	if err := checkBundle(*bundle); err != nil {
		log.Fatal(err)
	}
	if *check {
		fmt.Println("Hydrat Linux bundle OK")
		return
	}
	if os.Geteuid() == 0 {
		log.Fatal("start Hydrat with the packaged hydrat-app system service")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := serve(ctx, *state, *runtime, *bundle); err != nil {
		log.Fatal(err)
	}
}

func checkBundle(bundle string) error {
	for _, name := range []string{"tor-runtime", "tor/tor", "tor/pluggable_transports/lyrebird", "geo/geoip.dat", "geo/geosite.dat"} {
		info, err := os.Stat(filepath.Join(bundle, name))
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("missing runtime file %s", name)
		}
	}
	return nil
}

func serve(ctx context.Context, state, runtime, bundle string) error {
	private := filepath.Join(runtime, "private")
	if err := os.Mkdir(private, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	flow := filepath.Join(private, "f.sock")
	if err := os.Setenv(xrayflow.SocketEnvironment, flow); err != nil {
		return err
	}
	app, err := device.OpenMobile(ctx, state)
	if err != nil {
		return err
	}
	defer app.Close()
	prefs, err := openPreferences(state, filepath.Join(bundle, "geo"), app)
	if err != nil {
		return err
	}
	options := device.ProcessOptions{
		Embedded: xraycore.Host{}, FlowSocket: flow, Tor: filepath.Join(bundle, "tor-runtime"),
		Lyrebird: filepath.Join(bundle, "tor", "pluggable_transports", "lyrebird"), RuntimeDirectory: private,
	}
	control := device.NewControl(ctx, app, func(session context.Context) error {
		settings, sessionOptions, release, err := prefs.tunnelOptions(options)
		if err != nil {
			return err
		}
		defer release()
		return app.ConnectLinuxSingleDevice(session, sessionOptions, settings)
	})
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if err := control.Close(cleanup); err != nil {
			log.Printf("tunnel shutdown: %v", err)
		}
	}()
	socket := filepath.Join(runtime, "control.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(socket, 0660); err != nil {
		return err
	}
	server := &http.Server{
		Handler: newDesktopAPI(app, control, prefs), ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout: 8 * time.Second, WriteTimeout: 100 * time.Second, IdleTimeout: 10 * time.Second,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			return errors.Join(err, server.Close())
		}
		return nil
	}
}
