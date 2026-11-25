//go:build linux && !android

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/only-hydrat/hydrat/internal/device"
)

const maxInput = 4 * 1024 * 1024

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: hydrat-device daemon|import|connect|disconnect|status [options]")
	}
	command := args[0]
	switch command {
	case "daemon", "import", "connect", "disconnect", "status":
	default:
		return errors.New("unknown hydrat-device operation")
	}
	settings, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(output)
	socket := flags.String("socket", defaultSocket, "private local service socket")
	state := flags.String("state", filepath.Join(settings, "hydrat-app"), "private local state directory")
	var processes device.ProcessOptions
	if command == "daemon" {
		flags.StringVar(&processes.Xray, "xray", "xray", "Hydrat-compatible Xray binary")
		flags.StringVar(&processes.Tor, "tor", "tor", "Tor binary")
		flags.StringVar(&processes.Lyrebird, "lyrebird", "lyrebird", "Lyrebird binary")
		flags.StringVar(&processes.RuntimeDirectory, "runtime", "", "directory for private runtime sockets")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("subscription links are read from stdin")
	}
	if command != "daemon" && (command != "import" || !hasStateFlag(flags)) {
		return requestControl(ctx, *socket, command, input, output)
	}
	app, err := device.Open(ctx, *state)
	if err != nil {
		return err
	}
	defer app.Close()
	if command == "daemon" {
		return serve(ctx, app, processes, *socket)
	}
	raw, err := io.ReadAll(io.LimitReader(input, maxInput+1))
	if err != nil {
		return err
	}
	report, err := app.Import(ctx, string(raw))
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(report)
}

func hasStateFlag(flags *flag.FlagSet) bool {
	found := false
	flags.Visit(func(option *flag.Flag) { found = found || option.Name == "state" })
	return found
}
