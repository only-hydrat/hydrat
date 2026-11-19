package main

import (
	"context"
	"errors"
	"flag"
	"os/signal"
	"strings"
	"syscall"

	"github.com/only-hydrat/hydrat/internal/update"
)

func runUpdater(args []string) error {
	flags := flag.NewFlagSet("updater", flag.ContinueOnError)
	var files string
	var cfg update.HostConfig
	flags.StringVar(&cfg.ProjectDir, "project", "", "Compose project directory")
	flags.StringVar(&files, "files", "docker-compose.yml,docker-compose.updates.yml", "ordered list of trusted Compose files")
	flags.StringVar(&cfg.StateDir, "state", "/var/lib/hydrat-updates", "private updater state directory")
	flags.IntVar(&cfg.SocketGID, "socket-gid", 10001, "group allowed to connect to the updater")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected updater arguments")
	}
	cfg.Files = strings.Split(files, ",")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return update.ServeHost(ctx, cfg)
}
