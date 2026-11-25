//go:build linux && !android

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/only-hydrat/hydrat/internal/device"
)

const defaultSocket = "/run/hydrat-app/control.sock"

func serve(ctx context.Context, app *device.App, options device.ProcessOptions, socket string) error {
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(socket, 0660); err != nil {
		return err
	}
	control := device.NewControl(ctx, app, func(session context.Context) error {
		return app.ConnectLinux(session, options)
	})
	server := &http.Server{Handler: control, ReadHeaderTimeout: 3 * time.Second, IdleTimeout: 20 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		return errors.Join(err, closeControl(control))
	case <-ctx.Done():
	}
	timeout, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = server.Shutdown(timeout)
	if err != nil {
		err = errors.Join(err, server.Close())
	}
	return errors.Join(err, closeControl(control))
}

func closeControl(control *device.Control) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return control.Close(ctx)
}

func requestControl(ctx context.Context, socket, command string, input io.Reader, output io.Writer) error {
	method, path := http.MethodGet, "/status"
	var body io.Reader
	switch command {
	case "connect":
		method, path = http.MethodPost, "/connection"
	case "disconnect":
		method, path = http.MethodDelete, "/connection"
	case "import":
		method, path = http.MethodPost, "/sources"
		body = io.LimitReader(input, maxInput+1)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://local"+path, body)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return fmt.Errorf("local service %s: %s", response.Status, message)
	}
	_, err = io.Copy(output, response.Body)
	return err
}
