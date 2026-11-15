//go:build unix

package onion

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/only-hydrat/hydrat/internal/platform"
)

func (control Control) commands(ctx context.Context, commands [][2]string) error {
	file, err := os.Open(control.CookieFile)
	if err != nil {
		return errors.New("Tor authentication cookie unavailable")
	}
	cookie, readErr := io.ReadAll(io.LimitReader(file, 33))
	file.Close()
	if readErr != nil || len(cookie) != 32 {
		return errors.New("invalid Tor authentication cookie")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := platform.DialUnix(ctx, &net.Dialer{}, control.Socket)
	if err != nil {
		return errors.New("Tor control socket unavailable")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	reader := bufio.NewReaderSize(conn, 4096)
	exchange := func(command, expected string) error {
		if _, err := io.WriteString(conn, command+"\r\n"); err != nil {
			return errors.New("Tor control write failed")
		}
		for _, want := range strings.Split(expected, "\r\n") {
			line, err := reader.ReadSlice('\n')
			if err != nil || strings.TrimSuffix(string(line), "\r\n") != want {
				return errors.New("Tor control acknowledgement rejected")
			}
		}
		return nil
	}
	if err := exchange("AUTHENTICATE "+hex.EncodeToString(cookie), "250 OK"); err != nil {
		return err
	}
	for _, command := range commands {
		if err := exchange(command[0], command[1]); err != nil {
			return err
		}
	}
	return nil
}
