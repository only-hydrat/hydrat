package onion

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMapAddressAuthenticatesAndRequiresExactAcknowledgement(t *testing.T) {
	for _, response := range []string{"250 198.18.0.1=HOST\r\n", "451 resource exhausted\r\n", "250 198.18.0.2=HOST\r\n"} {
		t.Run(response[:3]+response[4:10], func(t *testing.T) {
			dir := t.TempDir()
			socket := filepath.Join(dir, "control")
			cookie := filepath.Join(dir, "cookie")
			if err := os.WriteFile(cookie, make([]byte, 32), 0600); err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			host := testHost(4)
			done := make(chan string, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err.Error()
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				reader := bufio.NewReader(conn)
				auth, _ := reader.ReadString('\n')
				if auth != "AUTHENTICATE "+strings.Repeat("00", 32)+"\r\n" {
					done <- "bad auth"
					return
				}
				conn.Write([]byte("250 OK\r\n"))
				command, _ := reader.ReadString('\n')
				if command != "MAPADDRESS 198.18.0.1="+host+"\r\n" {
					done <- "bad mapping"
					return
				}
				conn.Write([]byte(strings.ReplaceAll(response, "HOST", host)))
				done <- ""
			}()
			err = (Control{Socket: socket, CookieFile: cookie}).Map(context.Background(), "198.18.0.1", host)
			if (err == nil) != strings.HasPrefix(response, "250 198.18.0.1=") {
				t.Fatalf("unexpected result: %v", err)
			}
			if message := <-done; message != "" {
				t.Fatal(message)
			}
		})
	}
}

func TestMapAddressRejectsInputBeforeConnecting(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "198.18.0.1\r\nSIGNAL HALT"} {
		if err := (Control{}).Map(context.Background(), value, testHost(1)); err == nil {
			t.Fatal("accepted invalid address")
		}
	}
}

func TestReadinessWakesDormantTorBeforeWaitingForCircuit(t *testing.T) {
	dir := t.TempDir()
	cookie := filepath.Join(dir, "cookie")
	if err := os.WriteFile(cookie, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(dir, "control"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		r := bufio.NewReader(c)
		r.ReadString('\n')
		c.Write([]byte("250 OK\r\n"))
		cmd, _ := r.ReadString('\n')
		if cmd != "SIGNAL ACTIVE\r\n" {
			c.Write([]byte("250-status/circuit-established=0\r\n250 OK\r\n"))
			return
		}
		c.Write([]byte("250 OK\r\n"))
		cmd, _ = r.ReadString('\n')
		if cmd == "GETINFO status/circuit-established\r\n" {
			c.Write([]byte("250-status/circuit-established=1\r\n250 OK\r\n"))
		}
	}()
	if err := (Control{Socket: listener.Addr().String(), CookieFile: cookie}).Ready(t.Context()); err != nil {
		t.Fatal(err)
	}
}
