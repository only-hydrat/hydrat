package probe

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// The fixture acts as a Telegram server: decrypt the wire header and request,
// validate req_pq_multi, then encrypt a response with the reverse-direction key.
func telegramFixture(t *testing.T, padded bool, responseKind string) ContextDialer {
	t.Helper()
	return dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "149.154.162.123:443" {
			return nil, fmt.Errorf("unexpected target %s %s", network, address)
		}
		client, server := net.Pipe()
		done := make(chan error, 1)
		go func() {
			defer server.Close()
			done <- serveTelegramFixture(server, padded, responseKind)
		}()
		t.Cleanup(func() {
			client.Close()
			if err := <-done; err != nil {
				t.Error(err)
			}
		})
		return client, nil
	})
}

func serveTelegramFixture(conn net.Conn, padded bool, kind string) error {
	var header [64]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	block, _ := aes.NewCipher(header[8:40])
	decrypt := cipher.NewCTR(block, header[40:56])
	decoded := make([]byte, 64)
	decrypt.XORKeyStream(decoded, header[:])
	marker := byte(0xef)
	if padded {
		marker = 0xdd
	}
	if !bytes.Equal(decoded[56:60], bytes.Repeat([]byte{marker}, 4)) {
		return errors.New("wrong obfuscation marker")
	}
	reversed := make([]byte, 48)
	for i := range reversed {
		reversed[i] = header[55-i]
	}
	replyBlock, _ := aes.NewCipher(reversed[:32])
	encrypt := cipher.NewCTR(replyBlock, reversed[32:])
	reader := &cipher.StreamReader{S: decrypt, R: conn}
	length := 0
	if padded {
		var size [4]byte
		if _, err := io.ReadFull(reader, size[:]); err != nil {
			return err
		}
		length = int(binary.LittleEndian.Uint32(size[:]))
	} else {
		var size [1]byte
		if _, err := io.ReadFull(reader, size[:]); err != nil {
			return err
		}
		length = int(size[0]) * 4
	}
	if length < 40 || length > 43 {
		return fmt.Errorf("invalid req_pq frame %d", length)
	}
	request := make([]byte, length)
	if _, err := io.ReadFull(reader, request); err != nil {
		return err
	}
	if binary.LittleEndian.Uint64(request[:8]) != 0 || binary.LittleEndian.Uint32(request[16:20]) != 20 || binary.LittleEndian.Uint32(request[20:24]) != reqPQMultiConstructor {
		return errors.New("not an unauthenticated req_pq_multi")
	}
	if kind == "stall" {
		_, err := conn.Read(make([]byte, 1))
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("connection not closed on cancellation: %v", err)
	}
	response := make([]byte, 40)
	binary.LittleEndian.PutUint32(response[16:20], 20)
	binary.LittleEndian.PutUint32(response[20:24], resPQConstructor)
	copy(response[24:40], request[24:40])
	switch kind {
	case "nonce":
		response[24] ^= 1
	case "constructor":
		response[20] ^= 1
	case "auth":
		response[0] = 1
	case "body_length":
		binary.LittleEndian.PutUint32(response[16:20], 1000)
	}
	var frame []byte
	if padded {
		response = append(response, 1, 2, 3)
		frame = make([]byte, 4)
		binary.LittleEndian.PutUint32(frame, uint32(len(response)))
	} else {
		frame = []byte{byte(len(response) / 4)}
	}
	if kind == "oversized" {
		if padded {
			binary.LittleEndian.PutUint32(frame, 0x7fffffff)
		} else {
			frame = []byte{0x7f, 0xff, 0xff, 0x7f}
		}
	} else {
		frame = append(frame, response...)
	}
	if kind == "truncated" {
		frame = frame[:len(frame)-10]
	}
	encrypt.XORKeyStream(frame, frame)
	// A rejected size may close the pipe before the rest is written.
	_, err := conn.Write(frame)
	if kind == "oversized" && errors.Is(err, io.ErrClosedPipe) {
		return nil
	}
	return err
}

func TestTelegramObfuscatedWireAndValidation(t *testing.T) {
	for _, padded := range []bool{false, true} {
		for _, kind := range []string{"valid", "nonce", "constructor", "auth", "body_length", "oversized", "truncated"} {
			t.Run(fmt.Sprintf("padded_%t/%s", padded, kind), func(t *testing.T) {
				err := checkTelegramObfuscated(context.Background(), telegramFixture(t, padded, kind), "149.154.162.123:443", padded)
				if (err == nil) != (kind == "valid") {
					t.Fatalf("error=%v, kind=%s", err, kind)
				}
			})
		}
	}
}

func TestTelegramObfuscatedCancellationClosesSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialer := telegramFixture(t, true, "stall")
	// Cancel only once the handshake has been written and the server is reading.
	timer := time.AfterFunc(30*time.Millisecond, cancel)
	defer timer.Stop()
	started := time.Now()
	err := checkTelegramObfuscated(ctx, dialer, "149.154.162.123:443", true)
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("cancellation err=%v elapsed=%s", err, time.Since(started))
	}
}

func TestTelegramTransportShortBudgetAndCancellationAreNeutral(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		if canceled {
			cancel()
		}
		dialer := dialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() })
		checks := checkTelegramTransports(ctx, dialer, "socks")
		cancel()
		want := "budget_exhausted"
		if canceled {
			want = "canceled"
		}
		if len(checks) != 2 {
			t.Fatalf("checks=%+v", checks)
		}
		for _, check := range checks {
			if check.OK || check.Code != want {
				t.Fatalf("checks=%+v want=%s", checks, want)
			}
		}
	}
}

func TestTelegramTransportLocalProxyFailureIsNeutral(t *testing.T) {
	dialer := dialFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}, Err: errors.New("listener unavailable")}
	})
	for _, check := range checkTelegramTransports(context.Background(), dialer, "127.0.0.1:1080") {
		if check.OK || check.Code != "invalid_request" {
			t.Fatalf("local listener blamed on route: %+v", check)
		}
	}
}
