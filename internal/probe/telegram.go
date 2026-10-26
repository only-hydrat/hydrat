package probe

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/only-hydrat/hydrat/internal/qoe"
	"github.com/only-hydrat/hydrat/internal/socks5"
)

// Keep the endpoint and both transport identities fixed across candidates so
// routed controls test the same service. Changing these requires a policy bump.
const telegramTransportAddress = "149.154.162.123:443"

// CheckTelegramTransports makes unauthenticated req_pq_multi exchanges through
// the candidate, never directly from the host. It runs at QoE cadence only.
func CheckTelegramTransports(ctx context.Context, socksAddress string) []qoe.HTTPCheck {
	return checkTelegramTransports(ctx, socks5.Dialer{ProxyAddress: socksAddress}, socksAddress)
}

func checkTelegramTransports(ctx context.Context, dialer ContextDialer, socksAddress string) []qoe.HTTPCheck {
	checks := make([]qoe.HTTPCheck, 2)
	done := make(chan int, 2)
	for i, service := range []string{"telegram_obfuscated", "telegram_padded"} {
		go func() {
			started := time.Now()
			shortened := false
			if deadline, ok := ctx.Deadline(); ok {
				shortened = time.Until(deadline) < applicationGateDeadline-50*time.Millisecond
			}
			check := qoe.HTTPCheck{Service: service, Path: "route", Phase: "body", Code: "ok", OK: true}
			err := checkTelegramObfuscated(ctx, dialer, telegramTransportAddress, i == 1)
			check.ElapsedMS = time.Since(started).Milliseconds()
			if err != nil {
				check.OK = false
				check.Code = "body"
				var netErr net.Error
				switch {
				case errors.Is(ctx.Err(), context.Canceled):
					check.Code = "canceled"
				case localSOCKSDialFailure(err, socksAddress):
					check.Code = "invalid_request"
				case errors.As(err, &netErr) && netErr.Timeout(), errors.Is(err, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
					check.Code = "timeout"
					if shortened {
						check.Code = "budget_exhausted"
					}
				case errors.As(err, &netErr):
					check.Code = "transport"
				}
			}
			checks[i] = check
			done <- i
		}()
	}
	// Join both requests before the caller releases/reconfigures its probe slot.
	<-done
	<-done
	return checks
}

func checkTelegramObfuscated(ctx context.Context, dialer ContextDialer, address string, padded bool) error {
	ctx, cancel := context.WithTimeout(ctx, applicationGateDeadline)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}

	// Telegram obfuscated2: client stream consumes the full 64-byte header;
	// the independent server stream starts at counter zero with reversed keys.
	// See Telethon network/connection/tcpobfuscated.py and tcpintermediate.py.
	header := make([]byte, 64)
	for {
		if _, err := rand.Read(header); err != nil {
			return err
		}
		prefix := string(header[:4])
		if header[0] != 0xef && prefix != "PVrG" && prefix != "GET " && prefix != "POST" && prefix != "\xee\xee\xee\xee" && binary.LittleEndian.Uint32(header[4:8]) != 0 {
			break
		}
	}
	block, err := aes.NewCipher(header[8:40])
	if err != nil {
		return err
	}
	encrypt := cipher.NewCTR(block, header[40:56])
	reverse := make([]byte, 48)
	for i := range reverse {
		reverse[i] = header[55-i]
	}
	block, err = aes.NewCipher(reverse[:32])
	if err != nil {
		return err
	}
	decrypt := cipher.NewCTR(block, reverse[32:])
	marker := byte(0xef)
	if padded {
		marker = 0xdd
	}
	for i := 56; i < 60; i++ {
		header[i] = marker
	}
	encryptedHeader := make([]byte, 64)
	encrypt.XORKeyStream(encryptedHeader, header)
	copy(header[56:64], encryptedHeader[56:64])
	if err := writeFull(conn, header); err != nil {
		return err
	}

	payload := make([]byte, 40)
	binary.LittleEndian.PutUint64(payload[8:16], uint64(time.Now().Unix())<<32)
	binary.LittleEndian.PutUint32(payload[16:20], 20)
	binary.LittleEndian.PutUint32(payload[20:24], reqPQMultiConstructor)
	if _, err := rand.Read(payload[24:40]); err != nil {
		return err
	}
	frame := []byte{byte(len(payload) / 4)}
	if padded {
		var padding [4]byte
		if _, err := rand.Read(padding[:]); err != nil {
			return err
		}
		payload = append(payload, padding[1:1+int(padding[0]&3)]...)
		frame = make([]byte, 4)
		binary.LittleEndian.PutUint32(frame, uint32(len(payload)))
	}
	frame = append(frame, payload...)
	encrypt.XORKeyStream(frame, frame)
	if err := writeFull(conn, frame); err != nil {
		return err
	}
	reader := &cipher.StreamReader{S: decrypt, R: conn}
	var size int
	if padded {
		var length [4]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return err
		}
		size = int(binary.LittleEndian.Uint32(length[:]))
	} else {
		words, err := readAbridgedLength(reader)
		if err != nil {
			return err
		}
		size = words * 4
	}
	if size < 40 || size > 256*1024 {
		return fmt.Errorf("invalid obfuscated MTProto frame length %d", size)
	}
	response := make([]byte, size)
	if _, err := io.ReadFull(reader, response); err != nil {
		return err
	}
	bodyLength := int(binary.LittleEndian.Uint32(response[16:20]))
	if binary.LittleEndian.Uint64(response[:8]) != 0 || bodyLength < 20 || bodyLength%4 != 0 || bodyLength > len(response)-20 || binary.LittleEndian.Uint32(response[20:24]) != resPQConstructor {
		return errors.New("invalid obfuscated MTProto resPQ")
	}
	if string(response[24:40]) != string(payload[24:40]) {
		return errors.New("obfuscated MTProto nonce mismatch")
	}
	return nil
}
