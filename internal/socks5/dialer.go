package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

type DialContextFunc func(context.Context, string, string) (net.Conn, error)

type Dialer struct {
	ProxyAddress string
	Username     string
	Password     string
	Dial         DialContextFunc
}

func (dialer Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, fmt.Errorf("SOCKS5 dialer only supports TCP, got %s", network)
	}
	connection, err := dialer.open(ctx)
	if err != nil {
		return nil, err
	}
	stopClose := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopClose()
	failed := true
	defer func() {
		if failed {
			_ = connection.Close()
		}
	}()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid target port")
	}
	request := []byte{5, 1, 0}
	request, err = appendAddress(request, host, port)
	if err != nil {
		return nil, err
	}
	if _, err := connection.Write(request); err != nil {
		return nil, err
	}
	var header [4]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return nil, err
	}
	if header[0] != 5 || header[1] != 0 {
		return nil, fmt.Errorf("SOCKS5 connect failed with code %d", header[1])
	}
	if err := discardAddress(connection, header[3]); err != nil {
		return nil, err
	}
	if !stopClose() {
		return nil, ctx.Err()
	}
	_ = connection.SetDeadline(time.Time{})
	failed = false
	return connection, nil
}

func (dialer Dialer) open(ctx context.Context) (net.Conn, error) {
	if dialer.ProxyAddress == "" {
		return nil, errors.New("SOCKS5 proxy address is required")
	}
	dial := dialer.Dial
	if dial == nil {
		netDialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
		dial = netDialer.DialContext
	}
	connection, err := dial(ctx, "tcp", dialer.ProxyAddress)
	if err != nil {
		return nil, err
	}
	stopClose := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopClose()
	failed := true
	defer func() {
		if failed {
			_ = connection.Close()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	_ = connection.SetDeadline(deadline)
	methods := []byte{0}
	if dialer.Username != "" || dialer.Password != "" {
		methods = []byte{0, 2}
	}
	hello := append([]byte{5, byte(len(methods))}, methods...)
	if _, err := connection.Write(hello); err != nil {
		return nil, err
	}
	var response [2]byte
	if _, err := io.ReadFull(connection, response[:]); err != nil {
		return nil, err
	}
	if response[0] != 5 || response[1] == 0xff {
		return nil, errors.New("SOCKS5 proxy rejected authentication methods")
	}
	if response[1] == 2 {
		if len(dialer.Username) > 255 || len(dialer.Password) > 255 {
			return nil, errors.New("SOCKS5 credentials are too long")
		}
		auth := []byte{1, byte(len(dialer.Username))}
		auth = append(auth, dialer.Username...)
		auth = append(auth, byte(len(dialer.Password)))
		auth = append(auth, dialer.Password...)
		if _, err := connection.Write(auth); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(connection, response[:]); err != nil || response[1] != 0 {
			return nil, errors.New("SOCKS5 username/password authentication failed")
		}
	} else if response[1] != 0 {
		return nil, fmt.Errorf("unsupported SOCKS5 authentication method %d", response[1])
	}
	if !stopClose() {
		return nil, ctx.Err()
	}
	failed = false
	return connection, nil
}

// ListenPacket establishes one RFC 1928 UDP association through the proxy.
// The returned PacketConn accepts ordinary destination addresses and owns both
// the UDP relay socket and its required TCP control connection.
func (dialer Dialer) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	control, err := dialer.open(ctx)
	if err != nil {
		return nil, err
	}
	stopClose := context.AfterFunc(ctx, func() { _ = control.Close() })
	defer stopClose()
	failed := true
	defer func() {
		if failed {
			_ = control.Close()
		}
	}()
	request, err := appendAddress([]byte{5, 3, 0}, "0.0.0.0", 0)
	if err != nil {
		return nil, err
	}
	if _, err := control.Write(request); err != nil {
		return nil, err
	}
	var header [4]byte
	if _, err := io.ReadFull(control, header[:]); err != nil {
		return nil, err
	}
	if header[0] != 5 || header[1] != 0 {
		return nil, fmt.Errorf("SOCKS5 UDP associate failed with code %d", header[1])
	}
	relayHost, relayPort, err := readAddress(control, header[3])
	if err != nil {
		return nil, err
	}
	proxyHost, _, splitErr := net.SplitHostPort(dialer.ProxyAddress)
	if splitErr != nil {
		return nil, splitErr
	}
	if relayHost == "0.0.0.0" || relayHost == "::" {
		relayHost = proxyHost
	}
	relay, err := net.ResolveUDPAddr("udp", net.JoinHostPort(relayHost, strconv.Itoa(relayPort)))
	if err != nil {
		return nil, err
	}
	packet, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		return nil, err
	}
	if !stopClose() {
		_ = packet.Close()
		return nil, ctx.Err()
	}
	_ = control.SetDeadline(time.Time{})
	failed = false
	return &udpPacketConn{packet: packet, control: control}, nil
}

type udpPacketConn struct {
	packet  *net.UDPConn
	control net.Conn
	once    sync.Once
	err     error
}

func (connection *udpPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	framed := make([]byte, len(payload)+262)
	count, err := connection.packet.Read(framed)
	if err != nil {
		return 0, nil, err
	}
	if count < 4 || framed[0] != 0 || framed[1] != 0 || framed[2] != 0 {
		return 0, nil, errors.New("invalid SOCKS5 UDP response")
	}
	reader := bytes.NewReader(framed[4:count])
	host, port, err := readAddress(reader, framed[3])
	if err != nil {
		return 0, nil, err
	}
	dataOffset := count - reader.Len()
	data := framed[dataOffset:count]
	if len(data) > len(payload) {
		return 0, nil, io.ErrShortBuffer
	}
	copy(payload, data)
	return len(data), &net.UDPAddr{IP: net.ParseIP(host), Port: port}, nil
}

func (connection *udpPacketConn) WriteTo(payload []byte, target net.Addr) (int, error) {
	host, portText, err := net.SplitHostPort(target.String())
	if err != nil {
		return 0, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("invalid UDP target port")
	}
	framed, err := appendAddress([]byte{0, 0, 0}, host, port)
	if err != nil {
		return 0, err
	}
	framed = append(framed, payload...)
	if _, err := connection.packet.Write(framed); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (connection *udpPacketConn) Close() error {
	connection.once.Do(func() {
		connection.err = errors.Join(connection.packet.Close(), connection.control.Close())
	})
	return connection.err
}

func (connection *udpPacketConn) LocalAddr() net.Addr { return connection.packet.LocalAddr() }
func (connection *udpPacketConn) SetDeadline(value time.Time) error {
	return connection.packet.SetDeadline(value)
}
func (connection *udpPacketConn) SetReadDeadline(value time.Time) error {
	return connection.packet.SetReadDeadline(value)
}
func (connection *udpPacketConn) SetWriteDeadline(value time.Time) error {
	return connection.packet.SetWriteDeadline(value)
}
func (connection *udpPacketConn) SetReadBuffer(bytes int) error {
	return connection.packet.SetReadBuffer(bytes)
}
func (connection *udpPacketConn) SetWriteBuffer(bytes int) error {
	return connection.packet.SetWriteBuffer(bytes)
}

func appendAddress(target []byte, host string, port int) ([]byte, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			target = append(target, 1)
			target = append(target, ipv4...)
		} else {
			target = append(target, 4)
			target = append(target, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("invalid target hostname")
		}
		target = append(target, 3, byte(len(host)))
		target = append(target, host...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	return append(target, portBytes[:]...), nil
}

func discardAddress(reader io.Reader, addressType byte) error {
	_, _, err := readAddress(reader, addressType)
	return err
}

func readAddress(reader io.Reader, addressType byte) (string, int, error) {
	var host string
	switch addressType {
	case 1:
		value := make([]byte, 4)
		if _, err := io.ReadFull(reader, value); err != nil {
			return "", 0, err
		}
		host = net.IP(value).String()
	case 4:
		value := make([]byte, 16)
		if _, err := io.ReadFull(reader, value); err != nil {
			return "", 0, err
		}
		host = net.IP(value).String()
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(reader, size[:]); err != nil {
			return "", 0, err
		}
		value := make([]byte, int(size[0]))
		if _, err := io.ReadFull(reader, value); err != nil {
			return "", 0, err
		}
		host = string(value)
	default:
		return "", 0, errors.New("invalid SOCKS5 address type")
	}
	var port [2]byte
	if _, err := io.ReadFull(reader, port[:]); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(port[:])), nil
}
