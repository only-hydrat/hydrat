package onion

import (
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type Listener struct {
	tcp         net.Listener
	udp         net.PacketConn
	cancel      context.CancelFunc
	once        sync.Once
	workers     sync.WaitGroup
	connections chan struct{}
	ordinary    chan struct{}
	onion       chan struct{}
	i2p         chan struct{}
}

func Listen(parent context.Context, address string, handler DNS) (*Listener, error) {
	tcp, err := net.Listen("tcp4", address)
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Listener{tcp: tcp, udp: udp, cancel: cancel, connections: make(chan struct{}, 64), ordinary: make(chan struct{}, 128), onion: make(chan struct{}, 8), i2p: make(chan struct{}, 8)}
	context.AfterFunc(ctx, func() { tcp.Close(); udp.Close() })
	s.workers.Add(2)
	go func() {
		defer s.workers.Done()
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			select {
			case s.connections <- struct{}{}:
			default:
				c.Close()
				continue
			}
			s.workers.Add(1)
			go func() {
				defer s.workers.Done()
				defer func() { <-s.connections }()
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				source, _ := netip.ParseAddrPort(c.RemoteAddr().String())
				for count := 0; count < 1024; count++ {
					c.SetDeadline(time.Now().Add(5 * time.Second))
					var prefix [2]byte
					if _, err := io.ReadFull(c, prefix[:]); err != nil {
						return
					}
					n := binary.BigEndian.Uint16(prefix[:])
					if n < 12 {
						return
					}
					packet := make([]byte, n)
					if _, err := io.ReadFull(c, packet); err != nil {
						return
					}
					reply := s.query(ctx, handler, source.Addr(), packet)
					if len(reply) == 0 {
						return
					}
					binary.BigEndian.PutUint16(prefix[:], uint16(len(reply)))
					if _, err := c.Write(append(prefix[:], reply...)); err != nil {
						return
					}
				}
			}()
		}
	}()
	go func() {
		defer s.workers.Done()
		buffer := make([]byte, 65535)
		for {
			n, remote, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			packet := append([]byte(nil), buffer[:n]...)
			source, _ := netip.ParseAddrPort(remote.String())
			budget := s.budget(packet)
			select {
			case budget <- struct{}{}:
			default:
				continue
			}
			s.workers.Add(1)
			go func() {
				defer s.workers.Done()
				defer func() { <-budget }()
				queryCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
				defer cancel()
				reply, err := handler.Handle(queryCtx, source.Addr(), packet)
				if err == nil && len(reply) > 0 {
					udp.WriteTo(udpReply(packet, reply), remote)
				}
			}()
		}
	}()
	return s, nil
}

func (s *Listener) budget(packet []byte) chan struct{} {
	var message dnsmessage.Message
	if message.Unpack(packet) == nil {
		for _, q := range message.Questions {
			name := strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")
			if name == "i2p" || strings.HasSuffix(name, ".i2p") {
				return s.i2p
			}
			if name == "onion" || strings.HasSuffix(name, ".onion") {
				return s.onion
			}
		}
	}
	return s.ordinary
}
func (s *Listener) query(ctx context.Context, h DNS, source netip.Addr, p []byte) []byte {
	budget := s.budget(p)
	select {
	case budget <- struct{}{}:
		defer func() { <-budget }()
	default:
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	reply, _ := h.Handle(ctx, source, p)
	return reply
}
func (s *Listener) Addr() string { return s.tcp.Addr().String() }
func (s *Listener) Close() {
	s.once.Do(func() { s.cancel(); s.tcp.Close(); s.udp.Close(); s.workers.Wait() })
}

// Forward preserves the ordinary resolver's UDP path, retrying over TCP only
// when the response is truncated. Both attempts share one deadline. Packets
// are forwarded unchanged, including EDNS and DNSSEC fields.
func Forward(address string) func(context.Context, []byte) ([]byte, error) {
	return func(ctx context.Context, p []byte) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		c, err := (&net.Dialer{}).DialContext(ctx, "udp4", address)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		stop := context.AfterFunc(ctx, func() { c.Close() })
		defer stop()
		deadline, _ := ctx.Deadline()
		c.SetDeadline(deadline)
		if _, err := c.Write(p); err != nil {
			return nil, err
		}
		buffer := make([]byte, 65535)
		for {
			n, err := c.Read(buffer)
			if err != nil {
				return nil, err
			}
			response := buffer[:n]
			header, valid := matchingDNSResponse(p, response)
			if !valid {
				continue
			}
			if header.Truncated {
				return forwardTCP(address)(ctx, p)
			}
			return response, nil
		}
	}
}

func matchingDNSResponse(query, response []byte) (dnsmessage.Header, bool) {
	var q, r dnsmessage.Parser
	qh, err := q.Start(query)
	if err != nil {
		return dnsmessage.Header{}, false
	}
	rh, err := r.Start(response)
	if err != nil || !rh.Response || rh.ID != qh.ID || rh.OpCode != qh.OpCode {
		return rh, false
	}
	qq, err := q.AllQuestions()
	if err != nil {
		return rh, false
	}
	rq, err := r.AllQuestions()
	if err != nil || len(qq) != len(rq) {
		return rh, false
	}
	for i := range qq {
		if qq[i].Type != rq[i].Type || qq[i].Class != rq[i].Class ||
			!strings.EqualFold(qq[i].Name.String(), rq[i].Name.String()) {
			return rh, false
		}
	}
	return rh, true
}

func forwardTCP(address string) func(context.Context, []byte) ([]byte, error) {
	return func(ctx context.Context, p []byte) ([]byte, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp4", address)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		stop := context.AfterFunc(ctx, func() { c.Close() })
		defer stop()
		deadline := time.Now().Add(3 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		c.SetDeadline(deadline)
		prefix := []byte{byte(len(p) >> 8), byte(len(p))}
		if _, err := c.Write(append(prefix, p...)); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(c, prefix); err != nil {
			return nil, err
		}
		response := make([]byte, binary.BigEndian.Uint16(prefix))
		_, err = io.ReadFull(c, response)
		if err == nil {
			if _, valid := matchingDNSResponse(p, response); !valid {
				return nil, errors.New("mismatched DNS response")
			}
		}
		return response, err
	}
}

// TCP forwarding must not accidentally produce fragmented UDP replies. Retain
// the caller's EDNS allowance (capped to 1232) and signal a TCP retry when needed.
func udpReply(query, reply []byte) []byte {
	limit := 512
	var q dnsmessage.Message
	if q.Unpack(query) == nil {
		for _, rr := range q.Additionals {
			if rr.Header.Type == dnsmessage.TypeOPT {
				limit = max(512, min(1232, int(rr.Header.Class)))
				break
			}
		}
	}
	if len(reply) <= limit {
		return reply
	}
	var r dnsmessage.Message
	if r.Unpack(reply) != nil {
		return nil
	}
	r.Truncated = true
	r.Answers = nil
	r.Authorities = nil
	r.Additionals = nil
	b, err := r.Pack()
	if err != nil || len(b) > limit {
		return nil
	}
	return b
}
