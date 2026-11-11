package onion

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestForwardOrdinaryDNSUsesUDPThenTCPOnlyOnTruncation(t *testing.T) {
	for _, truncated := range []bool{false, true} {
		t.Run(map[bool]string{false: "UDP-only resolver", true: "TCP fallback"}[truncated], func(t *testing.T) {
			udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			query := dnsmessage.Message{Header: dnsmessage.Header{ID: 123, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("example.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}, Additionals: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 1232, TTL: 32768}, Body: &dnsmessage.OPTResource{}}}}
			packet, err := query.Pack()
			if err != nil {
				t.Fatal(err)
			}
			query.Response = true
			answer, _ := query.Pack()
			query.Truncated = truncated
			udpAnswer, _ := query.Pack()
			udpSeen := make(chan []byte, 1)
			go func() {
				b := make([]byte, 65535)
				n, peer, e := udp.ReadFrom(b)
				if e != nil {
					return
				}
				udpSeen <- append([]byte(nil), b[:n]...)
				udp.WriteTo(udpAnswer, peer)
			}()
			tcpSeen := make(chan []byte, 1)
			if truncated {
				tcp, e := net.Listen("tcp4", udp.LocalAddr().String())
				if e != nil {
					t.Fatal(e)
				}
				defer tcp.Close()
				go func() {
					c, e := tcp.Accept()
					if e != nil {
						return
					}
					defer c.Close()
					c.SetDeadline(time.Now().Add(time.Second))
					var prefix [2]byte
					if _, e := io.ReadFull(c, prefix[:]); e != nil {
						return
					}
					b := make([]byte, binary.BigEndian.Uint16(prefix[:]))
					if _, e := io.ReadFull(c, b); e != nil {
						return
					}
					tcpSeen <- b
					binary.BigEndian.PutUint16(prefix[:], uint16(len(answer)))
					c.Write(append(prefix[:], answer...))
				}()
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			got, err := Forward(udp.LocalAddr().String())(ctx, packet)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, answer) {
				t.Fatal("DNS response fields changed")
			}
			select {
			case received := <-udpSeen:
				if !bytes.Equal(received, packet) {
					t.Fatal("UDP query changed, including EDNS/DNSSEC")
				}
			default:
				t.Fatal("resolver never received UDP query")
			}
			if truncated {
				if !bytes.Equal(<-tcpSeen, packet) {
					t.Fatal("TCP query changed")
				}
			}
		})
	}
}

func TestForwardRejectsUnrelatedResponseAndHonorsCancellation(t *testing.T) {
	for _, cancelRequest := range []bool{false, true} {
		t.Run(map[bool]string{false: "unrelated response", true: "cancellation"}[cancelRequest], func(t *testing.T) {
			udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			q := dnsmessage.Message{Header: dnsmessage.Header{ID: 100}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("ordinary.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
			query, _ := q.Pack()
			q.Response = true
			answer, _ := q.Pack()
			go func() {
				b := make([]byte, 1024)
				_, peer, err := udp.ReadFrom(b)
				if err != nil {
					return
				}
				if cancelRequest {
					cancel()
					return
				}
				wrong := append([]byte(nil), answer...)
				wrong[0] ^= 1
				udp.WriteTo(wrong, peer)
				udp.WriteTo(answer, peer)
			}()
			done := make(chan error, 1)
			go func() {
				got, err := Forward(udp.LocalAddr().String())(ctx, query)
				if !cancelRequest && err == nil && !bytes.Equal(got, answer) {
					err = io.ErrUnexpectedEOF
				}
				done <- err
			}()
			select {
			case err := <-done:
				if cancelRequest && err == nil {
					t.Fatal("cancelled request succeeded")
				}
				if !cancelRequest && err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("forward did not complete promptly")
			}
		})
	}
}
