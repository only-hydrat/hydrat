package onion

import (
	"context"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"net/netip"
	"strings"
)

// DNS separates onion resolution from the existing ordinary DNS path.
// Install must acknowledge the mapping in every profile currently permitted
// to serve onion traffic before a successful answer is returned.
type DNS struct {
	I2P     func(context.Context, netip.Addr, []byte) ([]byte, error)
	Resolve func(netip.Addr, string) (netip.Addr, error)
	Allowed func(netip.Addr) bool
	Install func(context.Context, string, string) error
	Forward func(context.Context, []byte) ([]byte, error)
}

func (server DNS) Handle(ctx context.Context, source netip.Addr, packet []byte) ([]byte, error) {
	if len(packet) > 65535 {
		return nil, errors.New("oversized DNS packet")
	}
	var query dnsmessage.Message
	if err := query.Unpack(packet); err != nil {
		return nil, errors.New("malformed DNS packet")
	}
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionDesired: query.RecursionDesired, RecursionAvailable: true}, Questions: query.Questions}
	reply := func(code dnsmessage.RCode) ([]byte, error) { response.RCode = code; return response.Pack() }
	if query.Response || query.OpCode != 0 || len(query.Questions) != 1 {
		return reply(dnsmessage.RCodeFormatError)
	}
	question := query.Questions[0]
	name := strings.ToLower(strings.TrimSuffix(question.Name.String(), "."))
	if name == "i2p" || strings.HasSuffix(name, ".i2p") {
		if server.I2P == nil {
			return reply(dnsmessage.RCodeRefused)
		}
		return server.I2P(ctx, source, packet)
	}
	if name != "onion" && !strings.HasSuffix(name, ".onion") {
		if server.Forward == nil {
			return reply(dnsmessage.RCodeServerFailure)
		}
		return server.Forward(ctx, packet)
	}
	if server.Allowed == nil || !server.Allowed(source) {
		return reply(dnsmessage.RCodeRefused)
	}
	name, err := Normalize(name)
	if err != nil {
		return reply(dnsmessage.RCodeNameError)
	}
	if question.Class != dnsmessage.ClassINET {
		return reply(dnsmessage.RCodeRefused)
	}
	// Tor streams use TCP. No IPv6, HTTPS/SVCB, MX, or other records are
	// synthesized, and none of these queries leave the local resolver.
	if question.Type != dnsmessage.TypeA {
		return reply(dnsmessage.RCodeSuccess)
	}
	if server.Resolve == nil || server.Install == nil {
		return reply(dnsmessage.RCodeServerFailure)
	}
	address, err := server.Resolve(source, name)
	if err != nil {
		return reply(dnsmessage.RCodeServerFailure)
	}
	if err := server.Install(ctx, address.String(), name); err != nil {
		return reply(dnsmessage.RCodeServerFailure)
	}
	if !server.Allowed(source) {
		return reply(dnsmessage.RCodeRefused)
	}
	response.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: address.As4()}}}
	return reply(dnsmessage.RCodeSuccess)
}
