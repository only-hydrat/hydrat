package i2p

import (
	"context"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"net/netip"
)

type DNS struct {
	Book    *Book
	Allowed func(netip.Addr) bool
	Wake    func(context.Context) error
}

func (d DNS) Handle(ctx context.Context, source netip.Addr, packet []byte) ([]byte, error) {
	var q dnsmessage.Message
	if err := q.Unpack(packet); err != nil {
		return nil, err
	}
	r := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: q.RecursionDesired, RecursionAvailable: true}, Questions: q.Questions}
	reply := func(code dnsmessage.RCode) ([]byte, error) { r.RCode = code; return r.Pack() }
	if q.Response || q.OpCode != 0 || len(q.Questions) != 1 {
		return reply(dnsmessage.RCodeFormatError)
	}
	if d.Allowed == nil || !d.Allowed(source) {
		return reply(dnsmessage.RCodeRefused)
	}
	question := q.Questions[0]
	name, err := Name(question.Name.String())
	if err != nil {
		return reply(dnsmessage.RCodeNameError)
	}
	if question.Class != dnsmessage.ClassINET {
		return reply(dnsmessage.RCodeRefused)
	}
	if question.Type != dnsmessage.TypeA {
		return reply(dnsmessage.RCodeSuccess)
	}
	if d.Book == nil || d.Wake == nil {
		return reply(dnsmessage.RCodeServerFailure)
	}
	ip, _, err := d.Book.resolve(name, source)
	if err != nil {
		if errors.Is(err, errUnknownName) {
			return reply(dnsmessage.RCodeNameError)
		}
		return reply(dnsmessage.RCodeServerFailure)
	}
	if !d.Allowed(source) {
		return reply(dnsmessage.RCodeRefused)
	}
	if err = d.Wake(ctx); err != nil {
		return reply(dnsmessage.RCodeServerFailure)
	}
	if !d.Allowed(source) {
		return reply(dnsmessage.RCodeRefused)
	}
	r.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: ip.As4()}}}
	return reply(dnsmessage.RCodeSuccess)
}
