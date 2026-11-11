package onion

import (
	"golang.org/x/net/dns/dnsmessage"
	"testing"
)

func TestI2PDNSDoesNotConsumeOrdinaryBudget(t *testing.T) {
	l := &Listener{i2p: make(chan struct{}, 1), ordinary: make(chan struct{}, 1), onion: make(chan struct{}, 1)}
	p, _ := (&dnsmessage.Message{Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("example.i2p."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	if b := l.budget(p); b == nil || b == l.ordinary || b == l.onion {
		t.Fatal("I2P shares unrelated DNS budget")
	}
}
