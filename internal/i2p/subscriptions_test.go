package i2p

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func TestImportPreviewAndSubscriptionConflicts(t *testing.T) {
	b, err := OpenBook(t.TempDir() + "/book")
	if err != nil {
		t.Fatal(err)
	}
	destination := strings.Repeat("a", 52) + ".b32.i2p"
	p := b.Preview("good.i2p=" + destination + "\nbad.test=" + destination + "\n")
	if p.Valid != 1 || len(p.Errors) != 1 {
		t.Fatal(p)
	}
	if err := b.ApplyImport(p, "feed", false); err == nil {
		t.Fatal("invalid batch accepted")
	}
	p = b.Preview("good.i2p=" + destination + "\n")
	if err := b.ApplyImport(p, "feed", false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.Export(), "good.i2p=") {
		t.Fatal("export lost entry")
	}
}
func TestPublicSubscriptionAddressPolicy(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.1.1", "198.19.0.1", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "2002:a00:1::1"} {
		if publicIP(netip.MustParseAddr(s)) {
			t.Fatal("private/reserved IP allowed", s)
		}
	}
	if !publicIP(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public HTTPS rejected")
	}
}
func TestPublicClientNeverResolvesPrivateNamespaces(t *testing.T) {
	c := PublicHTTPSClient()
	defer c.CloseIdleConnections()
	for _, host := range []string{"name.i2p", "name.i2p.", "name.onion"} {
		_, err := c.Transport.(*http.Transport).DialContext(t.Context(), "tcp", host+":443")
		if err == nil || !strings.Contains(err.Error(), "private namespace") {
			t.Fatal(host, err)
		}
	}
}
