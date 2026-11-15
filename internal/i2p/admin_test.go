package i2p

import (
	"testing"
)

func TestSubscriptionRejectsPrivateAndClearnetHTTP(t *testing.T) {
	for _, u := range []string{"http://example.org/hosts.txt", "https://127.0.0.1/x", "https://[::1]/x", "https://example.org:123/x", "https://user:pass@example.org/"} {
		if validateSubscriptionURL(u) == nil {
			t.Fatal(u)
		}
	}
}
