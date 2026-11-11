package sources

import "testing"

func TestIndependentTorBridgesRejectAliases(t *testing.T) {
	a := "Bridge obfs4 192.0.2.1:443 1111111111111111111111111111111111111111 cert=x iat-mode=0"
	for _, tt := range []struct {
		line string
		want bool
	}{
		{"Bridge obfs4 192.0.2.2:443 2222222222222222222222222222222222222222 cert=x iat-mode=0", true},
		{"Bridge obfs4 192.0.2.1:8443 2222222222222222222222222222222222222222 cert=y iat-mode=1", false},
		{"Bridge obfs4 [::ffff:192.0.2.1]:443 2222222222222222222222222222222222222222 cert=x", false},
		{"Bridge obfs4 192.0.2.2:443 1111111111111111111111111111111111111111 cert=y", false},
		{"invalid", false},
	} {
		if got := IndependentTorBridges(a, tt.line); got != tt.want {
			t.Fatalf("independence=%v want=%v", got, tt.want)
		}
	}
}
