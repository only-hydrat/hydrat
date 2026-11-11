package sources

import (
	"net"
	"net/netip"
	"strings"
)

// IndependentTorBridges uses the relay identity and endpoint, not subscription
// labels or obfs4 options. Two aliases of one relay or host cannot corroborate
// a route failure. This also handles inventories predating route metadata.
func IndependentTorBridges(a, b string) bool {
	identity := func(raw string) (string, string) {
		item := parseTorBridge(0, raw)
		if item.Kind != KindTorBridge {
			return "", ""
		}
		fields := strings.Fields(strings.TrimPrefix(item.Payload, "Bridge "))
		index := 1
		if !strings.Contains(fields[0], ":") {
			index = 2
		}
		host, _, err := net.SplitHostPort(fields[index-1])
		if err != nil {
			return "", ""
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if ip, err := netip.ParseAddr(host); err == nil {
			host = ip.Unmap().String()
		}
		return host, strings.ToUpper(fields[index])
	}
	ah, ak := identity(a)
	bh, bk := identity(b)
	return ah != "" && bh != "" && ak != "" && bk != "" && ah != bh && ak != bk
}
