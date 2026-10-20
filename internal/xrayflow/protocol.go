// Package xrayflow supplies the private, process-local flow recovery protocol.
// The registry/server files are also compiled into the pinned Xray build.
package xrayflow

import (
	"errors"
	"net/netip"
)

const SocketEnvironment = "HYDRAT_XRAY_FLOW_SOCKET"

var (
	ErrInvalidRequest = errors.New("invalid flow recovery request")
	ErrStaleInstance  = errors.New("flow recovery instance changed")
)

type Snapshot struct {
	Instance string `json:"instance"`
	BeforeID uint64 `json:"before_id"`
	Active   int    `json:"active"`
}

type ResetRequest struct {
	Snapshot Snapshot `json:"snapshot"`
	Outbound string   `json:"outbound"`
	Source   string   `json:"source"`
}

type ResetResponse struct {
	Closed int `json:"closed"`
}

func (q ResetRequest) Validate() error {
	address, err := netip.ParseAddr(q.Source)
	if err != nil || !address.Is4() || address.IsUnspecified() || q.Source != address.String() || !validTag(q.Outbound) || len(q.Snapshot.Instance) != 32 {
		return ErrInvalidRequest
	}
	return nil
}

func validTag(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, ch := range value {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.') {
			return false
		}
	}
	return true
}
