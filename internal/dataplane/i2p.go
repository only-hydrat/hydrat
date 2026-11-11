package dataplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// I2PPolicyLevel isolates cold-start handshake time from ordinary egress.
// It must match config/xray/main.json.
const I2PPolicyLevel = 19819

func validateI2PHandler(route ClientRoute, o Outbound) error {
	var c struct {
		Tag      string `json:"tag"`
		Protocol string `json:"protocol"`
		Settings struct {
			Servers []struct {
				Address string `json:"address"`
				Port    int    `json:"port"`
				Users   []struct {
					Level int    `json:"level"`
					User  string `json:"user"`
					Pass  string `json:"pass"`
				} `json:"users"`
			} `json:"servers"`
		} `json:"settings"`
	}
	d := json.NewDecoder(bytes.NewReader(o.Config))
	d.DisallowUnknownFields()
	invalid := errors.New("invalid private I2P bridge configuration")
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF || c.Protocol != "socks" || c.Tag != route.I2POutbound || len(c.Settings.Servers) != 1 {
		return invalid
	}
	s := c.Settings.Servers[0]
	if s.Address != "127.0.0.1" || s.Port != 19447 || len(s.Users) != 1 || s.Users[0].User != route.ClientID || s.Users[0].Pass != route.I2PToken || s.Users[0].Level != I2PPolicyLevel {
		return invalid
	}
	return nil
}
