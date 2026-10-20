package qoe

import (
	"fmt"
	"sort"
	"strings"
)

// HTTPCheck contains bounded service outcomes for diagnostics and comparison.
// Do not add URLs, custom gate names, response bodies or raw errors here.
type HTTPCheck struct {
	Service   string `json:"service"`
	Path      string `json:"path,omitempty"`
	Phase     string `json:"phase"`
	Code      string `json:"code"`
	Status    int    `json:"status,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms"`
	OK        bool   `json:"ok"`
}

// SafeHTTPChecks also validates metadata received from a remote agent.
func SafeHTTPChecks(checks []HTTPCheck) []HTTPCheck {
	if len(checks) == 0 {
		return nil
	}
	result := make([]HTTPCheck, 0, min(len(checks), 32))
	var perPath [3]int
	for _, check := range checks[:min(len(checks), 32)] {
		c := &check
		switch c.Service {
		case "youtube", "chatgpt", "openai", "telegram", "instagram", "qoe_endpoint":
		default:
			c.Service = "custom"
		}
		switch c.Path {
		case "route", "control":
		default:
			c.Path = "unknown"
		}
		switch c.Phase {
		case "request", "dns", "connect", "tls", "headers", "body", "status":
		default:
			c.Phase = "request"
		}
		switch c.Code {
		case "ok", "timeout", "budget_exhausted", "canceled", "dns", "tls", "transport", "body", "http_status", "invalid_request":
		default:
			c.Code = "transport"
		}
		if c.Status < 100 || c.Status > 599 {
			c.Status = 0
		}
		c.ElapsedMS = min(600_000, max(0, c.ElapsedMS))
		pathIndex := 0
		switch c.Path {
		case "route":
			pathIndex = 1
		case "control":
			pathIndex = 2
		}
		if perPath[pathIndex] == 16 {
			continue
		}
		perPath[pathIndex]++
		result = append(result, *c)
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].Path+result[i].Service < result[j].Path+result[j].Service })
	return result
}

func HTTPFailureSummary(checks []HTTPCheck) string {
	var fields []string
	var routeCount, controlCount, routeFailed, controlFailed int
	for _, c := range SafeHTTPChecks(checks) {
		switch c.Path {
		case "route":
			routeCount++
			if !c.OK {
				routeFailed++
			}
		case "control":
			controlCount++
			if !c.OK {
				controlFailed++
			}
		}
		if !c.OK {
			fields = append(fields, fmt.Sprintf("%s/%s:%s:%s:http_%d:%dms", c.Path, c.Service, c.Phase, c.Code, c.Status, c.ElapsedMS))
		}
	}
	if len(fields) == 0 {
		return ""
	}
	return fmt.Sprintf(" route_failed=%d/%d control_failed=%d/%d checks=%s", routeFailed, routeCount, controlFailed, controlCount, strings.Join(fields, ","))
}
