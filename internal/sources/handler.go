package sources

import (
	"net/url"
	"strings"
)

const visionUDP443HandlerSuffix = "-vision-udp443-v1"

// VLESSHandlerID versions the Xray handler when enabling UDP/443 changes its config.
func VLESSHandlerID(candidateID, payload string) string {
	parsed, err := url.Parse(payload)
	if err == nil && strings.TrimSpace(parsed.Query().Get("flow")) == "xtls-rprx-vision" {
		return candidateID + visionUDP443HandlerSuffix
	}
	return candidateID
}

func CandidateIDFromVLESSHandler(handlerID string) string {
	return strings.TrimSuffix(handlerID, visionUDP443HandlerSuffix)
}
