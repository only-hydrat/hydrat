package sources

import (
	"net/url"
	"strings"
)

const (
	visionUDP443HandlerSuffix   = "-vision-udp443-v1"
	visionStandardHandlerSuffix = "-vision-standard-v2"
)

// VLESSHandlerID versions the Xray handler when restoring standard Vision changes its config.
func VLESSHandlerID(candidateID, payload string) string {
	parsed, err := url.Parse(payload)
	if err == nil && strings.TrimSpace(parsed.Query().Get("flow")) == "xtls-rprx-vision" {
		return candidateID + visionStandardHandlerSuffix
	}
	return candidateID
}

func CandidateIDFromVLESSHandler(handlerID string) string {
	return strings.TrimSuffix(strings.TrimSuffix(handlerID, visionUDP443HandlerSuffix), visionStandardHandlerSuffix)
}
