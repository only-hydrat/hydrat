package refresh

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
)

func TestRefreshFailuresClassifyWithoutURLsOrRawErrors(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{context.DeadlineExceeded, "timeout"},
		{context.Canceled, "canceled"},
		{&net.DNSError{Err: "private-token", Name: "private-host"}, "dns"},
		{&tls.CertificateVerificationError{Err: errors.New("private-token")}, "tls"},
		{errors.New("fetch subscription: HTTP 503"), "HTTP 503"},
		{errors.New("fetch subscription: HTTP 503 private-token"), "failed"},
		{errors.New("private-token"), "failed"},
	} {
		err := fmt.Errorf("fetch subscription: %w", &url.Error{Op: "Get", URL: "https://private-host/private-token", Err: test.err})
		got := safeRefreshError(err).Error()
		if !strings.Contains(got, test.want) || strings.Contains(got, "private") {
			t.Fatalf("got=%q want=%q", got, test.want)
		}
	}
}
