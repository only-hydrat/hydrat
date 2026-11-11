package agentapi

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

// WithI2PHandler exposes optional I2P management only on the private agent socket.
func WithI2PHandler(h http.Handler) Option { return func(s *Server) { s.i2p = h } }
func (c *Client) I2PHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		suffix := strings.TrimPrefix(r.URL.Path, "/api/admin/i2p")
		if suffix == "" {
			suffix = "/"
		}
		ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, r.Method, "http://unix/v1/i2p"+suffix, r.Body)
		if err != nil {
			http.Error(w, "invalid I2P request", 400)
			return
		}
		req.URL.RawQuery = r.URL.RawQuery
		req.Header.Set("Content-Type", "application/json")
		// Never forward admin credentials to another service.
		client := *c.http
		client.Timeout = 40 * time.Second
		res, err := client.Do(req)
		if err != nil {
			http.Error(w, "I2P agent unavailable", 503)
			return
		}
		defer res.Body.Close()
		limit := int64(2 << 20)
		if suffix == "/export" {
			limit = 8 << 20
		}
		body, readErr := io.ReadAll(io.LimitReader(res.Body, limit+1))
		if readErr != nil || int64(len(body)) > limit {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			io.WriteString(w, `{"error":"I2P response exceeds limit or is incomplete"}`)
			return
		}
		for _, k := range []string{"Content-Type", "Content-Disposition"} {
			if v := res.Header.Get(k); v != "" {
				w.Header().Set(k, v)
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(res.StatusCode)
		w.Write(body)
	})
}
