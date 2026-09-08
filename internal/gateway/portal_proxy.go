package gateway

import (
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const (
	InternalTokenHeader = "X-Hydrat-Internal-Token"
	ClientIPHeader      = "X-Hydrat-Client-IP"
)

func NewPortalProxy(upstream, internalToken string, transport http.RoundTripper) (http.Handler, error) {
	target, err := url.Parse(upstream)
	if err != nil || target.Scheme == "" || target.Host == "" {
		return nil, errors.New("portal proxy upstream is invalid")
	}
	if strings.TrimSpace(internalToken) == "" {
		return nil, errors.New("portal proxy internal token is required")
	}
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(target)
			request.Out.Host = target.Host
			request.Out.Header.Del(InternalTokenHeader)
			request.Out.Header.Del(ClientIPHeader)
			request.Out.Header.Del("Forwarded")
			request.Out.Header.Del("X-Forwarded-For")
			request.Out.Header.Del("X-Forwarded-Host")
			request.Out.Header.Del("X-Forwarded-Proto")
			request.Out.Header.Set(InternalTokenHeader, internalToken)
			request.Out.Header.Set(ClientIPHeader, remoteIP(request.In.RemoteAddr))
		},
	}
	return proxy, nil
}

func remoteIP(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err == nil {
		return host
	}
	return remoteAddress
}
