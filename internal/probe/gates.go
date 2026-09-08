package probe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const (
	reqPQMultiConstructor uint32 = 0xbe7e8ef1
	resPQConstructor      uint32 = 0x05162463
)

type HTTPGateConfig struct {
	YouTubeURL   string
	ChatGPTURL   string
	OpenAIURL    string
	TelegramURL  string
	InstagramURL string
	CustomGates  []CustomGateCheck
}

type CustomGateCheck struct {
	Name       string
	URL        string
	Acceptable func(int) bool
}

type HTTPGateResult struct {
	ChatGPTWeb   bool
	OpenAI401    bool
	TelegramWeb  bool
	YouTubeWeb   bool
	InstagramWeb bool
	CustomGates  map[string]bool
}

func DefaultHTTPGateConfig() HTTPGateConfig {
	return HTTPGateConfig{
		YouTubeURL:   "https://www.youtube.com/generate_204",
		ChatGPTURL:   "https://chatgpt.com/",
		OpenAIURL:    "https://api.openai.com/v1/models",
		TelegramURL:  "https://web.telegram.org/",
		InstagramURL: "https://www.instagram.com/",
	}
}

func StatusesAcceptable(statuses []int) func(int) bool {
	if len(statuses) == 0 {
		return statusBelow400
	}
	statusSet := make(map[int]bool, len(statuses))
	for _, s := range statuses {
		statusSet[s] = true
	}
	return func(s int) bool { return statusSet[s] }
}

func CheckHTTPGates(ctx context.Context, client *http.Client) HTTPGateResult {
	return CheckHTTPGatesWithConfig(ctx, client, DefaultHTTPGateConfig())
}

func CheckHTTPGatesWithConfig(ctx context.Context, client *http.Client, cfg HTTPGateConfig) HTTPGateResult {
	return checkHTTPServicesWithConfig(ctx, client, cfg,
		chatGPTReachable,
		openAIAcceptable,
		statusBelow400,
	)
}

// CheckHTTPReachability is a control-plane check: any non-5xx HTTP response
// proves that DNS, TCP, TLS and the remote service are reachable. It is
// intentionally less strict than CheckHTTPGates, which enforces whether a
// candidate route is suitable for clients.
func CheckHTTPReachability(ctx context.Context, client *http.Client) HTTPGateResult {
	return CheckHTTPReachabilityWithConfig(ctx, client, DefaultHTTPGateConfig())
}

func CheckHTTPReachabilityWithConfig(ctx context.Context, client *http.Client, cfg HTTPGateConfig) HTTPGateResult {
	return checkHTTPServicesWithConfig(ctx, client, cfg,
		httpServiceReachable,
		httpServiceReachable,
		httpServiceReachable,
	)
}

func checkHTTPServicesWithConfig(
	ctx context.Context,
	client *http.Client,
	cfg HTTPGateConfig,
	chatGPTAcceptable, openAIAcceptable, telegramAcceptable func(int) bool,
) HTTPGateResult {
	if client == nil {
		client = http.DefaultClient
	}
	ytURL := cfg.YouTubeURL
	if ytURL == "" {
		ytURL = "https://www.youtube.com/generate_204"
	}
	cgURL := cfg.ChatGPTURL
	if cgURL == "" {
		cgURL = "https://chatgpt.com/"
	}
	oaURL := cfg.OpenAIURL
	if oaURL == "" {
		oaURL = "https://api.openai.com/v1/models"
	}
	tgURL := cfg.TelegramURL
	if tgURL == "" {
		tgURL = "https://web.telegram.org/"
	}
	igURL := cfg.InstagramURL
	if igURL == "" {
		igURL = "https://www.instagram.com/"
	}
	type checkItem struct {
		name       string
		url        string
		acceptable func(int) bool
		isCustom   bool
	}
	checks := make([]checkItem, 0, 5+len(cfg.CustomGates))
	checks = append(checks,
		checkItem{name: "chatgpt", url: cgURL, acceptable: chatGPTAcceptable},
		checkItem{name: "openai", url: oaURL, acceptable: openAIAcceptable},
		checkItem{name: "telegram", url: tgURL, acceptable: telegramAcceptable},
		checkItem{name: "youtube", url: ytURL, acceptable: statusBelow400},
		checkItem{name: "instagram", url: igURL, acceptable: statusBelow400},
	)
	for _, cg := range cfg.CustomGates {
		acceptable := cg.Acceptable
		if acceptable == nil {
			acceptable = statusBelow400
		}
		checks = append(checks, checkItem{
			name:       cg.Name,
			url:        cg.URL,
			acceptable: acceptable,
			isCustom:   true,
		})
	}

	type result struct {
		name     string
		ok       bool
		isCustom bool
	}
	results := make(chan result, len(checks))
	for _, check := range checks {
		check := check
		go func() {
			results <- result{
				name:     check.name,
				ok:       checkStatus(ctx, client, check.url, check.acceptable),
				isCustom: check.isCustom,
			}
		}()
	}
	gates := HTTPGateResult{}
	if len(cfg.CustomGates) > 0 {
		gates.CustomGates = make(map[string]bool, len(cfg.CustomGates))
	}
	for range checks {
		item := <-results
		if item.isCustom {
			gates.CustomGates[item.name] = item.ok
		} else {
			switch item.name {
			case "chatgpt":
				gates.ChatGPTWeb = item.ok
			case "openai":
				gates.OpenAI401 = item.ok
			case "telegram":
				gates.TelegramWeb = item.ok
			case "youtube":
				gates.YouTubeWeb = item.ok
			case "instagram":
				gates.InstagramWeb = item.ok
			}
		}
	}
	return gates
}

func checkStatus(ctx context.Context, client *http.Client, url string, acceptable func(int) bool) bool {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	originClient := *client
	originClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := originClient.Do(request)
	if err != nil {
		return false
	}
	if _, err := discardBody(ctx, response.Body, 4096); err != nil {
		return false
	}
	return acceptable(response.StatusCode)
}

func statusBelow400(status int) bool {
	return status >= 200 && status < 400
}

func httpServiceReachable(status int) bool {
	return status >= 200 && status < 500
}

func chatGPTReachable(status int) bool {
	return statusBelow400(status) ||
		status == http.StatusForbidden ||
		status == http.StatusTooManyRequests
}

func openAIAcceptable(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusNoContent || status == http.StatusOK
}

func discardBody(ctx context.Context, body io.ReadCloser, limit int64) (int64, error) {
	if body == nil {
		return 0, errors.New("response body is nil")
	}
	type result struct {
		count int64
		err   error
	}
	done := make(chan result, 1)
	go func() {
		count, err := io.Copy(io.Discard, io.LimitReader(body, limit))
		done <- result{count: count, err: err}
	}()
	select {
	case result := <-done:
		closeErr := body.Close()
		if result.err != nil {
			return result.count, result.err
		}
		return result.count, closeErr
	case <-ctx.Done():
		_ = body.Close()
		result := <-done
		return result.count, ctx.Err()
	}
}

type ContextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

func CheckTelegramMTProto(ctx context.Context, dialer ContextDialer, dataCenters []string) (bool, error) {
	if dialer == nil {
		return false, errors.New("MTProto dialer is required")
	}
	if len(dataCenters) == 0 {
		return false, errors.New("at least one Telegram data center is required")
	}
	var lastError error
	for _, address := range dataCenters {
		ok, err := checkTelegramDC(ctx, dialer, address)
		if ok {
			return true, nil
		}
		if err != nil {
			lastError = err
		}
	}
	if lastError == nil {
		lastError = errors.New("Telegram MTProto gate failed")
	}
	return false, lastError
}

func checkTelegramDC(ctx context.Context, dialer ContextDialer, address string) (bool, error) {
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false, err
	}
	defer connection.Close()
	deadline := time.Now().Add(3 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return false, err
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return false, err
	}
	payload := make([]byte, 40)
	binary.LittleEndian.PutUint64(payload[8:16], uint64(time.Now().Unix())<<32)
	binary.LittleEndian.PutUint32(payload[16:20], 20)
	binary.LittleEndian.PutUint32(payload[20:24], reqPQMultiConstructor)
	copy(payload[24:], nonce)
	frame := append([]byte{0xef, byte(len(payload) / 4)}, payload...)
	if _, err := connection.Write(frame); err != nil {
		return false, err
	}

	lengthWords, err := readAbridgedLength(connection)
	if err != nil {
		return false, err
	}
	if lengthWords < 10 || lengthWords > 1024*1024/4 {
		return false, fmt.Errorf("invalid MTProto response length %d", lengthWords*4)
	}
	response := make([]byte, lengthWords*4)
	if _, err := io.ReadFull(connection, response); err != nil {
		return false, err
	}
	if len(response) < 40 || binary.LittleEndian.Uint64(response[:8]) != 0 || binary.LittleEndian.Uint32(response[20:24]) != resPQConstructor {
		return false, errors.New("invalid MTProto resPQ response")
	}
	if string(response[24:40]) != string(nonce) {
		return false, errors.New("MTProto nonce mismatch")
	}
	return true, nil
}

func readAbridgedLength(reader io.Reader) (int, error) {
	var first [1]byte
	if _, err := io.ReadFull(reader, first[:]); err != nil {
		return 0, err
	}
	if first[0] < 0x7f {
		return int(first[0]), nil
	}
	var extended [3]byte
	if _, err := io.ReadFull(reader, extended[:]); err != nil {
		return 0, err
	}
	return int(extended[0]) | int(extended[1])<<8 | int(extended[2])<<16, nil
}
