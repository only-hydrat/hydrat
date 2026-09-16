package portal

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestAdminSessionsExpireRefreshAndRevoke(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	random := append(bytes.Repeat([]byte{1}, 64), bytes.Repeat([]byte{2}, 32)...)
	auth := newAdminAuthWith("secret", func() time.Time { return now }, bytes.NewReader(random))
	token, idle, absolute, err := auth.createSession()
	if err != nil || len(token) != 43 || idle != 30*time.Minute || absolute != 8*time.Hour {
		t.Fatalf("token=%q idle=%s absolute=%s err=%v", token, idle, absolute, err)
	}
	if len(auth.sessions) != 1 {
		t.Fatalf("sessions=%d", len(auth.sessions))
	}
	if _, ok := auth.sessions[sha256.Sum256([]byte(token))]; !ok {
		t.Fatal("session was not stored by token digest")
	}

	now = now.Add(29 * time.Minute)
	if !auth.authenticateBearer(token) {
		t.Fatal("live token rejected")
	}
	now = now.Add(31 * time.Minute)
	if auth.authenticateBearer(token) {
		t.Fatal("idle-expired token accepted")
	}

	token, _, _, err = auth.createSession()
	if err != nil {
		t.Fatal(err)
	}
	auth.revoke(token)
	if auth.authenticateBearer(token) {
		t.Fatal("revoked token accepted")
	}
	for _, malformed := range []string{"", "not-a-token", "A", "abc="} {
		if auth.authenticateBearer(malformed) {
			t.Fatalf("malformed token %q accepted", malformed)
		}
	}
	token, _, _, err = auth.createSession()
	if err != nil {
		t.Fatal(err)
	}
	if !auth.authenticateBearer(token) {
		t.Fatal("restart fixture must be a live token accepted by the original auth")
	}
	if newAdminAuthWith("secret", func() time.Time { return now }, bytes.NewReader(nil)).authenticateBearer(token) {
		t.Fatal("session survived restart")
	}
}

func TestAdminSessionsAbsoluteExpiry(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	auth := newAdminAuthWith("secret", func() time.Time { return now }, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	token, _, _, err := auth.createSession()
	if err != nil {
		t.Fatal(err)
	}
	for range 16 {
		now = now.Add(29 * time.Minute)
		if !auth.authenticateBearer(token) {
			t.Fatal("token rejected before absolute expiry")
		}
	}
	now = now.Add(15 * time.Minute)
	if !auth.authenticateBearer(token) {
		t.Fatal("token rejected before absolute expiry")
	}
	now = now.Add(time.Minute)
	if auth.authenticateBearer(token) {
		t.Fatal("absolute-expired token accepted")
	}
}

func TestAdminSessionsRejectRandomFailure(t *testing.T) {
	auth := newAdminAuthWith("secret", time.Now, errReader{errors.New("random failed")})
	if _, _, _, err := auth.createSession(); err == nil {
		t.Fatal("random reader failure accepted")
	}
}

func TestAdminSessionsCapacity(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	random := make([]byte, 257*32)
	for i := 0; i < 257; i++ {
		random[i*32] = byte(i)
		random[i*32+1] = byte(i >> 8)
	}
	auth := newAdminAuthWith("secret", func() time.Time { return now }, bytes.NewReader(random))
	for range 256 {
		if _, _, _, err := auth.createSession(); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err := auth.createSession(); !errors.Is(err, errSessionCapacity) {
		t.Fatalf("257th session err=%v", err)
	}
}

type errReader struct{ err error }

func (reader errReader) Read([]byte) (int, error) { return 0, reader.err }

func TestPasswordThrottle(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	auth := newAdminAuthWith("secret", func() time.Time { return now }, rand.Reader)
	for attempt := 1; attempt <= 5; attempt++ {
		if authenticated, retry := auth.authenticatePassword("limited", "wrong"); authenticated || retry != 0 {
			t.Fatalf("attempt %d authenticated=%t retry=%s", attempt, authenticated, retry)
		}
	}
	if authenticated, retry := auth.authenticatePassword("limited", "secret"); authenticated || retry <= 0 {
		t.Fatalf("throttled correct password authenticated=%t retry=%s", authenticated, retry)
	}
	clearAuth := newAdminAuthWith("secret", func() time.Time { return now }, rand.Reader)
	for range 2 {
		clearAuth.authenticatePassword("cleared", "wrong")
	}
	if authenticated, retry := clearAuth.authenticatePassword("cleared", "secret"); !authenticated || retry != 0 {
		t.Fatalf("successful password authenticated=%t retry=%s", authenticated, retry)
	}
	if _, found := clearAuth.failures["cleared"]; found {
		t.Fatal("successful password login did not clear failures")
	}

	now = now.Add(500 * time.Millisecond)
	if authenticated, retry := auth.authenticatePassword("limited", "secret"); authenticated || retry != time.Minute {
		t.Fatalf("retry rounding authenticated=%t retry=%s", authenticated, retry)
	}
	now = now.Add(59*time.Second + 500*time.Millisecond)
	if authenticated, retry := auth.authenticatePassword("limited", "secret"); !authenticated || retry != 0 {
		t.Fatalf("minute-boundary password authenticated=%t retry=%s", authenticated, retry)
	}
}

func TestPasswordThrottleFailsClosedWithoutConfiguration(t *testing.T) {
	for _, test := range []struct {
		name     string
		password string
	}{
		{name: "empty header", password: ""},
		{name: "missing header", password: ""},
		{name: "non-empty header", password: "secret"},
	} {
		auth := newAdminAuthWith("", time.Now, rand.Reader)
		if authenticated, _ := auth.authenticatePassword("source", test.password); authenticated {
			t.Fatalf("%s accepted", test.name)
		}
	}
}

func TestPasswordThrottleBoundsSources(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	auth := newAdminAuthWith("secret", func() time.Time { return now }, rand.Reader)
	for source := range 1024 {
		if authenticated, retry := auth.authenticatePassword(fmt.Sprintf("source-%d", source), "wrong"); authenticated || retry != 0 {
			t.Fatalf("source %d authenticated=%t retry=%s", source, authenticated, retry)
		}
	}
	if len(auth.failures) != 1024 {
		t.Fatalf("named failure sources=%d", len(auth.failures))
	}
	for attempt := 1; attempt <= 5; attempt++ {
		if authenticated, retry := auth.authenticatePassword("overflow-a", "wrong"); authenticated || retry != 0 {
			t.Fatalf("overflow attempt %d authenticated=%t retry=%s", attempt, authenticated, retry)
		}
	}
	if authenticated, retry := auth.authenticatePassword("overflow-b", "secret"); authenticated || retry <= 0 {
		t.Fatalf("overflow sources did not share throttle: authenticated=%t retry=%s", authenticated, retry)
	}
	if len(auth.failures) != 1024 || len(auth.overflow) != 5 {
		t.Fatalf("named=%d overflow=%d", len(auth.failures), len(auth.overflow))
	}

	now = now.Add(time.Minute)
	if authenticated, retry := auth.authenticatePassword("fresh", "wrong"); authenticated || retry != 0 {
		t.Fatalf("fresh source authenticated=%t retry=%s", authenticated, retry)
	}
	if len(auth.failures) != 1 || len(auth.overflow) != 0 {
		t.Fatalf("expired source cleanup named=%d overflow=%d", len(auth.failures), len(auth.overflow))
	}
}

func TestAdminAuthConcurrent(t *testing.T) {
	auth := newAdminAuthWith("secret", time.Now, rand.Reader)
	var group sync.WaitGroup
	errs := make(chan error, 64)
	for worker := range 64 {
		group.Add(1)
		go func() {
			defer group.Done()
			token, _, _, err := auth.createSession()
			if err != nil {
				errs <- err
				return
			}
			auth.authenticateBearer(token)
			auth.revoke(token)
			auth.authenticatePassword(fmt.Sprintf("worker-%d", worker), "wrong")
			auth.authenticatePassword(fmt.Sprintf("worker-%d", worker), "secret")
		}()
	}
	group.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
