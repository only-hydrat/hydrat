package portal

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"time"
)

const (
	adminSessionIdle     = 30 * time.Minute
	adminSessionAbsolute = 8 * time.Hour
	maxAdminSessions     = 256
	adminFailureWindow   = time.Minute
	maxAdminFailures     = 5
	maxAdminFailureKeys  = 1024
)

var errSessionCapacity = errors.New("admin session capacity exhausted")

type adminSession struct {
	createdAt  time.Time
	lastUsedAt time.Time
}

type adminAuth struct {
	mu                 sync.Mutex
	passwordConfigured bool
	passwordDigest     [sha256.Size]byte
	sessions           map[[sha256.Size]byte]adminSession
	failures           map[string][]time.Time
	overflow           []time.Time
	now                func() time.Time
	random             io.Reader
}

func newAdminAuth(password string) *adminAuth {
	return newAdminAuthWith(password, time.Now, rand.Reader)
}

func newAdminAuthWith(password string, now func() time.Time, random io.Reader) *adminAuth {
	auth := &adminAuth{
		sessions: make(map[[sha256.Size]byte]adminSession),
		failures: make(map[string][]time.Time),
		now:      now,
		random:   random,
	}
	if password != "" {
		auth.passwordConfigured = true
		auth.passwordDigest = sha256.Sum256([]byte(password))
	}
	return auth
}

func (auth *adminAuth) createSession() (string, time.Duration, time.Duration, error) {
	auth.mu.Lock()
	defer auth.mu.Unlock()

	now := auth.now()
	auth.cleanSessions(now)
	if len(auth.sessions) >= maxAdminSessions {
		return "", 0, 0, errSessionCapacity
	}
	bytes := make([]byte, sha256.Size)
	if _, err := io.ReadFull(auth.random, bytes); err != nil {
		return "", 0, 0, err
	}
	token := base64.RawURLEncoding.EncodeToString(bytes)
	digest := sha256.Sum256([]byte(token))
	auth.sessions[digest] = adminSession{createdAt: now, lastUsedAt: now}
	return token, adminSessionIdle, adminSessionAbsolute, nil
}

func (auth *adminAuth) authenticatePassword(source, password string) (bool, time.Duration) {
	providedDigest := sha256.Sum256([]byte(password))
	auth.mu.Lock()
	defer auth.mu.Unlock()

	now := auth.now()
	auth.cleanFailures(now)
	history, named := auth.failures[source]
	if !named && len(auth.failures) < maxAdminFailureKeys {
		auth.failures[source] = nil
		named = true
	}
	if !named {
		history = auth.overflow
	}
	if len(history) >= maxAdminFailures {
		return false, retryAfter(history[0].Add(adminFailureWindow).Sub(now))
	}
	passwordMatches := subtle.ConstantTimeCompare(providedDigest[:], auth.passwordDigest[:]) == 1
	if auth.passwordConfigured && passwordMatches {
		if named {
			delete(auth.failures, source)
		}
		return true, 0
	}
	history = append(history, now)
	if named {
		auth.failures[source] = history
	} else {
		auth.overflow = history
	}
	return false, 0
}

func (auth *adminAuth) authenticateBearer(token string) bool {
	digest, ok := adminTokenDigest(token)
	if !ok {
		return false
	}
	auth.mu.Lock()
	defer auth.mu.Unlock()

	now := auth.now()
	session, ok := auth.sessions[digest]
	if !ok {
		return false
	}
	if sessionExpired(session, now) {
		delete(auth.sessions, digest)
		return false
	}
	session.lastUsedAt = now
	auth.sessions[digest] = session
	return true
}

func (auth *adminAuth) revoke(token string) {
	digest, ok := adminTokenDigest(token)
	if !ok {
		return
	}
	auth.mu.Lock()
	delete(auth.sessions, digest)
	auth.mu.Unlock()
}

func (auth *adminAuth) cleanSessions(now time.Time) {
	for digest, session := range auth.sessions {
		if sessionExpired(session, now) {
			delete(auth.sessions, digest)
		}
	}
}

func (auth *adminAuth) cleanFailures(now time.Time) {
	cutoff := now.Add(-adminFailureWindow)
	for source, history := range auth.failures {
		history = activeFailures(history, cutoff)
		if len(history) == 0 {
			delete(auth.failures, source)
		} else {
			auth.failures[source] = history
		}
	}
	auth.overflow = activeFailures(auth.overflow, cutoff)
}

func activeFailures(history []time.Time, cutoff time.Time) []time.Time {
	for index, timestamp := range history {
		if timestamp.After(cutoff) {
			return history[index:]
		}
	}
	return nil
}

func retryAfter(remaining time.Duration) time.Duration {
	return ((remaining + time.Second - 1) / time.Second) * time.Second
}

func adminTokenDigest(token string) ([sha256.Size]byte, bool) {
	bytes, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(bytes) != sha256.Size || base64.RawURLEncoding.EncodeToString(bytes) != token {
		return [sha256.Size]byte{}, false
	}
	return sha256.Sum256([]byte(token)), true
}

func sessionExpired(session adminSession, now time.Time) bool {
	return !now.Before(session.createdAt.Add(adminSessionAbsolute)) || !now.Before(session.lastUsedAt.Add(adminSessionIdle))
}
