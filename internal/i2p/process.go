package i2p

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// ExecRouter is the sole launcher; no user-supplied router flags are accepted.
// The shared data directory contains public netDb state and private router keys.
type ExecRouter struct {
	Binary, Directory string
	Output            io.Writer
	mu                sync.Mutex
	cmd               *exec.Cmd
	done              chan error
	password          string
	startedAt         time.Time
	verified          bool
}

func (r *ExecRouter) controlCertificate() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Hydrat private I2P control"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := atomicFile(filepath.Join(r.Directory, "control.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})); err != nil {
		return err
	}
	return atomicFile(filepath.Join(r.Directory, "control.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
func (r *ExecRouter) Inspect(ctx context.Context) (RouterStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd == nil {
		return RouterStatus{}, errors.New("I2P stopped")
	}
	select {
	case <-r.done:
		r.cmd = nil
		return RouterStatus{}, errors.New("I2P process exited")
	default:
	}
	// Control may take a short time to bind. Nothing is declared ready before
	// its authenticated counters have been received.
	if _, err := os.Stat(filepath.Join(r.Directory, "control.sock")); err != nil {
		if r.verified || !os.IsNotExist(err) || time.Since(r.startedAt) > 30*time.Second {
			return RouterStatus{}, errors.New("I2P control socket unavailable")
		}
		return RouterStatus{}, nil
	}
	auth, err := r.rpc(ctx, "Authenticate", map[string]any{"API": 1, "Password": r.password})
	if err != nil {
		return RouterStatus{}, err
	}
	var token string
	if err = json.Unmarshal(auth["Token"], &token); err != nil || token == "" {
		return RouterStatus{}, errors.New("I2P authentication failed")
	}
	// This pinned i2pd handles authentication separately; RouterInfo treats Token
	// as an unknown statistic. Transport authentication is the pinned Unix TLS peer.
	result, err := r.rpc(ctx, "RouterInfo", map[string]any{"i2p.router.net.tunnels.participating": "", "i2p.router.netdb.activepeers": "", "i2p.router.net.tunnels.inbound": "", "i2p.router.net.tunnels.outbound": "", "i2p.router.status": ""})
	if err != nil {
		return RouterStatus{}, err
	}
	var count, peers int
	if err = json.Unmarshal(result["i2p.router.net.tunnels.participating"], &count); err != nil || count < 0 {
		return RouterStatus{}, errors.New("I2P transit counter unavailable")
	}
	if err = json.Unmarshal(result["i2p.router.netdb.activepeers"], &peers); err != nil {
		return RouterStatus{}, err
	}
	var inbound, outbound int
	if json.Unmarshal(result["i2p.router.net.tunnels.inbound"], &inbound) != nil || json.Unmarshal(result["i2p.router.net.tunnels.outbound"], &outbound) != nil {
		return RouterStatus{}, errors.New("I2P tunnel counters unavailable")
	}
	var ready string
	if json.Unmarshal(result["i2p.router.status"], &ready) != nil || (ready != "0" && ready != "1") {
		return RouterStatus{}, errors.New("I2P client readiness unavailable")
	}
	r.verified = true
	return RouterStatus{Transit: count, Ready: ready == "1" && peers > 0}, nil
}
