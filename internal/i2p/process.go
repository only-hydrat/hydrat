package i2p

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
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

func (r *ExecRouter) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != nil {
		return nil
	}
	if err := os.MkdirAll(r.Directory, 0700); err != nil {
		return err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	r.password = hex.EncodeToString(secret)
	// i2pd's generated SHA-1 certificate is rejected by modern OpenSSL.
	// Generate a private, short-lived certificate and pin it over the Unix socket.
	if err := r.controlCertificate(); err != nil {
		return err
	}
	empty := filepath.Join(r.Directory, "empty-tunnels")
	if err := os.MkdirAll(empty, 0700); err != nil {
		return err
	}
	files, err := os.ReadDir(empty)
	if err != nil || len(files) != 0 {
		return errors.New("unexpected I2P tunnel configuration")
	}
	config := "tunconf=/dev/null\ntunnelsdir=" + empty + "\ndaemon=false\nnotransit=true\nfloodfill=false\nshare=0\nlog=stdout\nloglevel=warn\nipv6=false\n[ntcp2]\npublished=false\n[ssu2]\npublished=false\n[upnp]\nenabled=false\n[http]\nenabled=false\n[httpproxy]\nenabled=false\n[sam]\nenabled=false\n[bob]\nenabled=false\n[i2cp]\nenabled=false\n[socksproxy]\nkeys=shareddest\nenabled=true\naddress=0.0.0.0\nport=4447\noutproxy.enabled=false\ninbound.length=3\noutbound.length=3\ninbound.quantity=2\noutbound.quantity=2\n[shareddest]\ninbound.length=3\noutbound.length=3\ninbound.quantity=2\noutbound.quantity=2\n[addressbook]\nenabled=false\n[reseed]\nverify=true\n[i2pcontrol]\nenabled=true\naddress=" + filepath.Join(r.Directory, "control.sock") + "\nport=0\npassword=" + r.password + "\ncert=" + filepath.Join(r.Directory, "control.crt") + "\nkey=" + filepath.Join(r.Directory, "control.key") + "\n"
	if err := atomicFile(filepath.Join(r.Directory, "i2pd.conf"), []byte(config)); err != nil {
		return err
	}
	// Command-line security flags override any accidental config change.
	r.cmd = exec.Command(r.Binary, "--conf="+filepath.Join(r.Directory, "i2pd.conf"), "--datadir="+r.Directory, "--certsdir=/usr/local/share/i2pd/certificates", "--notransit", "--share=0")
	r.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	r.cmd.Stdout = r.Output
	r.cmd.Stderr = r.Output
	if err := r.cmd.Start(); err != nil {
		r.cmd = nil
		return err
	}
	r.startedAt, r.verified = time.Now(), false
	r.done = make(chan error, 1)
	c, done := r.cmd, r.done
	go func() { done <- c.Wait() }()
	return nil
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
func (r *ExecRouter) Stop(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd == nil {
		return nil
	}
	_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGTERM)
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-r.done:
	case <-timer.C:
		_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGKILL)
		<-r.done
	case <-ctx.Done():
		_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGKILL)
		<-r.done
	}
	r.cmd = nil
	return nil
}
func (r *ExecRouter) rpc(ctx context.Context, method string, params map[string]any) (map[string]json.RawMessage, error) {
	cert, err := os.ReadFile(filepath.Join(r.Directory, "control.crt"))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(cert)
	if block == nil {
		return nil, errors.New("I2P control certificate unavailable")
	}
	transport := &http.Transport{DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(r.Directory, "control.sock"))
		if err != nil {
			return nil, err
		}
		t := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, VerifyConnection: func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) == 0 || subtle.ConstantTimeCompare(s.PeerCertificates[0].Raw, block.Bytes) != 1 {
				return errors.New("I2P control certificate mismatch")
			}
			return nil
		}})
		if err = t.HandshakeContext(ctx); err != nil {
			c.Close()
			return nil, err
		}
		return t, nil
	}}
	defer transport.CloseIdleConnections()
	payload, _ := json.Marshal(map[string]any{"id": 1, "jsonrpc": "2.0", "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, "POST", "https://localhost/", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var reply struct {
		Result map[string]json.RawMessage `json:"result"`
		Error  json.RawMessage            `json:"error"`
	}
	if err = json.NewDecoder(io.LimitReader(res.Body, 65536)).Decode(&reply); err != nil {
		return nil, err
	}
	if len(reply.Error) > 0 || reply.Result == nil {
		return nil, errors.New("I2P control rejected request")
	}
	return reply.Result, nil
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
