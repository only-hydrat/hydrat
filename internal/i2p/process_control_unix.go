//go:build unix

package i2p

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

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
