//go:build unix

package torpool

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestProbeCandidateCreatesNestedDataDirectoryBeforeStartingTor(t *testing.T) {
	baseDir := filepath.Join(t.TempDir(), "tor", "profiles")
	runner := &dataDirCheckingRunner{}
	manager, err := NewManager(Config{
		DataDir: baseDir, ExplorerProfiles: 1,
	}, runner)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	profile, err := manager.ProbeCandidate(context.Background(), Candidate{
		ID:     "bridge",
		Bridge: "Bridge 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567",
	})
	if err != nil {
		t.Fatal(err)
	}
	if runner.checked != profile.DataDir {
		t.Fatalf("checked data directory=%q, want %q", runner.checked, profile.DataDir)
	}
	info, err := os.Stat(profile.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("profile data directory mode=%v", info.Mode())
	}
}
