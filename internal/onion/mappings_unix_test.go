//go:build unix

package onion

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMappingsSurviveRestartAndNeverReuseAddresses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mappings.json")
	m, err := OpenMappings(path, "198.18.0.0/15", 2)
	if err != nil {
		t.Fatal(err)
	}
	first, err := m.Resolve(testHost(1))
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.Resolve(testHost(2))
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("address reused")
	}
	m, err = OpenMappings(path, "198.18.0.0/15", 2)
	if err != nil {
		t.Fatal(err)
	}
	again, err := m.Resolve(testHost(1))
	if err != nil || again != first {
		t.Fatalf("mapping changed: %v %v", again, err)
	}
	if _, err := m.Resolve(testHost(3)); err == nil {
		t.Fatal("capacity exceeded")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	if _, err := OpenMappings(path, "198.19.0.0/16", 2); err == nil {
		t.Fatal("pool changed with cached client addresses")
	}
}
