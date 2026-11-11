package onion

import (
	"crypto/sha3"
	"encoding/base32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testHost(seed byte) string {
	key := make([]byte, 32)
	key[0] = seed
	input := append([]byte(".onion checksum"), key...)
	input = append(input, 3)
	digest := sha3.Sum256(input)
	raw := append(key, digest[:2]...)
	raw = append(raw, 3)
	return strings.ToLower(base32.StdEncoding.EncodeToString(raw)) + ".onion"
}

func TestNamesValidateV3AndSubdomains(t *testing.T) {
	host := testHost(1)
	for _, valid := range []string{host, "www." + host, strings.ToUpper(host) + "."} {
		if _, err := Normalize(valid); err != nil {
			t.Fatal(err)
		}
	}
	for _, invalid := range []string{"example.com", "onion", "abc.onion", "-bad." + host, host + ".evil", host + "\r\nSIGNAL HALT", "b" + host[1:]} {
		if _, err := Normalize(invalid); err == nil {
			t.Fatalf("accepted invalid name %q", invalid)
		}
	}
}

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

func TestCorruptMappingsAreNotReset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mappings.json")
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenMappings(path, "198.18.0.0/15", 2); err == nil {
		t.Fatal("corruption silently reset")
	}
}

func TestMappingsRejectTrailingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mappings.json")
	data := `{"version":1,"pool":"198.18.0.0/15","hosts":{}} {}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenMappings(path, "198.18.0.0/15", 2); err == nil {
		t.Fatal("accepted trailing state")
	}
}
