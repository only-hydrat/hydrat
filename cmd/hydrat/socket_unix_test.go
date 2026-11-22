//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFlowControlPreservesNewAgentSocketParentAccess(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "new-agent")
	path, err := flowControlSocket(filepath.Join(parent, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(parent); err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("agent socket parent must remain traversable: info=%v err=%v", info, err)
	}
	if path != filepath.Join(parent, "flow-control", "xray.sock") {
		t.Fatalf("path=%s", path)
	}
}
