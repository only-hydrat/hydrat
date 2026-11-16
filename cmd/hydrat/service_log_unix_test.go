//go:build unix

package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/only-hydrat/hydrat/internal/retainedlog"
)

func TestOpenServiceLogAgentWritesGatewaySegmentWithPreparedOwnership(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "logs")
	t.Setenv("HYDRAT_LOG_DIR", directory)
	t.Setenv("HYDRAT_LOG_RETENTION", "72h")

	type preparation struct {
		path     string
		uid, gid int
	}
	var preparations []preparation
	writer, err := openServiceLogWithDirectoryPreparer("agent", func(path string, uid, gid int) error {
		preparations = append(preparations, preparation{path: path, uid: uid, gid: gid})
		return os.Mkdir(path, 0o750)
	})
	if err != nil {
		t.Fatalf("openServiceLogWithDirectoryPreparer: %v", err)
	}
	writeServiceLogLine(t, writer, "agent retained line")

	wantPreparations := []preparation{
		{path: directory, uid: 0, gid: 10001},
		{path: filepath.Join(directory, "gateway"), uid: 0, gid: 0},
		{path: filepath.Join(directory, "controller"), uid: 10001, gid: 10001},
	}
	if fmt.Sprint(preparations) != fmt.Sprint(wantPreparations) {
		t.Fatalf("preparations=%v, want %v", preparations, wantPreparations)
	}
	requireServiceLogContains(t, filepath.Join(directory, "gateway"), "gateway", "agent retained line")
	requireNoServiceSegments(t, directory, "gateway")
	requireNoServiceSegments(t, filepath.Join(directory, "controller"), "gateway")
}

func TestOpenServiceLogAgentFailsClosedWhenOwnershipCannotBeSet(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "logs")
	t.Setenv("HYDRAT_LOG_DIR", directory)
	t.Setenv("HYDRAT_LOG_RETENTION", "72h")
	denied := errors.New("chown denied")

	writer, err := openServiceLogWithDirectoryPreparer("agent", func(string, int, int) error { return denied })
	if writer != nil {
		_ = writer.Close()
		t.Fatal("ownership failure returned a writer")
	}
	if !errors.Is(err, denied) {
		t.Fatalf("error=%v, want chown failure", err)
	}
	matches, globErr := filepath.Glob(filepath.Join(directory, "gateway-*.log"))
	if globErr != nil {
		t.Fatalf("Glob: %v", globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("ownership failure created log segments: %v", matches)
	}
}

func TestOpenServiceLogControllerWritesControllerSegmentInPreparedDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "logs")
	controllerDirectory := filepath.Join(directory, "controller")
	if err := os.MkdirAll(controllerDirectory, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Setenv("HYDRAT_LOG_DIR", directory)
	t.Setenv("HYDRAT_LOG_RETENTION", "72h")

	writer, err := openServiceLog("controller")
	if err != nil {
		t.Fatalf("openServiceLog: %v", err)
	}
	writeServiceLogLine(t, writer, "controller retained line")
	requireServiceLogContains(t, controllerDirectory, "controller", "controller retained line")
	requireNoServiceSegments(t, directory, "controller")
	requireNoServiceSegments(t, filepath.Join(directory, "gateway"), "controller")
}

func TestOpenServiceLogControllerRequiresPrecreatedServiceDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "logs")
	if err := os.MkdirAll(directory, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Setenv("HYDRAT_LOG_DIR", directory)
	t.Setenv("HYDRAT_LOG_RETENTION", "72h")

	writer, err := openServiceLog("controller")
	if writer != nil {
		_ = writer.Close()
		t.Fatal("openServiceLog returned a writer without a precreated controller directory")
	}
	if err == nil {
		t.Fatal("openServiceLog created the controller directory")
	}
	if _, statErr := os.Lstat(filepath.Join(directory, "controller")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("controller directory exists after rejected open: %v", statErr)
	}
}

func TestOpenServiceLogRejectsInvalidConfiguration(t *testing.T) {
	absoluteDirectory := filepath.Join(t.TempDir(), "logs")
	for _, test := range []struct {
		name      string
		command   string
		directory string
		retention string
	}{
		{name: "wrong retention", command: "controller", directory: absoluteDirectory, retention: "71h"},
		{name: "relative directory", command: "controller", directory: "logs", retention: "72h"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("HYDRAT_LOG_DIR", test.directory)
			t.Setenv("HYDRAT_LOG_RETENTION", test.retention)
			writer, err := openServiceLog(test.command)
			if err == nil {
				if writer != nil {
					_ = writer.Close()
				}
				t.Fatal("openServiceLog succeeded, want error")
			}
		})
	}
}

func TestOpenServiceLogIgnoresUnsupportedCommand(t *testing.T) {
	t.Setenv("HYDRAT_LOG_DIR", "relative")
	t.Setenv("HYDRAT_LOG_RETENTION", "71h")
	writer, err := openServiceLog("backup")
	if err != nil {
		t.Fatalf("openServiceLog: %v", err)
	}
	if writer != nil {
		_ = writer.Close()
		t.Fatal("openServiceLog returned a writer for unsupported command")
	}
}

func TestRunInitializesServiceLogBeforeYAMLLoadThenRestoresAndClosesIt(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "logs")
	controllerDirectory := filepath.Join(directory, "controller")
	if err := os.MkdirAll(controllerDirectory, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Setenv("HYDRAT_LOG_DIR", directory)
	t.Setenv("HYDRAT_LOG_RETENTION", "72h")
	t.Setenv("HYDRAT_CONFIG", filepath.Join(t.TempDir(), "missing.yml"))

	previousArgs := os.Args
	os.Args = []string{"hydrat", "controller"}
	t.Cleanup(func() { os.Args = previousArgs })

	var previous bytes.Buffer
	previousOutput := log.Writer()
	log.SetOutput(&previous)
	t.Cleanup(func() { log.SetOutput(previousOutput) })

	var opened *retainedlog.Writer
	err := runWithServiceLogOpener(func(command string) (*retainedlog.Writer, error) {
		var openErr error
		opened, openErr = openServiceLog(command)
		return opened, openErr
	})
	if err == nil || !strings.Contains(err.Error(), "open config") {
		t.Fatalf("run error=%v, want config load error", err)
	}
	if opened == nil {
		t.Fatal("service log was not opened before config load")
	}
	if log.Writer() != &previous {
		t.Fatal("run did not restore the previous logger output")
	}
	if _, err := opened.Write([]byte("after close")); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("write after run error=%v, want os.ErrClosed", err)
	}
	requireServiceLogContains(t, controllerDirectory, "controller", "open config")
}

func writeServiceLogLine(t *testing.T, writer *retainedlog.Writer, line string) {
	t.Helper()
	previous := log.Writer()
	log.SetOutput(writer)
	log.Print(line)
	log.SetOutput(previous)
	if err := writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func requireServiceLogContains(t *testing.T, directory, service, text string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(directory, service+"-*.log"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	for _, path := range matches {
		if filepath.Base(path) == service+"-current.log" {
			continue
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", path, err)
		}
		if strings.Contains(string(contents), text) {
			return
		}
	}
	t.Fatalf("no %s log segment contains %q; matches=%v", service, text, matches)
}

func requireNoServiceSegments(t *testing.T, directory, service string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(directory, service+"-*.log"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("unexpected %s log segments in %s: %v", service, directory, matches)
	}
}
