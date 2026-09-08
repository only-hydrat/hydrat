package retainedlog

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	testService = "gateway"
	segmentAge  = time.Hour
)

func TestOpenWriteAndMaintainRollsOverSegment(t *testing.T) {
	dir := t.TempDir()
	utcPlusSeven := time.FixedZone("UTC+7", 7*60*60)
	now := time.Date(2026, time.July, 22, 17, 0, 0, 0, utcPlusSeven)
	clock := now

	w, err := Open(testConfig(dir, &clock))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	first := segmentPath(dir, testService, now)
	requireExists(t, first, true)
	info, err := os.Stat(first)
	if err != nil {
		t.Fatalf("Stat first segment: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("first segment mode = %04o, want 0640", got)
	}

	if _, err := w.Write([]byte("first\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	contents, err := os.ReadFile(first)
	if err != nil {
		t.Fatalf("ReadFile first segment: %v", err)
	}
	if got := string(contents); got != "first\n" {
		t.Fatalf("first segment contents = %q, want %q", got, "first\n")
	}

	clock = clock.Add(segmentAge)
	if err := w.Maintain(clock); err != nil {
		t.Fatalf("Maintain: %v", err)
	}

	second := segmentPath(dir, testService, clock)
	requireExists(t, second, true)
	target, err := os.Readlink(filepath.Join(dir, testService+"-current.log"))
	if err != nil {
		t.Fatalf("Readlink current segment: %v", err)
	}
	if filepath.IsAbs(target) {
		t.Fatalf("current segment target = %q, want relative path", target)
	}
	resolvedTarget := filepath.Clean(filepath.Join(dir, target))
	if resolvedTarget != second {
		t.Fatalf("current segment target resolves to %q, want %q", resolvedTarget, second)
	}
	requireExists(t, resolvedTarget, true)
}

func TestMaintainPrunesOnlyExpiredRegularServiceSegments(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	clock := now
	w, err := Open(testConfig(dir, &clock))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	cutoff := now.Add(-72 * time.Hour)
	before := segmentPath(dir, testService, cutoff.Add(-segmentAge-time.Second))
	exact := segmentPath(dir, testService, cutoff.Add(-segmentAge))
	after := segmentPath(dir, testService, cutoff.Add(-segmentAge+time.Second))
	for _, path := range []string{before, exact, after} {
		writeRegularFile(t, path)
	}

	otherService := segmentPath(dir, "controller", cutoff.Add(-segmentAge))
	arbitrary := filepath.Join(dir, "notes.txt")
	directory := filepath.Join(dir, "archive")
	symlinkTarget := filepath.Join(dir, "symlink-target")
	symlink := segmentPath(dir, testService, cutoff.Add(-2*segmentAge))
	writeRegularFile(t, otherService)
	writeRegularFile(t, arbitrary)
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatalf("Mkdir unrelated directory: %v", err)
	}
	writeRegularFile(t, symlinkTarget)
	if err := os.Symlink(symlinkTarget, symlink); err != nil {
		t.Fatalf("Symlink matching-looking entry: %v", err)
	}

	if err := w.Maintain(now); err != nil {
		t.Fatalf("Maintain: %v", err)
	}

	requireExists(t, before, false)
	requireExists(t, exact, false)
	requireExists(t, after, true)
	requireExists(t, segmentPath(dir, testService, now), true)
	requireExists(t, filepath.Join(dir, testService+"-current.log"), true)
	for _, path := range []string{otherService, arbitrary, directory, symlink} {
		requireExists(t, path, true)
	}
}

func TestOpenAppliesRetentionCleanupAtStartup(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	clock := now
	w, err := Open(testConfig(dir, &clock))
	if err != nil {
		t.Fatalf("initial Open: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("initial Close: %v", err)
	}

	cutoff := now.Add(-72 * time.Hour)
	before := segmentPath(dir, testService, cutoff.Add(-segmentAge-time.Second))
	exact := segmentPath(dir, testService, cutoff.Add(-segmentAge))
	after := segmentPath(dir, testService, cutoff.Add(-segmentAge+time.Second))
	for _, path := range []string{before, exact, after} {
		writeRegularFile(t, path)
	}

	w, err = Open(testConfig(dir, &clock))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Errorf("reopened Close: %v", err)
		}
	})

	requireExists(t, before, false)
	requireExists(t, exact, false)
	requireExists(t, after, true)
}

func TestOpenDiagnosesStartupRemovalFailureAndRemainsWritable(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	clock := now
	expired := segmentPath(dir, testService, now.Add(-72*time.Hour-segmentAge))
	writeRegularFile(t, expired)

	denied := errors.New("denied")
	removeAttempts := 0
	config := testConfig(dir, &clock)
	config.Remove = func(string) error {
		removeAttempts++
		if removeAttempts == 1 {
			return denied
		}
		return nil
	}
	w, err := Open(config)
	if err != nil {
		t.Fatalf("Open after startup removal failure: %v", err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	if _, err := w.Write([]byte("still writable\n")); err != nil {
		t.Fatalf("Write after startup removal failure: %v", err)
	}
	contents, err := os.ReadFile(segmentPath(dir, testService, now))
	if err != nil {
		t.Fatalf("ReadFile current segment: %v", err)
	}
	if !strings.Contains(string(contents), "retained log maintenance failed: initial log cleanup") {
		t.Fatalf("current segment contents = %q, want startup maintenance diagnostic", contents)
	}
	if !strings.Contains(string(contents), "still writable") {
		t.Fatalf("current segment contents = %q, want caller write", contents)
	}
	requireExists(t, expired, true)
	if err := w.Maintain(now); err != nil {
		t.Fatalf("Maintain retry: %v", err)
	}
	if removeAttempts != 2 {
		t.Fatalf("removal attempts = %d, want 2", removeAttempts)
	}
	requireExists(t, expired, false)
}

func TestOpenFatalStructuralCleanupIncludesRemovalFailure(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	clock := now
	expired := segmentPath(dir, testService, now.Add(-72*time.Hour-segmentAge))
	writeRegularFile(t, expired)

	denied := errors.New("denied after removal")
	config := testConfig(dir, &clock)
	config.Remove = func(path string) error {
		if err := os.Remove(path); err != nil {
			return err
		}
		return denied
	}
	w, err := Open(config)
	if w != nil {
		_ = w.Close()
		t.Fatal("Open returned a writer after fatal structural cleanup")
	}
	if err == nil {
		t.Fatal("Open succeeded after fatal structural cleanup")
	}
	if !errors.Is(err, denied) {
		t.Fatalf("Open error = %v, want joined removal failure", err)
	}
}

func TestOpenRejectsInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	notDirectory := filepath.Join(dir, "not-a-directory")
	writeRegularFile(t, notDirectory)

	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"empty service", func(c *Config) { c.Service = "" }},
		{"absolute service", func(c *Config) { c.Service = filepath.Join(dir, "escape") }},
		{"parent escaping service", func(c *Config) { c.Service = "../escape" }},
		{"nested service", func(c *Config) { c.Service = "nested/service" }},
		{"non-positive retention", func(c *Config) { c.Retention = 0 }},
		{"negative retention", func(c *Config) { c.Retention = -time.Hour }},
		{"non-positive segment duration", func(c *Config) { c.SegmentDuration = 0 }},
		{"negative segment duration", func(c *Config) { c.SegmentDuration = -time.Hour }},
		{"retention shorter than segment", func(c *Config) { c.Retention = segmentAge - time.Second }},
		{"directory is a regular file", func(c *Config) { c.Directory = notDirectory }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := now
			config := testConfig(dir, &clock)
			tc.mutate(&config)
			w, err := Open(config)
			if err == nil {
				if w != nil {
					_ = w.Close()
				}
				t.Fatal("Open succeeded, want configuration error")
			}
		})
	}
}

func TestOpenRejectsMatchingSegmentSymlink(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	clock := now
	target := filepath.Join(t.TempDir(), "outside.log")
	if err := os.WriteFile(target, []byte("outside\n"), 0o600); err != nil {
		t.Fatalf("WriteFile target: %v", err)
	}
	if err := os.Symlink(target, segmentPath(dir, testService, now)); err != nil {
		t.Fatalf("Symlink current segment: %v", err)
	}

	w, err := Open(testConfig(dir, &clock))
	if err == nil {
		if w != nil {
			_ = w.Close()
		}
		t.Fatal("Open followed a matching segment symlink")
	}
	contents, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("ReadFile target: %v", readErr)
	}
	if got := string(contents); got != "outside\n" {
		t.Fatalf("target contents = %q, want unchanged", got)
	}
	info, statErr := os.Stat(target)
	if statErr != nil {
		t.Fatalf("Stat target: %v", statErr)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("target mode = %04o, want 0600", got)
	}
}

func TestOpenRejectsHardLinkedSegmentBeforeMutation(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	clock := now
	target := filepath.Join(t.TempDir(), "outside.log")
	if err := os.WriteFile(target, []byte("outside\n"), 0o600); err != nil {
		t.Fatalf("WriteFile target: %v", err)
	}
	if err := os.Chmod(target, 0o600); err != nil {
		t.Fatalf("Chmod target: %v", err)
	}
	if err := os.Link(target, segmentPath(dir, testService, now)); err != nil {
		t.Fatalf("Link current segment: %v", err)
	}

	w, err := Open(testConfig(dir, &clock))
	if err == nil {
		if w != nil {
			_ = w.Close()
		}
		t.Fatal("Open accepted a hard-linked segment")
	}
	contents, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("ReadFile target: %v", readErr)
	}
	if got := string(contents); got != "outside\n" {
		t.Fatalf("target contents = %q, want unchanged", got)
	}
	info, statErr := os.Stat(target)
	if statErr != nil {
		t.Fatalf("Stat target: %v", statErr)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("target mode = %04o, want 0600", got)
	}
}

func TestValidateOpenedSegmentRejectsUnexpectedOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "segment.log")
	writeRegularFile(t, path)
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		t.Fatalf("Stat segment: %v", err)
	}
	stat.Uid = uint32(os.Geteuid() + 1)

	if err := validateOpenedSegment(&stat, filepath.Base(path)); err == nil {
		t.Fatal("validateOpenedSegment accepted a segment owned by another uid")
	}
}

func TestOpenRejectsSymlinkedDirectoryComponent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(outside, alias); err != nil {
		t.Fatalf("Symlink directory component: %v", err)
	}

	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	clock := now
	config := testConfig(filepath.Join(alias, "logs"), &clock)
	w, err := Open(config)
	if err == nil {
		if w != nil {
			_ = w.Close()
		}
		t.Fatal("Open accepted a symlinked directory component")
	}
	requireExists(t, filepath.Join(outside, "logs"), false)
}

func TestOpenRequiresPreparedDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "missing")
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	clock := now

	w, err := Open(testConfig(directory, &clock))
	if w != nil {
		_ = w.Close()
		t.Fatal("Open returned a writer for an unprepared directory")
	}
	if err == nil {
		t.Fatal("Open created an unprepared directory")
	}
	if _, statErr := os.Lstat(directory); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unprepared directory exists after Open: %v", statErr)
	}
}

func TestPrepareDirectoryRejectsSymlinkBeforeOwnershipMutation(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	for _, test := range []struct {
		name      string
		directory string
		prepare   func(t *testing.T)
	}{
		{
			name:      "component",
			directory: filepath.Join(root, "alias", "logs"),
			prepare: func(t *testing.T) {
				t.Helper()
				if err := os.Symlink(outside, filepath.Join(root, "alias")); err != nil {
					t.Fatalf("Symlink component: %v", err)
				}
			},
		},
		{
			name:      "final",
			directory: filepath.Join(root, "logs"),
			prepare: func(t *testing.T) {
				t.Helper()
				if err := os.Symlink(outside, filepath.Join(root, "logs")); err != nil {
					t.Fatalf("Symlink final directory: %v", err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.prepare(t)
			ownershipMutated := false
			err := prepareDirectoryWithOwner(test.directory, func(int) error {
				ownershipMutated = true
				return nil
			})
			if err == nil {
				t.Fatal("PrepareDirectory accepted a symlinked path")
			}
			if ownershipMutated {
				t.Fatal("ownership mutation ran before the symlinked path was rejected")
			}
		})
	}
}

func TestPrepareDirectoryAppliesModeBeforeDescriptorOwnership(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "nested", "logs")
	ownerCalled := false
	err := prepareDirectoryWithOwner(directory, func(directoryFD int) error {
		ownerCalled = true
		var stat unix.Stat_t
		if err := unix.Fstat(directoryFD, &stat); err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			return fmt.Errorf("ownership descriptor mode = %o, want directory", stat.Mode)
		}
		if got := os.FileMode(stat.Mode).Perm(); got != 0o750 {
			return fmt.Errorf("ownership descriptor mode = %04o, want 0750", got)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("prepareDirectoryWithOwner: %v", err)
	}
	if !ownerCalled {
		t.Fatal("descriptor ownership operation was not called")
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatalf("Stat prepared directory: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o750 {
		t.Fatalf("prepared directory mode = %04o, want 0750", got)
	}
}

func TestWriterStaysAnchoredWhenDirectoryPathIsReplaced(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "logs")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatalf("Mkdir log directory: %v", err)
	}
	outside := t.TempDir()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	clock := now
	var customRemovalPath string
	config := testConfig(dir, &clock)
	config.Remove = func(path string) error {
		customRemovalPath = path
		return os.Remove(path)
	}
	w, err := Open(config)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	expiredName := filepath.Base(segmentPath(dir, testService, now.Add(-72*time.Hour-segmentAge)))
	writeRegularFile(t, filepath.Join(dir, expiredName))
	writeRegularFile(t, filepath.Join(outside, expiredName))

	anchored := filepath.Join(root, "anchored")
	if err := os.Rename(dir, anchored); err != nil {
		t.Fatalf("Rename directory: %v", err)
	}
	if err := os.Symlink(outside, dir); err != nil {
		t.Fatalf("Replace directory with symlink: %v", err)
	}

	clock = clock.Add(segmentAge)
	if _, err := w.Write([]byte("anchored\n")); err != nil {
		t.Fatalf("Write after directory replacement: %v", err)
	}
	if err := w.Maintain(clock); err != nil {
		t.Fatalf("Maintain after directory replacement: %v", err)
	}
	anchoredSegment := segmentPath(anchored, testService, clock)
	requireExists(t, anchoredSegment, true)
	contents, err := os.ReadFile(anchoredSegment)
	if err != nil {
		t.Fatalf("ReadFile anchored segment: %v", err)
	}
	if got := string(contents); got != "anchored\n" {
		t.Fatalf("anchored segment contents = %q, want %q", got, "anchored\n")
	}
	requireExists(t, segmentPath(outside, testService, clock), false)
	requireExists(t, filepath.Join(anchored, expiredName), false)
	requireExists(t, filepath.Join(outside, expiredName), true)
	if customRemovalPath == "" {
		t.Fatal("custom remover was not called")
	}
	removalDirectory, err := os.Stat(filepath.Dir(customRemovalPath))
	if err != nil {
		t.Fatalf("Stat custom removal directory: %v", err)
	}
	anchoredDirectory, err := os.Stat(anchored)
	if err != nil {
		t.Fatalf("Stat anchored directory: %v", err)
	}
	if !os.SameFile(removalDirectory, anchoredDirectory) {
		t.Fatalf("custom removal path %q was not anchored to retained directory", customRemovalPath)
	}
}

func TestMaintainReturnsRemovalErrorAndWriterRemainsUsable(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	clock := now
	config := testConfig(dir, &clock)
	denied := errors.New("denied")
	config.Remove = func(string) error { return denied }
	w, err := Open(config)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	current := segmentPath(dir, testService, now)
	expired := segmentPath(dir, testService, now.Add(-72*time.Hour-segmentAge))
	writeRegularFile(t, expired)

	if err := w.Maintain(now); !errors.Is(err, denied) {
		t.Fatalf("Maintain error = %v, want removal error", err)
	}
	requireExists(t, current, true)
	requireExists(t, expired, true)
	if _, err := w.Write([]byte("still writable\n")); err != nil {
		t.Fatalf("Write after failed cleanup: %v", err)
	}
}

func TestMaintainPreservesEntryReplacedAfterValidation(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	clock := now
	expired := segmentPath(dir, testService, now.Add(-72*time.Hour-segmentAge))
	writeRegularFile(t, expired)
	moved := expired + ".moved"
	target := filepath.Join(t.TempDir(), "outside.log")
	if err := os.WriteFile(target, []byte("outside\n"), 0o600); err != nil {
		t.Fatalf("WriteFile outside target: %v", err)
	}

	config := testConfig(dir, &clock)
	installWriterTestHooks(t, dir, &writerTestHooks{
		beforePruneRename: func(name string) {
			if name != filepath.Base(expired) {
				return
			}
			if err := os.Rename(expired, moved); err != nil {
				t.Fatalf("Rename validated segment: %v", err)
			}
			if err := os.Symlink(target, expired); err != nil {
				t.Fatalf("Replace validated segment with symlink: %v", err)
			}
		},
	})
	w, err := Open(config)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	info, err := os.Lstat(expired)
	if err != nil {
		t.Fatalf("Lstat replacement: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("replacement mode = %v, want symlink", info.Mode())
	}
	requireExists(t, moved, true)
	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile outside target: %v", err)
	}
	if got := string(contents); got != "outside\n" {
		t.Fatalf("outside target contents = %q, want unchanged", got)
	}
}

func TestConcurrentWritersUpdateCurrentLinkWithoutTempCollision(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	clock := now
	first, err := Open(testConfig(dir, &clock))
	if err != nil {
		t.Fatalf("Open first writer: %v", err)
	}
	second, err := Open(testConfig(dir, &clock))
	if err != nil {
		_ = first.Close()
		t.Fatalf("Open second writer: %v", err)
	}
	for _, writer := range []*Writer{first, second} {
		t.Cleanup(func() {
			if err := writer.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
	}

	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	hook := func(string) {
		ready <- struct{}{}
		<-release
	}
	for _, writer := range []*Writer{first, second} {
		writer.testHooks = &writerTestHooks{beforeCurrentLink: hook}
	}

	results := make(chan error, 2)
	next := now.Add(segmentAge)
	for _, writer := range []*Writer{first, second} {
		go func() {
			results <- writer.Maintain(next)
		}()
	}

	for range 2 {
		select {
		case <-ready:
		case err := <-results:
			close(release)
			t.Fatalf("Maintain completed before current-link barrier: %v", err)
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatal("timed out waiting for concurrent current-link updates")
		}
	}
	close(release)

	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Errorf("Maintain: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for concurrent Maintain")
		}
	}

	target, err := os.Readlink(filepath.Join(dir, testService+"-current.log"))
	if err != nil {
		t.Fatalf("Readlink current segment: %v", err)
	}
	if target != filepath.Base(segmentPath(dir, testService, next)) {
		t.Fatalf("current segment target = %q, want active segment", target)
	}
}

func TestMaintenanceTickWritesBoundedDiagnostic(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	clock := now
	ticks := make(chan time.Time, 1)
	diagnosticDone := make(chan struct{}, 1)
	maintenanceErr := &largeDiagnosticError{}
	config := testConfig(dir, &clock)
	config.CleanupInterval = time.Hour
	config.Remove = func(string) error { return maintenanceErr }
	installWriterTestHooks(t, dir, &writerTestHooks{
		cleanupTicks: ticks,
		afterDiagnostic: func() {
			diagnosticDone <- struct{}{}
		},
	})
	w, err := Open(config)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	expired := segmentPath(dir, testService, now.Add(-72*time.Hour-segmentAge))
	writeRegularFile(t, expired)
	ticks <- now
	select {
	case <-diagnosticDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ticker maintenance diagnostic")
	}

	contents, err := os.ReadFile(segmentPath(dir, testService, now))
	if err != nil {
		t.Fatalf("ReadFile current segment: %v", err)
	}
	if !strings.Contains(string(contents), "retained log maintenance failed: remove expired log segment") {
		t.Fatalf("current segment contents = %q, want ticker maintenance diagnostic", contents)
	}
	if len(contents) > maxDiagnosticSize {
		t.Fatalf("diagnostic size = %d, want at most %d", len(contents), maxDiagnosticSize)
	}
	if maintenanceErr.written > maxDiagnosticSize {
		t.Fatalf("formatted bytes = %d, want at most %d", maintenanceErr.written, maxDiagnosticSize)
	}
}

func TestWriteDiagnosticBoundsFormattingWork(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	clock := now
	w, err := Open(testConfig(dir, &clock))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	maintenanceErr := &largeDiagnosticError{}
	w.writeDiagnostic(maintenanceErr)
	if maintenanceErr.written > maxDiagnosticSize {
		t.Fatalf("formatted bytes = %d, want at most %d", maintenanceErr.written, maxDiagnosticSize)
	}
	contents, err := os.ReadFile(segmentPath(dir, testService, now))
	if err != nil {
		t.Fatalf("ReadFile current segment: %v", err)
	}
	if len(contents) > maxDiagnosticSize {
		t.Fatalf("diagnostic size = %d, want at most %d", len(contents), maxDiagnosticSize)
	}
	if len(contents) == 0 || contents[len(contents)-1] != '\n' {
		t.Fatalf("diagnostic = %q, want newline termination", contents)
	}
}

func TestCloseIsConcurrentAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	clock := now
	config := testConfig(dir, &clock)
	config.CleanupInterval = time.Hour
	installWriterTestHooks(t, dir, &writerTestHooks{cleanupTicks: make(chan time.Time)})
	w, err := Open(config)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	const callers = 32
	start := make(chan struct{})
	results := make(chan error, callers)
	for range callers {
		go func() {
			<-start
			results <- w.Close()
		}()
	}
	close(start)
	for range callers {
		select {
		case err := <-results:
			if err != nil {
				t.Errorf("Close: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for concurrent Close")
		}
	}
	if _, err := w.Write([]byte("closed\n")); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Write after Close error = %v, want os.ErrClosed", err)
	}
}

func TestCloseWaitsForMaintenanceTickerCleanup(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	clock := now
	stopStarted := make(chan struct{})
	releaseStop := make(chan struct{})
	config := testConfig(dir, &clock)
	config.CleanupInterval = time.Hour
	installWriterTestHooks(t, dir, &writerTestHooks{
		cleanupTicks: make(chan time.Time),
		stopCleanupTicks: func() {
			close(stopStarted)
			<-releaseStop
		},
	})
	w, err := Open(config)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	closed := make(chan error, 1)
	go func() { closed <- w.Close() }()
	select {
	case <-stopStarted:
	case <-time.After(2 * time.Second):
		close(releaseStop)
		t.Fatal("timed out waiting for maintenance ticker cleanup")
	}
	select {
	case err := <-closed:
		close(releaseStop)
		t.Fatalf("Close returned before ticker cleanup completed: %v", err)
	default:
	}
	close(releaseStop)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return after ticker cleanup completed")
	}
}

type largeDiagnosticError struct {
	written int
}

func installWriterTestHooks(t *testing.T, directory string, hooks *writerTestHooks) {
	t.Helper()
	if _, loaded := writerTestHooksByDirectory.LoadOrStore(directory, hooks); loaded {
		t.Fatalf("test hooks already installed for %s", directory)
	}
	t.Cleanup(func() {
		writerTestHooksByDirectory.Delete(directory)
	})
}

func (*largeDiagnosticError) Error() string { return "large diagnostic" }

func (err *largeDiagnosticError) Format(state fmt.State, _ rune) {
	chunk := []byte(strings.Repeat("x", 256))
	for err.written < 1<<20 {
		n, writeErr := state.Write(chunk)
		err.written += n
		if writeErr != nil {
			return
		}
	}
}

func testConfig(dir string, clock *time.Time) Config {
	return Config{
		Directory:       dir,
		Service:         testService,
		Retention:       72 * time.Hour,
		SegmentDuration: segmentAge,
		CleanupInterval: 0,
		Now:             func() time.Time { return *clock },
	}
}

func segmentPath(dir, service string, start time.Time) string {
	return filepath.Join(dir, fmt.Sprintf("%s-%s.log", service, start.UTC().Format("20060102T150405Z")))
}

func writeRegularFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("segment\n"), 0o640); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
}

func requireExists(t *testing.T, path string, want bool) {
	t.Helper()
	_, err := os.Lstat(path)
	if want && err != nil {
		t.Fatalf("expected %s: %v", path, err)
	}
	if !want && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected %s removed, err=%v", path, err)
	}
}
