package retainedlog

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	timestampLayout       = "20060102T150405Z"
	maxDiagnosticSize     = 2048
	temporaryNameAttempts = 100
)

var (
	servicePattern             = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	writerTestHooksByDirectory sync.Map
)

// Config defines the storage and retention policy for a Writer.
type Config struct {
	Directory       string
	Service         string
	Retention       time.Duration
	SegmentDuration time.Duration
	CleanupInterval time.Duration
	Now             func() time.Time
	Remove          func(string) error
}

type writerTestHooks struct {
	beforePruneRename func(string)
	beforeCurrentLink func(string)
	cleanupTicks      <-chan time.Time
	stopCleanupTicks  func()
	afterDiagnostic   func()
}

// Writer writes a service log to retained UTC time segments.
type Writer struct {
	mu           sync.Mutex
	config       Config
	directory    *os.File
	customRemove bool
	testHooks    *writerTestHooks
	file         *os.File
	segmentStart time.Time
	closed       bool

	stop chan struct{}
	done chan struct{}

	closeOnce sync.Once
	closeErr  error
}

// Open creates a retained log writer and performs the initial cleanup.
func Open(config Config) (*Writer, error) {
	customRemove := config.Remove != nil
	if err := prepareConfig(&config); err != nil {
		return nil, err
	}
	directory, err := openDirectory(config.Directory, false)
	if err != nil {
		return nil, err
	}

	writer := &Writer{
		config:       config,
		directory:    directory,
		customRemove: customRemove,
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
	}
	if hooks, ok := writerTestHooksByDirectory.Load(config.Directory); ok {
		writer.testHooks = hooks.(*writerTestHooks)
	}
	now := config.Now().UTC()
	writer.mu.Lock()
	openErr := writer.openSegmentLocked(now.Truncate(config.SegmentDuration))
	writer.mu.Unlock()
	if openErr != nil {
		writer.mu.Lock()
		closeErr := writer.closeResourcesLocked()
		writer.closed = true
		writer.mu.Unlock()
		return nil, errors.Join(openErr, closeErr)
	}

	writer.mu.Lock()
	cleanup := writer.pruneLocked(now)
	writer.mu.Unlock()
	if structuralErr := cleanup.structuralError(); structuralErr != nil {
		maintenanceErr := errors.Join(structuralErr, cleanup.removalError())
		writer.mu.Lock()
		closeErr := writer.closeResourcesLocked()
		writer.closed = true
		writer.mu.Unlock()
		return nil, errors.Join(fmt.Errorf("initial log maintenance: %w", maintenanceErr), closeErr)
	}
	if removalErr := cleanup.removalError(); removalErr != nil {
		writer.writeDiagnostic(withErrorContext("initial log cleanup", removalErr))
	}

	if config.CleanupInterval > 0 {
		go writer.maintenanceLoop()
	} else {
		close(writer.done)
	}
	return writer, nil
}

func prepareConfig(config *Config) error {
	if config.Directory == "" || !filepath.IsAbs(config.Directory) || filepath.Clean(config.Directory) != config.Directory {
		return fmt.Errorf("log directory must be an absolute clean path: %q", config.Directory)
	}
	if !servicePattern.MatchString(config.Service) {
		return fmt.Errorf("invalid log service %q", config.Service)
	}
	if config.Retention <= 0 {
		return fmt.Errorf("log retention must be positive: %s", config.Retention)
	}
	if config.SegmentDuration <= 0 {
		return fmt.Errorf("log segment duration must be positive: %s", config.SegmentDuration)
	}
	if config.Retention < config.SegmentDuration {
		return fmt.Errorf("log retention %s is shorter than segment duration %s", config.Retention, config.SegmentDuration)
	}
	if config.CleanupInterval < 0 {
		return fmt.Errorf("log cleanup interval must not be negative: %s", config.CleanupInterval)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Remove == nil {
		config.Remove = os.Remove
	}
	return nil
}

// PrepareDirectory securely creates and opens directory without following
// symbolic links, applies mode 0750, and sets ownership on the open descriptor.
func PrepareDirectory(directory string, uid, gid int) error {
	return prepareDirectoryWithOwner(directory, func(directoryFD int) error {
		return unix.Fchown(directoryFD, uid, gid)
	})
}

func prepareDirectoryWithOwner(directory string, setOwner func(int) error) error {
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return fmt.Errorf("log directory must be an absolute clean path: %q", directory)
	}
	if setOwner == nil {
		return errors.New("log directory ownership operation is required")
	}
	directoryFile, err := openDirectory(directory, true)
	if err != nil {
		return err
	}
	if err := setOwner(int(directoryFile.Fd())); err != nil {
		return errors.Join(fmt.Errorf("chown log directory: %w", err), directoryFile.Close())
	}
	return directoryFile.Close()
}

func openDirectory(directory string, create bool) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	fd, err := unix.Open(string(filepath.Separator), flags, 0)
	if err != nil {
		return nil, fmt.Errorf("open log directory root: %w", err)
	}

	walkPath := platformDirectoryPath(directory)
	components := strings.Split(strings.TrimPrefix(walkPath, string(filepath.Separator)), string(filepath.Separator))
	for _, component := range components {
		if component == "" {
			continue
		}
		nextFD, openErr := unix.Openat(fd, component, flags, 0)
		if create && errors.Is(openErr, unix.ENOENT) {
			mkdirErr := unix.Mkdirat(fd, component, 0o750)
			if mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = unix.Close(fd)
				return nil, fmt.Errorf("create log directory component %q: %w", component, mkdirErr)
			}
			nextFD, openErr = unix.Openat(fd, component, flags, 0)
		}
		if openErr != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("open log directory component %q without following links: %w", component, openErr)
		}
		_ = unix.Close(fd)
		fd = nextFD
	}

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("inspect log directory: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("log directory is not a directory: %s", directory)
	}
	if err := unix.Fchmod(fd, 0o750); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("chmod log directory: %w", err)
	}

	file := os.NewFile(uintptr(fd), directory)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create log directory handle")
	}
	return file, nil
}

func (writer *Writer) openSegmentLocked(start time.Time) error {
	name := writer.config.Service + "-" + start.UTC().Format(timestampLayout) + ".log"
	file, err := openRegularFileAt(int(writer.directory.Fd()), name)
	if err != nil {
		return fmt.Errorf("open log segment: %w", err)
	}

	temporary, err := writer.createCurrentLink(name)
	if err != nil {
		_ = file.Close()
		return err
	}
	current := writer.config.Service + "-current.log"
	if err := unix.Renameat(int(writer.directory.Fd()), temporary, int(writer.directory.Fd()), current); err != nil {
		_ = unix.Unlinkat(int(writer.directory.Fd()), temporary, 0)
		_ = file.Close()
		return fmt.Errorf("replace current log link: %w", err)
	}

	if writer.file != nil {
		_ = writer.file.Close()
	}
	writer.file = file
	writer.segmentStart = start.UTC()
	return nil
}

func openRegularFileAt(directoryFD int, name string) (*os.File, error) {
	flags := unix.O_CREAT | unix.O_APPEND | unix.O_WRONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	var fd int
	var err error
	for range 3 {
		fd, err = unix.Openat(directoryFD, name, flags, 0o640)
		if !errors.Is(err, unix.ENOENT) {
			break
		}
	}
	if err != nil {
		return nil, err
	}

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("inspect opened log segment: %w", err)
	}
	if err := validateOpenedSegment(&stat, name); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := unix.Fchmod(fd, 0o640); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("chmod log segment: %w", err)
	}

	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create log segment file handle")
	}
	return file, nil
}

func validateOpenedSegment(stat *unix.Stat_t, name string) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("opened log segment is not a regular file: %s", name)
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("opened log segment uid is %d, want %d: %s", stat.Uid, os.Geteuid(), name)
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("opened log segment link count is %d, want 1: %s", stat.Nlink, name)
	}
	return nil
}

func (writer *Writer) createCurrentLink(target string) (string, error) {
	directoryFD := int(writer.directory.Fd())
	for range temporaryNameAttempts {
		temporary, err := writer.temporaryName("current")
		if err != nil {
			return "", fmt.Errorf("name current log link temporary: %w", err)
		}
		if writer.testHooks != nil && writer.testHooks.beforeCurrentLink != nil {
			writer.testHooks.beforeCurrentLink(temporary)
		}
		err = unix.Symlinkat(target, directoryFD, temporary)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("create current log link: %w", err)
		}
		return temporary, nil
	}
	return "", fmt.Errorf("create current log link: exhausted unique temporary names")
}

func (writer *Writer) temporaryName(purpose string) (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf(".%s-%s.%s.tmp", writer.config.Service, purpose, hex.EncodeToString(random[:])), nil
}

// Write appends body to the current UTC segment, rotating first if needed.
func (writer *Writer) Write(body []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.closed {
		return 0, os.ErrClosed
	}

	start := writer.config.Now().UTC().Truncate(writer.config.SegmentDuration)
	if writer.file == nil || !start.Equal(writer.segmentStart) {
		if err := writer.openSegmentLocked(start); err != nil {
			return 0, err
		}
	}
	n, err := writer.file.Write(body)
	if err == nil && n != len(body) {
		err = io.ErrShortWrite
	}
	return n, err
}

// Maintain rotates an idle writer and removes expired closed segments.
func (writer *Writer) Maintain(now time.Time) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.closed {
		return os.ErrClosed
	}

	now = now.UTC()
	start := now.Truncate(writer.config.SegmentDuration)
	if writer.file == nil || !start.Equal(writer.segmentStart) {
		if err := writer.openSegmentLocked(start); err != nil {
			return err
		}
	}
	return writer.pruneLocked(now).err()
}

type pruneResult struct {
	structural []error
	removal    []error
}

func (result pruneResult) structuralError() error { return errors.Join(result.structural...) }
func (result pruneResult) removalError() error    { return errors.Join(result.removal...) }
func (result pruneResult) err() error {
	return errors.Join(result.structuralError(), result.removalError())
}

func (writer *Writer) pruneLocked(now time.Time) pruneResult {
	entries, err := readDirectoryAt(int(writer.directory.Fd()))
	if err != nil {
		return pruneResult{structural: []error{fmt.Errorf("read log directory: %w", err)}}
	}

	prefix := writer.config.Service + "-"
	cutoff := now.UTC().Add(-writer.config.Retention)
	var result pruneResult
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		name := entry.Name()
		segmentStart, ok := parseSegmentName(name, prefix)
		if !ok || segmentStart.Equal(writer.segmentStart) || segmentStart.Add(writer.config.SegmentDuration).After(cutoff) {
			continue
		}

		candidateFD, err := unix.Openat(
			int(writer.directory.Fd()),
			name,
			unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
			0,
		)
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ELOOP) {
			continue
		}
		if err != nil {
			result.structural = append(result.structural, fmt.Errorf("open expired log segment %s without following links: %w", name, err))
			continue
		}
		var expected unix.Stat_t
		err = unix.Fstat(candidateFD, &expected)
		if err != nil {
			_ = unix.Close(candidateFD)
			result.structural = append(result.structural, fmt.Errorf("inspect expired log segment %s: %w", name, err))
			continue
		}
		if expected.Mode&unix.S_IFMT != unix.S_IFREG {
			_ = unix.Close(candidateFD)
			continue
		}

		removalErr, structuralErr := writer.removeValidatedSegment(name, expected)
		_ = unix.Close(candidateFD)
		if removalErr != nil {
			result.removal = append(result.removal, withErrorContext("remove expired log segment "+name, removalErr))
		}
		if structuralErr != nil {
			result.structural = append(result.structural, fmt.Errorf("secure expired log segment %s: %w", name, structuralErr))
		}
	}
	return result
}

func readDirectoryAt(directoryFD int) ([]os.DirEntry, error) {
	fd, err := unix.Openat(directoryFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), "retained-log-directory")
	if directory == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create directory enumeration handle")
	}
	defer directory.Close()
	return directory.ReadDir(-1)
}

func parseSegmentName(name, prefix string) (time.Time, bool) {
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".log") {
		return time.Time{}, false
	}
	timestamp := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".log")
	segmentStart, err := time.Parse(timestampLayout, timestamp)
	if err != nil || segmentStart.Format(timestampLayout) != timestamp {
		return time.Time{}, false
	}
	return segmentStart, true
}

func (writer *Writer) removeValidatedSegment(name string, expected unix.Stat_t) (error, error) {
	if writer.testHooks != nil && writer.testHooks.beforePruneRename != nil {
		writer.testHooks.beforePruneRename(name)
	}

	directoryFD := int(writer.directory.Fd())
	var quarantine string
	renamed := false
	for range temporaryNameAttempts {
		var nameErr error
		quarantine, nameErr = writer.temporaryName("prune")
		if nameErr != nil {
			return nil, fmt.Errorf("name quarantine temporary: %w", nameErr)
		}
		err := renameNoReplaceAt(directoryFD, name, directoryFD, quarantine)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if errors.Is(err, unix.ENOENT) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("quarantine candidate: %w", err)
		}
		renamed = true
		break
	}
	if !renamed {
		return nil, fmt.Errorf("quarantine candidate: exhausted unique temporary names")
	}

	var quarantined unix.Stat_t
	if err := unix.Fstatat(directoryFD, quarantine, &quarantined, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		restoreErr := restoreQuarantined(directoryFD, quarantine, name)
		return nil, errors.Join(fmt.Errorf("inspect quarantined candidate: %w", err), restoreErr)
	}
	if !sameInode(expected, quarantined) || quarantined.Mode&unix.S_IFMT != unix.S_IFREG {
		if err := restoreQuarantined(directoryFD, quarantine, name); err != nil {
			return nil, fmt.Errorf("restore concurrently replaced entry from %s: %w", quarantine, err)
		}
		return nil, nil
	}

	if err := writer.removeQuarantined(quarantine); err != nil {
		restoreErr := restoreQuarantined(directoryFD, quarantine, name)
		return err, restoreErr
	}
	return nil, nil
}

func sameInode(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino
}

func restoreQuarantined(directoryFD int, quarantine, name string) error {
	if err := renameNoReplaceAt(directoryFD, quarantine, directoryFD, name); err != nil {
		return fmt.Errorf("restore quarantined entry %s: %w", quarantine, err)
	}
	return nil
}

func (writer *Writer) removeQuarantined(quarantine string) error {
	directoryFD := int(writer.directory.Fd())
	if writer.customRemove {
		path, err := anchoredRemovalPath(directoryFD, quarantine)
		if err != nil {
			return fmt.Errorf("resolve anchored custom removal path: %w", err)
		}
		if err := writer.config.Remove(path); err != nil {
			return err
		}
		var stat unix.Stat_t
		err = unix.Fstatat(directoryFD, quarantine, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect custom removal result: %w", err)
		}
	}
	if err := unix.Unlinkat(directoryFD, quarantine, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

func (writer *Writer) maintenanceLoop() {
	ticks, stopTicker := writer.maintenanceTicks()
	defer close(writer.done)
	defer stopTicker()
	for {
		select {
		case <-writer.stop:
			return
		case tick, ok := <-ticks:
			if !ok {
				return
			}
			if err := writer.Maintain(tick.UTC()); err != nil {
				writer.writeDiagnostic(err)
			}
		}
	}
}

func (writer *Writer) maintenanceTicks() (<-chan time.Time, func()) {
	if writer.testHooks != nil && writer.testHooks.cleanupTicks != nil {
		stop := writer.testHooks.stopCleanupTicks
		if stop == nil {
			stop = func() {}
		}
		return writer.testHooks.cleanupTicks, stop
	}
	ticker := time.NewTicker(writer.config.CleanupInterval)
	return ticker.C, ticker.Stop
}

func (writer *Writer) writeDiagnostic(maintenanceErr error) {
	message := diagnosticMessage(maintenanceErr)

	writer.mu.Lock()
	wrote := false
	if !writer.closed && writer.file != nil {
		_, _ = writer.file.Write(message)
		wrote = true
	}
	writer.mu.Unlock()

	if wrote && writer.testHooks != nil && writer.testHooks.afterDiagnostic != nil {
		writer.testHooks.afterDiagnostic()
	}
}

func diagnosticMessage(maintenanceErr error) []byte {
	var buffer bytes.Buffer
	limited := limitedWriter{writer: &buffer, remaining: maxDiagnosticSize - 1}
	_, _ = io.WriteString(&limited, "retained log maintenance failed: ")
	writeDiagnosticError(&limited, maintenanceErr)
	return append(buffer.Bytes(), '\n')
}

func writeDiagnosticError(writer io.Writer, maintenanceErr error) {
	defer func() {
		if recover() != nil {
			_, _ = io.WriteString(writer, "diagnostic formatting panic")
		}
	}()
	renderer := diagnosticErrorRenderer{writer: writer, remainingNodes: 64}
	_ = renderer.write(maintenanceErr, 0)
}

type contextualError struct {
	context string
	cause   error
}

func withErrorContext(context string, cause error) error {
	if cause == nil {
		return nil
	}
	return &contextualError{context: context, cause: cause}
}

func (err *contextualError) Error() string { return err.context + ": " + err.cause.Error() }
func (err *contextualError) Unwrap() error { return err.cause }

type diagnosticErrorRenderer struct {
	writer         io.Writer
	remainingNodes int
}

func (renderer *diagnosticErrorRenderer) write(err error, depth int) error {
	if err == nil {
		return nil
	}
	if renderer.remainingNodes == 0 || depth == 32 {
		_, writeErr := io.WriteString(renderer.writer, "[additional maintenance errors omitted]")
		return writeErr
	}
	renderer.remainingNodes--

	if contextual, ok := err.(*contextualError); ok {
		if _, writeErr := io.WriteString(renderer.writer, contextual.context+": "); writeErr != nil {
			return writeErr
		}
		return renderer.write(contextual.cause, depth+1)
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for index, child := range joined.Unwrap() {
			if index > 0 {
				if _, writeErr := io.WriteString(renderer.writer, "\n"); writeErr != nil {
					return writeErr
				}
			}
			if writeErr := renderer.write(child, depth+1); writeErr != nil {
				return writeErr
			}
		}
		return nil
	}
	if formatter, ok := err.(fmt.Formatter); ok {
		formatter.Format(diagnosticFormatState{Writer: renderer.writer}, 'v')
		return nil
	}
	_, writeErr := io.WriteString(renderer.writer, err.Error())
	return writeErr
}

type diagnosticFormatState struct {
	io.Writer
}

func (diagnosticFormatState) Width() (int, bool)     { return 0, false }
func (diagnosticFormatState) Precision() (int, bool) { return 0, false }
func (diagnosticFormatState) Flag(int) bool          { return false }

type limitedWriter struct {
	writer    io.Writer
	remaining int
}

func (writer *limitedWriter) Write(body []byte) (int, error) {
	if writer.remaining == 0 {
		return 0, io.ErrShortWrite
	}
	truncated := len(body) > writer.remaining
	if truncated {
		body = body[:writer.remaining]
	}
	n, err := writer.writer.Write(body)
	writer.remaining -= n
	if err == nil && (truncated || n != len(body)) {
		err = io.ErrShortWrite
	}
	return n, err
}

// Close stops background maintenance, flushes the active segment, and closes it.
func (writer *Writer) Close() error {
	writer.closeOnce.Do(func() {
		close(writer.stop)
		<-writer.done

		writer.mu.Lock()
		defer writer.mu.Unlock()
		writer.closed = true
		writer.closeErr = writer.closeResourcesLocked()
	})
	return writer.closeErr
}

func (writer *Writer) closeResourcesLocked() error {
	var fileErr error
	if writer.file != nil {
		file := writer.file
		writer.file = nil
		fileErr = errors.Join(file.Sync(), file.Close())
	}
	var directoryErr error
	if writer.directory != nil {
		directory := writer.directory
		writer.directory = nil
		directoryErr = directory.Close()
	}
	return errors.Join(fileErr, directoryErr)
}
