package platform_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/only-hydrat/hydrat/internal/platform"
)

// The refusal type is shared by every Windows stub, so its contract is checked
// on every platform: the Linux CI job runs this test even though no Linux code
// path returns it.
func TestUnsupportedErrorKeepsFeatureInMessage(t *testing.T) {
	err := platform.Unsupported("Tor process groups")
	if err == nil {
		t.Fatal("Unsupported returned nil")
	}
	const want = "Tor process groups: unsupported on windows"
	if err.Error() != want {
		t.Fatalf("message=%q, want %q", err.Error(), want)
	}
}

func TestUnsupportedErrorSurvivesWrapping(t *testing.T) {
	wrapped := fmt.Errorf("start agent: %w", platform.Unsupported("Unix socket transport"))
	var unsupported *platform.UnsupportedError
	if !errors.As(wrapped, &unsupported) {
		t.Fatalf("errors.As failed for %v", wrapped)
	}
	if unsupported.Feature != "Unix socket transport" {
		t.Fatalf("feature=%q", unsupported.Feature)
	}
}

func TestUnsupportedErrorIsNotConfusedWithOtherErrors(t *testing.T) {
	var unsupported *platform.UnsupportedError
	if errors.As(errors.New("dial tcp: connection refused"), &unsupported) {
		t.Fatal("plain error matched *platform.UnsupportedError")
	}
}
