package freesubs

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"
)

// TestLiveCatalogDiscovery hits the real catalog. It is skipped by default and
// runs only with HYDRAT_LIVE_FREESUBS=1, e.g. when checking that the shipped
// feed list still answers.
func TestLiveCatalogDiscovery(t *testing.T) {
	if os.Getenv("HYDRAT_LIVE_FREESUBS") != "1" {
		t.Skip("set HYDRAT_LIVE_FREESUBS=1 to check the live catalog")
	}
	discovery := New(Options{Client: &http.Client{Timeout: 60 * time.Second}})
	report := discovery.Run(context.Background())
	t.Logf("checked=%d usable=%d candidates=%d reality=%d failed=%d",
		report.Checked, report.Usable, report.Candidates, report.Reality, report.Failed)
	for _, feed := range report.Feeds {
		t.Logf("%-40s candidates=%5d reality=%5d format=%-7s error=%s",
			feed.Label, feed.Candidates, feed.Reality, feed.Format, feed.Error)
	}
	if report.Usable == 0 {
		t.Fatal("no usable free feed found")
	}
	if report.Reality == 0 {
		t.Fatal("no REALITY links found in live feeds")
	}
}
