package i2p

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddressAndConflictPagesAreComplete(t *testing.T) {
	b, err := OpenBook(filepath.Join(t.TempDir(), "book"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	dest := strings.Repeat("a", 52) + ".b32.i2p"
	var text strings.Builder
	for i := 0; i < 123; i++ {
		fmt.Fprintf(&text, "site-%03d.i2p=%s\n", i, dest)
	}
	if err := b.ApplyImport(b.Preview(text.String()), "manual", false); err != nil {
		t.Fatal(err)
	}
	a, _ := NewAdmin(b, ControlClient{}, filepath.Join(t.TempDir(), "settings"), "", true)
	a.config.Subscriptions = []Subscription{{ID: "feed", Conflicts: b.List()}}
	for _, path := range []string{"/", "/subscriptions/feed/conflicts"} {
		names := map[string]bool{}
		offset := 0
		for count := 0; count < 30; count++ {
			w := httptest.NewRecorder()
			a.ServeHTTP(w, httptest.NewRequest("GET", fmt.Sprintf("%s?offset=%d", path, offset), nil))
			var result struct {
				Entries []Entry `json:"entries"`
				Total   int     `json:"total"`
				Next    *int    `json:"next_offset"`
			}
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
				t.Fatal(path, w.Code, w.Body.String())
			}
			if result.Total != 123 || len(result.Entries) > 50 {
				t.Fatal(path, "missing bounded page", result.Total, len(result.Entries))
			}
			for _, e := range result.Entries {
				if names[e.Name] {
					t.Fatal("duplicate page entry")
				}
				names[e.Name] = true
			}
			if result.Next == nil {
				break
			}
			offset = *result.Next
		}
		if len(names) != 123 {
			t.Fatal(path, "lost entries", len(names))
		}
	}
}
