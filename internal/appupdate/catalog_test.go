package appupdate

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUpdateChecksOnlyStableAppReleasesForThisPlatform(t *testing.T) {
	asset := func(tag, name string) map[string]string {
		return map[string]string{"name": name, "state": "uploaded",
			"browser_download_url": "https://github.com/only-hydrat/hydrat/releases/download/" + tag + "/" + name}
	}
	releases := []map[string]any{
		{"tag_name": "v99.0.0"},
		{"tag_name": "app-v1.0.0", "prerelease": true, "assets": []any{asset("app-v1.0.0", "Hydrat-windows-x64-1.0.0.msi")}},
		{"tag_name": "app-v0.3.0", "draft": true},
		{"tag_name": "app-v0.4.0", "assets": []any{asset("app-v0.4.0", "Hydrat-android-arm64-0.4.0.apk")}},
		{"tag_name": "app-v0.2.0", "assets": []any{asset("app-v0.2.0", "Hydrat-windows-x64-0.2.0.msi")}},
		{"tag_name": "app-v0.9.0", "assets": []any{map[string]string{
			"name": "Hydrat-windows-x64-0.9.0.msi", "state": "uploaded", "browser_download_url": "https://example.org/fake.msi"}}},
	}
	body, err := json.Marshal(releases)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "api.github.com" || r.URL.Path != "/repos/only-hydrat/hydrat/releases" {
			t.Fatalf("unexpected catalog request: %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})}
	for _, test := range []struct {
		platform string
		current  string
		want     string
		newer    bool
	}{
		{"windows-amd64", "0.1.2", "0.2.0", true},
		{"windows-amd64", "0.2.0", "0.2.0", false},
		{"windows-amd64", "0.10.0", "0.2.0", false},
		{"android-arm64", "0.1.2", "0.4.0", true},
		{"linux-amd64", "0.1.2", "", false},
	} {
		t.Run(fmt.Sprintf("%s-%s", test.platform, test.current), func(t *testing.T) {
			got, err := check(t.Context(), client, test.platform, test.current)
			if err != nil || got.Current != test.current || got.Latest != test.want || (got.DownloadURL != "") != test.newer {
				t.Fatalf("offer = %+v, %v", got, err)
			}
		})
	}
}
