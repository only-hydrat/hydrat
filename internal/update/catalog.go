package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

const (
	repository    = "ghcr.io/only-hydrat/hydrat"
	latestRelease = "https://api.github.com/repos/only-hydrat/hydrat/releases/latest"
)

var (
	versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})(\.(0|[1-9][0-9]{0,5})){2}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Versions struct {
	Hydrat string `json:"hydrat"`
}

type Offer struct {
	Version string `json:"version"`
	Manual  bool   `json:"manual,omitempty"`
}

func findOffers(ctx context.Context, client *http.Client, current Versions) (map[string]Offer, error) {
	var release struct {
		Tag        string `json:"tag_name"`
		Draft      bool
		Prerelease bool
	}
	if err := fetchJSON(ctx, client, latestRelease, &release); err != nil {
		return nil, fmt.Errorf("Hydrat release: %w", err)
	}
	v, prefixed := strings.CutPrefix(release.Tag, "v")
	if release.Draft || release.Prerelease || !prefixed || !validVersion(v) {
		return nil, errors.New("invalid stable Hydrat release")
	}
	if newer(v, current.Hydrat) {
		return map[string]Offer{"hydrat": {Version: v}}, nil
	}
	return nil, nil
}

func fetchJSON(ctx context.Context, client *http.Client, url string, value any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return decodeJSON(io.LimitReader(resp.Body, 128<<10), value)
}

func decodeJSON(r io.Reader, value any) error {
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("unexpected data after JSON")
	}
	return nil
}

func validVersion(v string) bool { return versionPattern.MatchString(v) }

func newer(version, current string) bool {
	if !validVersion(version) || !validVersion(current) {
		return false
	}
	var a, b [3]int
	for i, component := range strings.Split(version, ".") {
		a[i], _ = strconv.Atoi(component)
	}
	for i, component := range strings.Split(current, ".") {
		b[i], _ = strconv.Atoi(component)
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}
