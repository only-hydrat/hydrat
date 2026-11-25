// Package i18n provides the Hydrat interface catalog and locale selection.
package i18n

import (
	_ "embed"
	"encoding/json"
	"strconv"
	"strings"
)

//go:embed catalog/messages.json
var catalogJSON []byte

var catalog = readCatalog()

func readCatalog() map[string]map[string]string {
	var messages map[string]map[string]string
	if err := json.Unmarshal(catalogJSON, &messages); err != nil {
		panic(err)
	}
	return messages
}

// Select honors an explicit user choice, a configured default and then the
// detected locales in preference order. Russian is the fallback.
func Select(saved, configured, detected string) string {
	for _, preferred := range []string{saved, configured} {
		if supported(preferred) {
			return preferred
		}
	}
	best, weight := "ru", 0.0
	for _, item := range strings.Split(detected, ",") {
		tag, parameter, _ := strings.Cut(item, ";")
		base, _, _ := strings.Cut(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(tag)), "_", "-"), "-")
		switch base {
		case "zh":
			base = "zh-CN"
		case "en", "ru":
		default:
			continue
		}
		quality := 1.0
		if parameter != "" {
			value, ok := strings.CutPrefix(strings.TrimSpace(parameter), "q=")
			parsed, err := strconv.ParseFloat(value, 64)
			if !ok || err != nil || parsed > 1 {
				continue
			}
			quality = parsed
		}
		if quality > weight {
			best, weight = base, quality
		}
	}
	return best
}

func supported(locale string) bool {
	return locale == "ru" || locale == "en" || locale == "zh-CN"
}

func Text(locale, source string) string {
	if translated := catalog[locale][source]; translated != "" {
		return translated
	}
	return source
}

// MessagesJSON returns the catalog for a single locale for the browser UI.
func MessagesJSON(locale string) []byte {
	messages := catalog[locale]
	if messages == nil {
		return []byte("{}")
	}
	data, err := json.Marshal(messages)
	if err != nil {
		panic(err)
	}
	return data
}
