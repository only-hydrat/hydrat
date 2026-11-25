package i18n

import "testing"

func TestLanguagePrecedence(t *testing.T) {
	for _, tc := range []struct {
		saved, configured, detected, want string
	}{
		{"en", "zh-CN", "ru-RU", "en"},
		{"", "zh-CN", "en-US", "zh-CN"},
		{"", "", "de;q=0.9, en-GB;q=0.7, zh-Hans;q=0.1", "en"},
		{"", "", "zh-TW", "zh-CN"},
		{"", "", "de-DE", "ru"},
	} {
		if got := Select(tc.saved, tc.configured, tc.detected); got != tc.want {
			t.Errorf("Select(%q,%q,%q)=%q want %q", tc.saved, tc.configured, tc.detected, got, tc.want)
		}
	}
}

func TestMessagesAndPlaceholders(t *testing.T) {
	if Text("en", "Подключить") == "Подключить" || Text("zh-CN", "Система") == "Система" {
		t.Fatal("locale catalog does not contain the translated controls")
	}
	if Text("ru", "Подключить") != "Подключить" || Text("de", "Подключить") != "Подключить" {
		t.Fatal("Russian fallback changed")
	}
}
