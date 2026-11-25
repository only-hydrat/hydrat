package portal

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDashboardLanguage(t *testing.T) {
	for _, tc := range []struct {
		name, env, browser, saved, lang, title string
	}{
		{"browser", "", "de-DE,en-US;q=0.8", "", "en", "Control panel"},
		{"environment", "zh-CN", "ru-RU", "", "zh-CN", "控制面板"},
		{"saved", "zh-CN", "en-US", "ru", "ru", "Панель управления"},
		{"unsupported", "", "fr-FR", "", "ru", "Панель управления"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HYDRAT_PORTAL_LANGUAGE", tc.env)
			request := httptest.NewRequest("GET", "/", nil)
			request.Header.Set("Accept-Language", tc.browser)
			if tc.saved != "" {
				request.AddCookie(&http.Cookie{Name: portalLanguageCookie, Value: tc.saved})
			}
			result := httptest.NewRecorder()
			new(Server).dashboard(result, request)
			if result.Header().Get("Content-Language") != tc.lang ||
				!strings.Contains(result.Body.String(), `<html lang="`+tc.lang+`">`) ||
				!strings.Contains(result.Body.String(), tc.title) ||
				!strings.Contains(result.Body.String(), `id="routing-form"`) {
				t.Fatalf("wrong language or incomplete response for %s", tc.lang)
			}
		})
	}
}

func TestSaveDashboardLanguage(t *testing.T) {
	for _, tc := range []struct {
		form, site string
		status     int
	}{
		{"language=zh-CN", "same-origin", http.StatusSeeOther},
		{"language=", "same-origin", http.StatusSeeOther},
		{"language=unknown", "same-origin", http.StatusBadRequest},
		{"language=en", "cross-site", http.StatusForbidden},
	} {
		request := httptest.NewRequest("POST", "https://localhost/language", strings.NewReader(tc.form))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Sec-Fetch-Site", tc.site)
		result := httptest.NewRecorder()
		new(Server).saveLanguage(result, request)
		if result.Code != tc.status {
			t.Fatalf("%s: status=%d want %d", tc.form, result.Code, tc.status)
		}
		cookies := result.Result().Cookies()
		if tc.status == http.StatusSeeOther {
			if len(cookies) != 1 || cookies[0].Name != portalLanguageCookie ||
				cookies[0].Path != "/" || !cookies[0].HttpOnly || !cookies[0].Secure ||
				cookies[0].SameSite != http.SameSiteLaxMode {
				t.Fatalf("invalid language cookie: %v", cookies)
			}
		} else if len(cookies) != 0 {
			t.Fatalf("rejected request stored a cookie: %v", cookies)
		}
	}
}
