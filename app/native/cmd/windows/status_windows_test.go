package main

import (
	"testing"

	"github.com/only-hydrat/hydrat/internal/device"
)

func TestConnectionState(t *testing.T) {
	for _, tc := range []struct {
		name, connection, want string
		status                 device.Status
	}{
		{"first launch", "disconnected", "Добавьте источник", device.Status{}},
		{"TCP only", "requested", "VPN подключён · UDP недоступен", device.Status{Sources: 1, Running: true, Connected: true, TCP: true}},
		{"UDP only", "requested", "VPN подключён · TCP недоступен", device.Status{Sources: 1, Running: true, Connected: true, UDP: true}},
		{"full VPN", "requested", "VPN подключён", device.Status{Sources: 1, Running: true, Connected: true, TCP: true, UDP: true}},
		{"long search", "requested", "Рабочий маршрут пока не найден", device.Status{Sources: 1, Running: true, SearchingSeconds: 30}},
		{"recovery", "requested", "Восстанавливаем подключение…", device.Status{Sources: 1, Running: true, Recovering: true}},
		{"stopped", "disconnected", "VPN отключён", device.Status{Sources: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := presentStatus(device.ControlStatus{Status: tc.status, Connection: tc.connection})
			if got != tc.want {
				t.Errorf("status = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestImportFeedbackKeepsProblemLines(t *testing.T) {
	const input = "saved source\r\nbad input\r\n\r\nretry source"
	report := device.ImportReport{Imported: 2, Unavailable: 1, RefreshFailed: 1, LineErrors: []device.ImportLineError{
		{Line: 2, Reason: "unsupported source format"},
		{Line: 4, Reason: "source refresh failed"},
	}}
	feedback := importFeedback(input, report, nil)
	if feedback.draft == nil || *feedback.draft != "bad input\r\nretry source" {
		t.Fatalf("remaining draft = %v", feedback.draft)
	}
	if want := "Строка 1 — ожидается ссылка на подписку, конфиг VLESS или мост Tor\r\nСтрока 2 — источник сохранён, загрузить ноды не удалось"; feedback.details != want {
		t.Fatalf("details = %q, want %q", feedback.details, want)
	}
}

func TestTrayAndWindowConnectionAction(t *testing.T) {
	for _, tc := range []struct {
		phase, label   string
		sources        int
		known, enabled bool
	}{
		{"disconnected", "Подключить", 1, false, false},
		{"disconnected", "Добавить источник", 0, true, true},
		{"disconnected", "Подключить", 1, true, true},
		{"requested", "Отключить", 0, true, true},
		{"stopping", "Отключаем…", 1, true, false},
		{"failed", "Подключить снова", 1, true, true},
	} {
		status := device.ControlStatus{Connection: tc.phase, Status: device.Status{Sources: tc.sources}}
		label, enabled := connectionAction(status, tc.known)
		if label != tc.label || enabled != tc.enabled {
			t.Errorf("state=%s known=%v sources=%d: action=%q/%v, want %q/%v",
				tc.phase, tc.known, tc.sources, label, enabled, tc.label, tc.enabled)
		}
	}
}
