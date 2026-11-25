//go:build linux && !android

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/only-hydrat/hydrat/app/native/xraycore"
	"github.com/only-hydrat/hydrat/internal/appupdate"
	"github.com/only-hydrat/hydrat/internal/device"
	"github.com/only-hydrat/hydrat/internal/refresh"
)

const maxImportBytes = 4 << 20

type importResult struct {
	device.ImportReport
	Issues []device.ImportLineError
	Error  string
}

func newDesktopAPI(app *device.App, control *device.Control, prefs *preferences) http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("POST /sources/import", func(w http.ResponseWriter, r *http.Request) {
		input, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxImportBytes))
		if err != nil {
			fail(w, http.StatusBadRequest, "Список источников должен помещаться в 4 МБ.")
			return
		}
		report, err := app.ImportWithHWID(r.Context(), string(input), r.Header.Get("X-Hydrat-Source-HWID"))
		if rejectSourceHWID(w, err) {
			return
		}
		result := importResult{ImportReport: report, Issues: report.LineErrors}
		if err != nil && len(result.Issues) == 0 {
			result.Error = "Импорт прерван. Проверьте список и повторите попытку."
		}
		reply(w, result)
	})
	api.HandleFunc("GET /sources/{id}/hwid", func(w http.ResponseWriter, r *http.Request) {
		value, err := app.SourceHWID(r.Context(), r.PathValue("id"))
		if rejectSourceHWID(w, err) {
			return
		}
		if err != nil {
			fail(w, http.StatusInternalServerError, "Не удалось прочитать HWID.")
			return
		}
		reply(w, struct{ HWID string }{value})
	})
	api.HandleFunc("PUT /sources/{id}/hwid", func(w http.ResponseWriter, r *http.Request) {
		var value struct{ HWID *string }
		if !readSettings(w, r, &value) {
			return
		}
		if value.HWID == nil {
			fail(w, http.StatusBadRequest, "Укажите поле HWID. Его можно оставить пустым.")
			return
		}
		report, err := app.SetSourceHWID(r.Context(), r.PathValue("id"), *value.HWID)
		if rejectSourceHWID(w, err) {
			return
		}
		if err != nil {
			fail(w, http.StatusInternalServerError, "Не удалось сохранить HWID.")
			return
		}
		reply(w, report)
	})
	api.HandleFunc("POST /sources/suggested", func(w http.ResponseWriter, r *http.Request) {
		report, err := app.ImportSuggested(r.Context())
		if err != nil {
			fail(w, http.StatusBadGateway, "Не удалось получить бесплатные подписки.")
			return
		}
		reply(w, report)
	})
	api.HandleFunc("POST /sources/refresh", func(w http.ResponseWriter, r *http.Request) {
		report, err := app.RefreshSources(r.Context())
		if err != nil {
			fail(w, http.StatusBadGateway, "Обновление источников прервано.")
			return
		}
		reply(w, report)
	})
	api.HandleFunc("DELETE /sources/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := app.RemoveSource(r.Context(), r.PathValue("id")); err != nil {
			fail(w, http.StatusBadRequest, "Не удалось удалить источник.")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	api.HandleFunc("GET /settings", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, prefs.get())
	})
	api.HandleFunc("GET /updates", func(w http.ResponseWriter, r *http.Request) {
		result, err := appupdate.Check(r.Context(), appupdate.Linux)
		if err != nil {
			fail(w, http.StatusBadGateway, "Не удалось проверить обновления. Повторите попытку.")
			return
		}
		reply(w, result)
	})
	api.HandleFunc("PUT /settings", func(w http.ResponseWriter, r *http.Request) {
		var value settings
		if !readSettings(w, r, &value) {
			return
		}
		if err := prefs.set(app, value); err != nil {
			if errors.Is(err, refresh.ErrInvalidHWID) {
				fail(w, http.StatusBadRequest, "Проверьте поле HWID.")
			} else {
				fail(w, http.StatusInternalServerError, "Не удалось сохранить настройки.")
			}
			return
		}
		reply(w, prefs.get())
	})
	api.HandleFunc("GET /settings/geo", func(w http.ResponseWriter, _ *http.Request) {
		geo, err := prefs.geo()
		if err != nil {
			fail(w, http.StatusInternalServerError, "Не удалось загрузить настройки GeoIP и GeoSite.")
			return
		}
		reply(w, geo)
	})
	api.HandleFunc("PUT /settings/geo", func(w http.ResponseWriter, r *http.Request) {
		var geo xraycore.GeoSettings
		if !readSettings(w, r, &geo) {
			return
		}
		if err := prefs.setGeo(r.Context(), geo); err != nil {
			fail(w, http.StatusBadRequest, geoErrorText(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	if control != nil {
		api.Handle("/", control)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		api.ServeHTTP(w, r.WithContext(ctx))
	})
}

func rejectSourceHWID(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, refresh.ErrInvalidHWID):
		fail(w, http.StatusBadRequest, "В HWID должно быть 10–64 символа: латиница, цифры, дефис или знак равенства.")
	case errors.Is(err, device.ErrSourceHWIDRequiresHTTPS):
		fail(w, http.StatusBadRequest, "Отдельный HWID можно задать для одной HTTPS-подписки.")
	case errors.Is(err, sql.ErrNoRows):
		fail(w, http.StatusNotFound, "Источник не найден.")
	default:
		return false
	}
	return true
}

func readSettings(w http.ResponseWriter, r *http.Request, value any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		fail(w, http.StatusBadRequest, "Проверьте формат настроек.")
		return false
	}
	return true
}

func reply(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func fail(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"Error": message})
}

func geoErrorText(err error) string {
	switch err.Error() {
	case "invalid_geo_url":
		return "Укажите HTTPS-ссылки на файлы .dat."
	case "invalid_geo_tags", "missing_geo_tags":
		return "Проверьте имена групп. До 32 групп в каждом поле."
	case "geoip_download":
		return "Не удалось скачать GeoIP."
	case "geosite_download":
		return "Не удалось скачать GeoSite."
	case "geoip_groups", "geosite_groups":
		return "Проверьте файл базы и названия указанных групп."
	default:
		return "Не удалось сохранить правила."
	}
}
