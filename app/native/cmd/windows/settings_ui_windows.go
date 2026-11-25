package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/lxn/walk"
	ui "github.com/lxn/walk/declarative"
	"github.com/only-hydrat/hydrat/app/native/xraycore"
	"github.com/only-hydrat/hydrat/internal/appupdate"
	"github.com/only-hydrat/hydrat/internal/device"
	"github.com/only-hydrat/hydrat/internal/refresh"
	"golang.org/x/sys/windows"
)

const hwidHelp = "10–64 символа. Латинские буквы, цифры, дефис и знак равенства. Пустое поле включает автоматический HWID."

func settingsPage(ctx context.Context, workers *sync.WaitGroup, window **walk.MainWindow, app *device.App,
	prefs *preferences, geo xraycore.GeoSettings) ui.TabPage {
	current := prefs.load()
	dnsPreset := current.DNSPreset
	var resolvers [4]*walk.PushButton
	var resolverButtons []ui.Widget
	for i, label := range []string{"Авто", "Cloudflare", "Quad9", "Google"} {
		name := "navigation"
		if i == dnsPreset {
			name = "navigation-selected"
		}
		resolverButtons = append(resolverButtons, ui.PushButton{
			AssignTo: &resolvers[i], Name: name, Text: label, MinSize: ui.Size{Height: 34},
			OnClicked: func() {
				resolvers[dnsPreset].SetName("navigation")
				_ = resolvers[dnsPreset].Invalidate()
				dnsPreset = i
				resolvers[dnsPreset].SetName("navigation-selected")
				_ = resolvers[dnsPreset].Invalidate()
			},
		})
	}
	resolverButtons = append(resolverButtons, ui.HSpacer{})
	var geoEnabled *walk.CheckBox
	var hwid *walk.LineEdit
	var hwidError *walk.TextLabel
	var fast, background, score, interval, refreshInterval *walk.NumberEdit
	var save *walk.PushButton
	var outcome *walk.TextLabel

	settings := ui.TabPage{Title: "Общие", Layout: ui.VBox{Spacing: 9}, Children: []ui.Widget{
		ui.ScrollView{Layout: ui.VBox{Spacing: 10}, Children: []ui.Widget{
			card("Подключение",
				ui.Label{Text: "DNS-резолвер"},
				ui.Composite{Layout: ui.HBox{MarginsZero: true, Spacing: 4}, Children: resolverButtons},
				ui.CheckBox{AssignTo: &geoEnabled, Text: "Правила GeoIP и GeoSite", Checked: current.GeoRules, MinSize: ui.Size{Width: 250, Height: 24}, Alignment: ui.AlignHNearVCenter},
			),
			card("Поиск и качество",
				numericSetting("Проверок при подключении", &fast, current.FastWorkers, 1, 8, ""),
				numericSetting("Проверок в фоне", &background, current.BackgroundWorkers, 1, 8, ""),
				numericSetting("Порог качества VLESS", &score, current.MinVLESSScore, 50, 100, ""),
				numericSetting("Интервал поиска", &interval, current.BackgroundIntervalSeconds, 15, 900, " с"),
			),
			card("Подписки",
				numericSetting("Обновлять подписки каждые", &refreshInterval, current.SourceRefreshMinutes, 15, 1440, " мин"),
				settingRow("HWID для VLESS", ui.LineEdit{AssignTo: &hwid, Text: current.HWID, MaxLength: 64, CueBanner: "Автоматически",
					Accessibility: ui.Accessibility{Name: "HWID для подписок VLESS", Description: hwidHelp},
					OnTextChanged: func() {
						if hwidError != nil {
							hwidError.SetVisible(false)
						}
					}}),
				settingHint(hwidHelp),
				ui.TextLabel{AssignTo: &hwidError, Text: "Исправьте HWID или оставьте поле пустым.", Visible: false, MinSize: ui.Size{Width: 140}},
			),
			ui.VSpacer{},
		}},
		settingHint("Настройки подключения и поиска вступят в силу при следующем подключении."),
		ui.TextLabel{AssignTo: &outcome, Text: " ", MinSize: ui.Size{Width: 140}},
		ui.Composite{Layout: ui.HBox{MarginsZero: true}, Children: []ui.Widget{
			ui.HSpacer{},
			ui.PushButton{AssignTo: &save, Name: "primary", MinSize: ui.Size{Width: 158, Height: 40}, Text: "Сохранить", OnClicked: func() {
				value := connectionPreferences{
					DNSPreset: dnsPreset, GeoRules: geoEnabled.Checked(), HWID: hwid.Text(),
					MobileSettings: device.MobileSettings{
						FastWorkers: int(fast.Value()), BackgroundWorkers: int(background.Value()),
						MinVLESSScore: int(score.Value()), BackgroundIntervalSeconds: int(interval.Value()),
						SourceRefreshMinutes: int(refreshInterval.Value()),
					},
				}
				hwidError.SetVisible(false)
				completeSetting(ctx, workers, *window, save, outcome, "Сохраняем…",
					func(context.Context) error { return prefs.save(app, value) },
					func(err error) string {
						switch {
						case err == nil:
							return "Настройки сохранены."
						case errors.Is(err, refresh.ErrInvalidHWID):
							hwidError.SetVisible(true)
							_ = hwid.SetFocus()
							hwid.SetTextSelection(0, len(hwid.Text()))
							return "Проверьте поле HWID."
						default:
							return "Не удалось записать настройки. Повторите попытку."
						}
					})
			}},
		}},
	}}
	_, pages := newPageNavigation(nil, settings, geoSettingsPage(ctx, workers, window, prefs, geo),
		appUpdatesPage(ctx, workers, window))
	return ui.TabPage{Title: "Настройки", Layout: ui.VBox{MarginsZero: true}, Children: []ui.Widget{pages}}
}

func appUpdatesPage(ctx context.Context, workers *sync.WaitGroup, window **walk.MainWindow) ui.TabPage {
	var status *walk.TextLabel
	var check, download *walk.PushButton
	var downloadURL string
	return ui.TabPage{Title: "Обновления", Layout: ui.VBox{Spacing: 10}, Children: []ui.Widget{
		card("Обновления",
			ui.TextLabel{Text: "Установлена версия " + appupdate.CurrentVersion()},
			ui.TextLabel{AssignTo: &status, MinSize: ui.Size{Width: 140}},
			ui.Composite{Layout: ui.HBox{MarginsZero: true}, Children: []ui.Widget{
				ui.PushButton{AssignTo: &check, Text: "Проверить обновления", MinSize: ui.Size{Width: 160, Height: 38}, OnClicked: func() {
					download.SetVisible(false)
					var result appupdate.Result
					completeSetting(ctx, workers, *window, check, status, "Проверяем обновления…", func(request context.Context) error {
						var err error
						result, err = appupdate.Check(request, appupdate.Windows)
						return err
					}, func(err error) string {
						downloadURL = result.DownloadURL
						switch {
						case err != nil:
							return "Не удалось проверить обновления. Повторите попытку."
						case downloadURL != "":
							download.SetVisible(true)
							return "Доступна версия " + result.Latest
						case result.Latest == "":
							return "Подходящих релизов пока нет."
						default:
							return "Установлена актуальная версия."
						}
					})
				}},
				ui.PushButton{AssignTo: &download, Name: "primary", Text: "Скачать MSI", Visible: false, MinSize: ui.Size{Width: 105, Height: 38}, OnClicked: func() {
					if downloadURL == "" {
						return
					}
					url, err := windows.UTF16PtrFromString(downloadURL)
					if err == nil {
						err = windows.ShellExecute(windows.Handle((*window).Handle()), nil, url, nil, nil, windows.SW_SHOWNORMAL)
					}
					if err != nil {
						_ = status.SetText("Не удалось открыть браузер.")
					}
				}},
				ui.HSpacer{},
			}},
		),
		ui.VSpacer{},
	}}
}

func settingHint(text string) ui.TextLabel {
	return ui.TextLabel{Text: text, Name: "muted", MinSize: ui.Size{Width: 140}}
}

func settingRow(label string, widget ui.Widget) ui.Composite {
	return ui.Composite{Layout: ui.HBox{MarginsZero: true}, Children: []ui.Widget{
		ui.TextLabel{Text: label, Name: "muted", MinSize: ui.Size{Width: 172}, MaxSize: ui.Size{Width: 200}}, widget,
	}}
}

func numericSetting(label string, field **walk.NumberEdit, value, minimum, maximum int, suffix string) ui.Composite {
	return ui.Composite{Layout: ui.HBox{MarginsZero: true}, Children: []ui.Widget{
		ui.TextLabel{Text: label, Name: "muted", MinSize: ui.Size{Width: 172}, MaxSize: ui.Size{Width: 200}},
		ui.NumberEdit{AssignTo: field, MinSize: ui.Size{Width: 95}, MaxSize: ui.Size{Width: 108}, Accessibility: ui.Accessibility{Name: label},
			MinValue: float64(minimum), MaxValue: float64(maximum), Value: float64(value), Suffix: suffix, SpinButtonsVisible: false},
		ui.HSpacer{},
	}}
}

func geoSettingsPage(ctx context.Context, workers *sync.WaitGroup, window **walk.MainWindow, prefs *preferences,
	geo xraycore.GeoSettings) ui.TabPage {
	var ipURL, siteURL, ipTunnel, ipDirect, siteTunnel, siteDirect *walk.LineEdit
	var save *walk.PushButton
	var outcome *walk.TextLabel
	edit := func(label, value, placeholder string, input **walk.LineEdit) ui.Widget {
		return settingRow(label, ui.LineEdit{AssignTo: input, Text: value, CueBanner: placeholder, MaxLength: 4096,
			Accessibility: ui.Accessibility{Name: label}})
	}
	return ui.TabPage{Title: "GeoIP / GeoSite", Layout: ui.VBox{Spacing: 9}, Children: []ui.Widget{
		ui.ScrollView{Layout: ui.VBox{Spacing: 10}, Children: []ui.Widget{
			card("Базы",
				settingHint("Укажите HTTPS-ссылки на файлы .dat. Пустые поля используют базы из приложения."),
				edit("Ссылка на GeoIP", geo.IPURL, "Встроенная база", &ipURL),
				edit("Ссылка на GeoSite", geo.SiteURL, "Встроенная база", &siteURL),
			),
			card("Правила маршрутизации",
				settingHint("Укажите группы через запятую. Правила VPN имеют приоритет."),
				edit("GeoIP через VPN", geo.TunnelIP, "", &ipTunnel),
				edit("GeoIP напрямую", geo.DirectIP, "", &ipDirect),
				edit("GeoSite через VPN", geo.TunnelSite, "", &siteTunnel),
				edit("GeoSite напрямую", geo.DirectSite, "", &siteDirect),
			),
			ui.VSpacer{},
		}},
		settingHint("Правила вступят в силу при следующем подключении."),
		ui.TextLabel{AssignTo: &outcome, Text: " ", MinSize: ui.Size{Width: 140}},
		ui.Composite{Layout: ui.HBox{MarginsZero: true}, Children: []ui.Widget{
			ui.HSpacer{},
			ui.PushButton{AssignTo: &save, Name: "primary", MinSize: ui.Size{Width: 158, Height: 40}, Text: "Проверить и сохранить", OnClicked: func() {
				value := xraycore.GeoSettings{
					IPURL: strings.TrimSpace(ipURL.Text()), SiteURL: strings.TrimSpace(siteURL.Text()),
					TunnelIP: ipTunnel.Text(), DirectIP: ipDirect.Text(),
					TunnelSite: siteTunnel.Text(), DirectSite: siteDirect.Text(),
				}
				completeSetting(ctx, workers, *window, save, outcome, "Проверяем базы и правила…",
					func(ctx context.Context) error { return prefs.saveGeo(ctx, value) },
					func(err error) string {
						if err != nil {
							return geoErrorText(err)
						}
						return "Правила сохранены."
					})
			}},
		}},
	}}
}

func completeSetting(ctx context.Context, workers *sync.WaitGroup, window *walk.MainWindow,
	button *walk.PushButton, label *walk.TextLabel, pending string, operation func(context.Context) error, completed func(error) string) {
	button.SetEnabled(false)
	_ = label.SetText(pending)
	workers.Go(func() {
		actionCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		err := operation(actionCtx)
		if ctx.Err() == nil {
			window.Synchronize(func() {
				button.SetEnabled(true)
				_ = label.SetText(completed(err))
			})
		}
	})
}

func geoErrorText(err error) string {
	switch err.Error() {
	case "invalid_geo_url":
		return "Укажите HTTPS-ссылки на файлы .dat."
	case "invalid_geo_tags", "missing_geo_tags":
		return "Проверьте имена групп. До 32 групп в каждом поле."
	case "geoip_download":
		return "Не удалось скачать базу GeoIP."
	case "geosite_download":
		return "Не удалось скачать базу GeoSite."
	case "geoip_groups":
		return "Проверьте файл и имена групп GeoIP."
	case "geosite_groups":
		return "Проверьте файл и имена групп GeoSite."
	default:
		return "Не удалось сохранить правила."
	}
}
