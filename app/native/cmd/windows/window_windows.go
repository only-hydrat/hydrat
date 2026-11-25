package main

import (
	"context"
	"fmt"
	"image"
	_ "image/png"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lxn/walk"
	ui "github.com/lxn/walk/declarative"
	"github.com/only-hydrat/hydrat/internal/device"
	"golang.org/x/sys/windows"
)

func showWindow(parent context.Context, control *device.Control, app *device.App, prefs *preferences, iconPath, logPath string) error {
	ctx, cancel := context.WithCancel(parent)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		workers.Wait()
	}()

	var window *walk.MainWindow
	var nav *pageNavigation
	darkTheme := !highContrast()
	var primary, openLog *walk.PushButton
	var connection, hint, search *walk.TextLabel
	var routeLabels [4]*walk.Label
	var status device.ControlStatus
	var known bool
	sources := sourceView{ctx: ctx, workers: &workers, window: &window, app: app}

	applyConnection := func() {
		title, routes := presentStatus(status)
		_ = connection.SetText(title)
		if darkTheme {
			tone := textColor
			switch {
			case status.Connection == "failed":
				tone = danger
			case status.Recovering:
				tone = warning
			case status.TCP || status.UDP:
				tone = accent
			}
			connection.SetTextColor(tone)
		}
		for i, label := range routeLabels {
			_ = label.SetText(routes[i])
		}
		switch {
		case status.Connection == "stopping":
			_ = primary.SetText("Отключаем…")
		case status.Connection == "requested":
			_ = primary.SetText("Отключить")
		case status.Sources == 0:
			_ = primary.SetText("Добавить источник")
		case status.Connection == "failed":
			_ = primary.SetText("Подключить снова")
		default:
			_ = primary.SetText("Подключить")
		}
		primary.SetEnabled(known && status.Connection != "stopping")
		openLog.SetVisible(status.Connection == "failed")
		message := ""
		switch {
		case status.Connection == "failed":
			message = "Подробности сбоя сохранены в журнале Hydrat."
		case status.Sources == 0:
			message = "Добавьте подписку, конфиг VLESS или мост Tor, чтобы Hydrat мог подобрать маршрут."
		case status.Running && !status.TCP && !status.UDP && status.SearchingSeconds >= 30:
			message = "Hydrat продолжает проверять доступные ноды."
		}
		_ = hint.SetText(message)
		hint.SetVisible(message != "")
	}

	overview := ui.TabPage{Title: "Главная", Layout: ui.VBox{MarginsZero: true, Spacing: 12}, Children: []ui.Widget{
		card("",
			ui.TextLabel{AssignTo: &connection, Text: "Загружаем состояние…", Font: ui.Font{Family: "Segoe UI", PointSize: 19, Bold: true}, MinSize: ui.Size{Width: 130}},
			ui.TextLabel{AssignTo: &hint, Name: "muted", Visible: false, MinSize: ui.Size{Width: 130}},
			ui.Composite{Layout: ui.HBox{MarginsZero: true}, Children: []ui.Widget{
				ui.PushButton{AssignTo: &primary, Name: "primary", MinSize: ui.Size{Width: 155, Height: 42}, Text: "Подключить", Enabled: false, OnClicked: func() {
					switch {
					case !known || status.Connection == "stopping":
						return
					case status.Connection == "requested":
						control.Disconnect()
						status.Connection = "stopping"
					case status.Sources == 0:
						nav.show(1)
						_ = sources.input.SetFocus()
						return
					default:
						if err := control.Connect(); err != nil {
							_ = connection.SetText("Подключение пока недоступно")
							return
						}
						status.Connection = "requested"
					}
					applyConnection()
				}},
				ui.PushButton{AssignTo: &openLog, MinSize: ui.Size{Width: 134, Height: 42}, Text: "Открыть журнал", Visible: false, OnClicked: func() {
					if err := openLogFile(window, logPath); err != nil {
						walk.MsgBox(window, "Журнал Hydrat",
							`Откройте %LOCALAPPDATA%\Hydrat\hydrat.log в текстовом редакторе.`, walk.MsgBoxIconInformation)
					}
				}},
				ui.HSpacer{},
			}},
		),
		card("Маршруты",
			routeRow("TCP", &routeLabels[0]),
			routeRow("UDP", &routeLabels[1]),
			routeRow("Резерв TCP", &routeLabels[2]),
			routeRow("Резерв UDP", &routeLabels[3]),
			ui.TextLabel{AssignTo: &search, Name: "muted", Text: "Загружаем состояние…", MinSize: ui.Size{Width: 120}},
		),
		ui.VSpacer{},
	}}
	geoSettings, err := prefs.geo()
	if err != nil {
		return err
	}
	settings := settingsPage(ctx, &workers, &window, app, prefs, geoSettings)
	logo, err := walk.NewIconFromFileWithSize(filepath.Join(filepath.Dir(iconPath), "hydrat.ico"), walk.Size{Width: 32, Height: 32})
	if err != nil {
		return fmt.Errorf("загрузка значка Hydrat: %w", err)
	}
	defer logo.Dispose()
	var navigation ui.Composite
	nav, navigation = newPageNavigation([]ui.Widget{
		ui.ImageView{Image: logo, Mode: ui.ImageViewModeIdeal, MinSize: ui.Size{Width: 32, Height: 32}, MaxSize: ui.Size{Width: 32, Height: 32}},
		ui.Label{Text: "Hydrat", Font: ui.Font{Family: "Segoe UI", PointSize: 16, Bold: true}},
		ui.HSpacer{Size: 10},
	}, overview, sources.page(), settings)
	definition := ui.MainWindow{
		AssignTo: &window,
		Title:    "Hydrat",
		Size:     ui.Size{Width: 760, Height: 665},
		MinSize:  ui.Size{Width: 520, Height: 425},
		Font:     ui.Font{Family: "Segoe UI", PointSize: 10},
		Layout:   ui.VBox{Margins: ui.Margins{Left: 18, Top: 16, Right: 18, Bottom: 14}, Spacing: 14},
		Children: []ui.Widget{navigation},
	}
	if err := definition.Create(); err != nil {
		return err
	}
	if err := applyTheme(window); err != nil {
		return err
	}
	if cleanup, err := addTray(window, iconPath); err == nil {
		defer cleanup()
	} else {
		log.Printf("notification area: %v", err)
	}

	workers.Go(func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			pollCtx, stop := context.WithTimeout(ctx, time.Second)
			next, err := control.Snapshot(pollCtx)
			stop()
			window.Synchronize(func() {
				if err != nil {
					_ = search.SetText("Состояние временно недоступно")
					return
				}
				status, known = next, true
				applyConnection()
				sources.render(status.Inventory)
				_ = search.SetText(searchText(status))
			})
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return
			}
		}
	})
	window.Run()
	return nil
}

func openLogFile(owner *walk.MainWindow, path string) error {
	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	program, err := windows.UTF16PtrFromString(filepath.Join(systemDir, "notepad.exe"))
	if err != nil {
		return err
	}
	args, err := windows.UTF16PtrFromString(syscall.EscapeArg(path))
	if err != nil {
		return err
	}
	return windows.ShellExecute(windows.Handle(owner.Handle()), nil, program, args, nil, windows.SW_SHOWNORMAL)
}

func routeRow(role string, label **walk.Label) ui.Composite {
	return ui.Composite{Layout: ui.HBox{MarginsZero: true, Spacing: 16}, Children: []ui.Widget{
		ui.Label{Text: role, Name: "muted", MinSize: ui.Size{Width: 105}},
		ui.Label{AssignTo: label, Text: "Маршрут не выбран", EllipsisMode: ui.EllipsisEnd},
		ui.HSpacer{},
	}}
}

func presentStatus(status device.ControlStatus) (string, [4]string) {
	connection := "VPN отключён"
	switch {
	case status.Connection == "failed":
		connection = "Не удалось запустить VPN"
	case status.Connection == "stopping":
		connection = "Отключаем VPN…"
	case status.Recovering:
		connection = "Восстанавливаем подключение…"
	case status.TCP && status.UDP:
		connection = "VPN подключён"
	case status.TCP:
		connection = "VPN подключён · UDP недоступен"
	case status.UDP:
		connection = "VPN подключён · TCP недоступен"
	case status.Sources == 0:
		connection = "Добавьте источник"
	case status.Connection == "requested" && status.Running && status.SearchingSeconds >= 30:
		connection = "Рабочий маршрут пока не найден"
	case status.Connection == "requested" && status.Running:
		connection = "Подбираем маршрут…"
	case status.Connection == "requested":
		connection = "Запускаем VPN…"
	}

	missing := map[string]string{
		"tcp": "Маршрут не выбран", "udp": "Маршрут не выбран",
		"tcp_reserve": reserveText(status.TCPReserveStatus), "udp_reserve": reserveText(status.UDPReserveStatus),
	}
	for _, node := range status.Nodes {
		label := node.Label
		if label == "" {
			label = "Маршрут"
		}
		if node.Protocol != "" {
			label += " · " + strings.ToUpper(node.Protocol)
		}
		if node.LatencyMS > 0 {
			label += fmt.Sprintf(" · %.0f мс", node.LatencyMS)
		}
		if node.ThroughputMbps > 0 {
			label += fmt.Sprintf(" · %.1f Мбит/с", node.ThroughputMbps)
		}
		if node.State == "unavailable" {
			label += " · сбой"
		}
		missing[node.Role] = label
	}
	return connection, [4]string{missing["tcp"], missing["udp"], missing["tcp_reserve"], missing["udp_reserve"]}
}

func reserveText(state string) string {
	if state == "checking" {
		return "Проверяется"
	}
	return "Резерв не выбран"
}

func searchText(status device.ControlStatus) string {
	if !status.Running {
		return fmt.Sprintf("Нод в каталоге: %d", status.Candidates)
	}
	phase := "Ожидаем следующего обхода"
	switch status.Search.Mode {
	case "paused":
		phase = "Фоновый поиск приостановлен"
	case "background":
		phase = fmt.Sprintf("Фоновый поиск (%d)", status.Search.Workers)
	case "search":
		phase = fmt.Sprintf("Ищем маршрут (%d)", status.Search.Workers)
	}
	return fmt.Sprintf("%s · Проверено %d/%d · Готово %d · Сохранено %d",
		phase, status.Checked, status.Candidates, status.Qualified, status.Saved)
}

func addTray(window *walk.MainWindow, iconPath string) (func(), error) {
	file, err := os.Open(iconPath)
	if err != nil {
		return nil, err
	}
	picture, _, err := image.Decode(file)
	_ = file.Close()
	if err != nil {
		return nil, err
	}
	icon, err := walk.NewIconFromImage(picture)
	if err != nil {
		return nil, err
	}
	tray, err := walk.NewNotifyIcon(window)
	if err != nil {
		icon.Dispose()
		return nil, err
	}
	cleanup := func() { _ = tray.Dispose(); icon.Dispose() }
	if err := tray.SetIcon(icon); err != nil {
		cleanup()
		return nil, err
	}
	window.SetIcon(icon)
	_ = tray.SetToolTip("Hydrat")
	open := func() { window.Show(); _ = window.Activate() }
	tray.MouseUp().Attach(func(_, _ int, button walk.MouseButton) {
		if button == walk.LeftButton {
			open()
		}
	})
	var exit bool
	for _, item := range []struct {
		title string
		run   func()
	}{
		{"Открыть Hydrat", open},
		{"Выход", func() { exit = true; _ = window.Close() }},
	} {
		action := walk.NewAction()
		_ = action.SetText(item.title)
		action.Triggered().Attach(item.run)
		if err := tray.ContextMenu().Actions().Add(action); err != nil {
			cleanup()
			return nil, err
		}
	}
	if err := tray.SetVisible(true); err != nil {
		cleanup()
		return nil, err
	}
	window.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		if !exit && reason == walk.CloseReasonUser {
			*canceled = true
			window.Hide()
		}
	})
	return cleanup, nil
}
