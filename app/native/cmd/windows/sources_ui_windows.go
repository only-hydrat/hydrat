package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lxn/walk"
	ui "github.com/lxn/walk/declarative"
	"github.com/only-hydrat/hydrat/internal/device"
	"github.com/only-hydrat/hydrat/internal/refresh"
	"github.com/only-hydrat/hydrat/internal/sources"
)

type sourceView struct {
	ctx       context.Context
	workers   *sync.WaitGroup
	window    **walk.MainWindow
	app       *device.App
	inventory []device.SourceStatus
	busy      bool
	list      *walk.ListBox
	empty     *walk.TextLabel
	input     *walk.TextEdit
	hwid      *walk.LineEdit
	details   *walk.TextEdit
	result    *walk.TextLabel
	add       *walk.PushButton
	suggested *walk.PushButton
	refresh   *walk.PushButton
	remove    *walk.PushButton
	edit      *walk.PushButton
}

type sourceFeedback struct {
	summary, details string
	draft            *string
	after            func()
}

func (view *sourceView) page() ui.TabPage {
	var style walk.ListItemStyler
	if !highContrast() {
		style = sourceListStyle{view: view}
	}
	return ui.TabPage{Title: tr("Подключения"), Layout: ui.VBox{MarginsZero: true}, Children: []ui.Widget{
		ui.ScrollView{Layout: ui.VBox{Spacing: 8}, Children: []ui.Widget{
			card(tr("Источники"),
				ui.TextLabel{AssignTo: &view.empty, Name: "muted", Text: tr("Источников пока нет. Вставьте свою ссылку или добавьте бесплатные подписки."), MinSize: ui.Size{Width: 100}},
				ui.ListBox{AssignTo: &view.list, Model: []string{}, ItemStyler: style, Visible: false, MinSize: ui.Size{Height: 100}, MaxSize: ui.Size{Height: 160},
					Accessibility: ui.Accessibility{Name: tr("Добавленные источники")}, OnCurrentIndexChanged: view.syncActions,
					OnMouseUp: func(_, _ int, _ walk.MouseButton) { view.syncActions() },
					OnKeyUp:   func(walk.Key) { view.syncActions() }},
				ui.Composite{Layout: ui.HBox{MarginsZero: true}, Children: []ui.Widget{
					ui.PushButton{AssignTo: &view.refresh, MinSize: ui.Size{Width: 150, Height: 38}, Text: tr("Обновить источники"), Enabled: false, OnClicked: view.refreshSources},
					ui.PushButton{AssignTo: &view.edit, MinSize: ui.Size{Width: 130, Height: 38}, Text: tr("HWID источника"), Enabled: false, OnClicked: view.editSourceHWID},
					ui.PushButton{AssignTo: &view.remove, Name: "danger", MinSize: ui.Size{Width: 140, Height: 38}, Text: tr("Удалить источник"), Enabled: false, OnClicked: view.removeSource},
					ui.HSpacer{},
				}},
			),
			card(tr("Добавить источники"),
				ui.TextLabel{Name: "muted", Text: tr("Вставьте ссылки на подписки или конфиги, по одной на строку."), MinSize: ui.Size{Width: 120}},
				ui.TextEdit{AssignTo: &view.input, VScroll: true, MinSize: ui.Size{Height: 84}, MaxSize: ui.Size{Height: 110},
					Accessibility: ui.Accessibility{Name: tr("Ссылки на подписки или конфиги")}},
				settingRow(tr("HWID одной HTTPS-подписки"), ui.LineEdit{AssignTo: &view.hwid, MaxLength: 64, CueBanner: tr("Общий HWID"),
					Accessibility: ui.Accessibility{Name: tr("HWID одной HTTPS-подписки")}}),
				ui.Composite{Layout: ui.HBox{MarginsZero: true}, Children: []ui.Widget{
					ui.PushButton{AssignTo: &view.add, Name: "primary", MinSize: ui.Size{Width: 128, Height: 38}, Text: tr("Импортировать"), OnClicked: view.importSources},
					ui.PushButton{AssignTo: &view.suggested, MinSize: ui.Size{Width: 216, Height: 38}, Text: tr("Добавить бесплатные подписки"), OnClicked: view.importSuggested},
					ui.HSpacer{},
				}},
				ui.TextLabel{AssignTo: &view.result, Text: " ", MinSize: ui.Size{Width: 120}},
				ui.TextEdit{AssignTo: &view.details, VScroll: true, ReadOnly: true, Visible: false,
					MinSize: ui.Size{Height: 65}, MaxSize: ui.Size{Height: 92},
					Accessibility: ui.Accessibility{Name: tr("Проблемы при импорте")}},
			),
			ui.VSpacer{},
		}},
	}}
}

func (view *sourceView) syncActions() {
	if view.remove == nil || view.hwid == nil {
		return
	}
	index := view.list.CurrentIndex()
	selected := index >= 0 && index < len(view.inventory)
	view.remove.SetEnabled(!view.busy && selected)
	view.edit.SetEnabled(!view.busy && selected && canEditSourceHWID(view.inventory[index]))
	view.refresh.SetEnabled(!view.busy && len(view.inventory) > 0)
	view.add.SetEnabled(!view.busy)
	view.suggested.SetEnabled(!view.busy)
	view.hwid.SetEnabled(!view.busy)
}

func (view *sourceView) render(inventory []device.SourceStatus) {
	if !slices.Equal(view.inventory, inventory) {
		var selectedID string
		if index := view.list.CurrentIndex(); index >= 0 && index < len(view.inventory) {
			selectedID = view.inventory[index].ID
		}
		view.inventory = inventory
		_ = view.list.SetModel(sourceLabels(inventory))
		for index, item := range inventory {
			if item.ID == selectedID {
				_ = view.list.SetCurrentIndex(index)
				break
			}
		}
	}
	view.empty.SetVisible(len(inventory) == 0)
	view.list.SetVisible(len(inventory) > 0)
	view.syncActions()
}

func (view *sourceView) run(progress string, action func(context.Context) sourceFeedback) {
	if view.busy {
		return
	}
	view.busy = true
	view.syncActions()
	_ = view.input.SetReadOnly(true)
	_ = view.result.SetText(progress)
	view.details.SetVisible(false)
	view.workers.Go(func() {
		ctx, cancel := context.WithTimeout(view.ctx, 90*time.Second)
		defer cancel()
		feedback := action(ctx)
		if view.ctx.Err() != nil {
			return
		}
		(*view.window).Synchronize(func() {
			view.busy = false
			view.syncActions()
			_ = view.input.SetReadOnly(false)
			if feedback.draft != nil {
				_ = view.input.SetText(*feedback.draft)
				if *feedback.draft == "" {
					_ = view.hwid.SetText("")
				}
			}
			_ = view.result.SetText(feedback.summary)
			_ = view.details.SetText(feedback.details)
			view.details.SetVisible(feedback.details != "")
			if feedback.after != nil {
				feedback.after()
			}
		})
	})
}

func (view *sourceView) importSources() {
	input := view.input.Text()
	if strings.TrimSpace(input) == "" {
		_ = view.result.SetText(tr("Вставьте хотя бы одну ссылку или конфиг."))
		view.details.SetVisible(false)
		_ = view.input.SetFocus()
		return
	}
	hwid := view.hwid.Text()
	view.run(tr("Импортируем источники…"), func(ctx context.Context) sourceFeedback {
		report, err := view.app.ImportWithHWID(ctx, input, hwid)
		return importFeedback(input, report, err)
	})
}

func (view *sourceView) importSuggested() {
	view.run(tr("Проверяем бесплатные подписки…"), func(ctx context.Context) sourceFeedback {
		report, err := view.app.ImportSuggested(ctx)
		if err != nil {
			return sourceFeedback{summary: tr("Не удалось добавить бесплатные подписки. Повторите попытку.")}
		}
		return sourceFeedback{summary: importSummary(report)}
	})
}

func (view *sourceView) refreshSources() {
	view.run(tr("Обновляем источники…"), func(ctx context.Context) sourceFeedback {
		report, err := view.app.RefreshSources(ctx)
		if err != nil {
			return sourceFeedback{summary: tr("Обновление прервано. Повторите попытку.")}
		}
		return sourceFeedback{summary: fmt.Sprintf(tr("Обновлено: %d. Ошибок: %d."), report.Updated, report.Failed)}
	})
}

func (view *sourceView) removeSource() {
	index := view.list.CurrentIndex()
	if view.busy || index < 0 || index >= len(view.inventory) {
		return
	}
	source := view.inventory[index]
	label := sourceName(source, index)
	if walk.MsgBox(*view.window, tr("Удаление источника"), fmt.Sprintf(tr("Удалить «%s» и его ноды?"), label),
		walk.MsgBoxYesNo|walk.MsgBoxIconQuestion|walk.MsgBoxDefButton2) != walk.DlgCmdYes {
		return
	}
	view.run(tr("Удаляем источник…"), func(ctx context.Context) sourceFeedback {
		if err := view.app.RemoveSource(ctx, source.ID); err != nil {
			return sourceFeedback{summary: tr("Не удалось удалить источник.")}
		}
		return sourceFeedback{summary: tr("Источник удалён.")}
	})
}

func importFeedback(input string, report device.ImportReport, err error) sourceFeedback {
	if message := sourceHWIDError(err); message != "" {
		return sourceFeedback{summary: message}
	}
	if err != nil && len(report.LineErrors) == 0 {
		return sourceFeedback{summary: tr("Импорт прерван. Проверьте размер списка или повторите попытку.")}
	}
	lines := strings.Split(input, "\n")
	pending := make([]string, 0, len(report.LineErrors))
	messages := make([]string, 0, len(report.LineErrors))
	for _, issue := range report.LineErrors {
		if issue.Line < 1 || issue.Line > len(lines) {
			continue
		}
		pending = append(pending, strings.TrimSuffix(lines[issue.Line-1], "\r"))
		messages = append(messages, fmt.Sprintf(tr("Строка %d — %s"), len(pending), importErrorText(issue.Reason)))
	}
	draft := strings.Join(pending, "\r\n")
	return sourceFeedback{summary: importSummary(report), details: strings.Join(messages, "\r\n"), draft: &draft}
}

func canEditSourceHWID(source device.SourceStatus) bool {
	switch sources.Kind(source.Kind) {
	case sources.KindVLESSSubscription, sources.KindTorSubscription, sources.KindRemoteAuto:
		return true
	default:
		return false
	}
}

func (view *sourceView) editSourceHWID() {
	index := view.list.CurrentIndex()
	if view.busy || index < 0 || index >= len(view.inventory) || !canEditSourceHWID(view.inventory[index]) {
		return
	}
	source := view.inventory[index]
	view.run(tr("Загружаем HWID…"), func(ctx context.Context) sourceFeedback {
		value, err := view.app.SourceHWID(ctx, source.ID)
		if err != nil {
			return sourceFeedback{summary: tr("Не удалось прочитать HWID.")}
		}
		return sourceFeedback{after: func() { view.showSourceHWIDEditor(source, sourceName(source, index), value) }}
	})
}

func (view *sourceView) showSourceHWIDEditor(source device.SourceStatus, label, value string) {
	var dialog *walk.Dialog
	var input *walk.LineEdit
	var save, cancel *walk.PushButton
	var problem *walk.TextLabel
	editor := ui.Dialog{
		AssignTo: &dialog, DefaultButton: &save, CancelButton: &cancel, FixedSize: true,
		Title: tr("HWID источника"), MinSize: ui.Size{Width: 420}, Layout: ui.VBox{Spacing: 10},
		Children: []ui.Widget{
			ui.TextLabel{Text: label},
			ui.LineEdit{AssignTo: &input, Text: value, MaxLength: 64, CueBanner: tr("Общий HWID"),
				Accessibility: ui.Accessibility{Name: tr("HWID источника")}},
			settingHint(tr("Пустое поле использует общий HWID.")),
			ui.TextLabel{AssignTo: &problem, Visible: false},
			ui.Composite{Layout: ui.HBox{MarginsZero: true}, Children: []ui.Widget{
				ui.HSpacer{},
				ui.PushButton{AssignTo: &cancel, Text: tr("Отмена"), OnClicked: func() { dialog.Cancel() }},
				ui.PushButton{AssignTo: &save, Name: "primary", Text: tr("Сохранить"), OnClicked: func() {
					if _, err := refresh.NormalizeHWID(input.Text()); err != nil {
						_ = problem.SetText(sourceHWIDError(err))
						problem.SetVisible(true)
						_ = input.SetFocus()
						return
					}
					value = input.Text()
					dialog.Accept()
				}},
			}},
		},
	}
	if err := editor.Create(*view.window); err != nil {
		_ = view.result.SetText(tr("Не удалось открыть редактор HWID."))
		return
	}
	defer dialog.Dispose()
	if err := applyTheme(dialog); err != nil {
		_ = view.result.SetText(tr("Не удалось открыть редактор HWID."))
		return
	}
	if dialog.Run() != walk.DlgCmdOK {
		return
	}
	view.run(tr("Сохраняем HWID…"), func(ctx context.Context) sourceFeedback {
		report, err := view.app.SetSourceHWID(ctx, source.ID, value)
		message := sourceHWIDError(err)
		switch {
		case message != "":
			return sourceFeedback{summary: message}
		case err != nil:
			return sourceFeedback{summary: tr("Не удалось сохранить HWID.")}
		case report.Failed > 0:
			return sourceFeedback{summary: tr("HWID сохранён. Не удалось обновить источник.")}
		default:
			return sourceFeedback{summary: tr("HWID сохранён. Источник обновлён.")}
		}
	})
}

func sourceHWIDError(err error) string {
	switch {
	case errors.Is(err, refresh.ErrInvalidHWID):
		return tr("В HWID должно быть 10–64 символа: латиница, цифры, дефис или знак равенства.")
	case errors.Is(err, device.ErrSourceHWIDRequiresHTTPS):
		return tr("Отдельный HWID можно задать для одной HTTPS-подписки.")
	default:
		return ""
	}
}

func importSummary(report device.ImportReport) string {
	var items []string
	for _, item := range []struct {
		label string
		count int
	}{
		{tr("Добавлено"), report.Imported},
		{tr("Восстановлено"), report.Restored},
		{tr("Уже в списке или повторяются"), report.Skipped},
		{tr("Проблемных строк"), report.RefreshFailed + report.Unavailable},
	} {
		if item.count > 0 {
			items = append(items, fmt.Sprintf("%s: %d", item.label, item.count))
		}
	}
	if len(items) == 0 {
		return tr("Нет источников для импорта.")
	}
	return strings.Join(items, ". ") + "."
}

func importErrorText(reason string) string {
	switch reason {
	case "unsupported source format":
		return tr("ожидается ссылка на подписку, конфиг VLESS или мост Tor")
	case "invalid VLESS URI":
		return tr("проверьте ссылку VLESS")
	case "invalid subscription URL":
		return tr("проверьте адрес подписки")
	case "invalid Tor bridge line":
		return tr("проверьте строку моста Tor")
	case "unsupported Tor bridge transport":
		return tr("транспорт моста Tor не поддерживается")
	case "source refresh failed":
		return tr("источник сохранён, загрузить ноды не удалось")
	default:
		return tr("проверьте формат источника")
	}
}

func sourceName(source device.SourceStatus, index int) string {
	if source.Label == "" {
		return fmt.Sprintf(tr("Источник %d"), index+1)
	}
	return source.Label
}

func sourceLabels(inventory []device.SourceStatus) []string {
	sourceLines := make([]string, 0, len(inventory))
	for index, source := range inventory {
		label := fmt.Sprintf(tr("%s · Ноды: %d"), sourceName(source, index), source.Candidates)
		switch {
		case !source.Enabled:
			label += tr(" · отключён")
		case source.Failed:
			label += tr(" · ошибка обновления")
		case source.UpdatedAt > 0:
			label += tr(" · обновлён ") + time.Unix(source.UpdatedAt, 0).Format("02.01 15:04")
		}
		if source.CustomHWID {
			label += tr(" · свой HWID")
		}
		sourceLines = append(sourceLines, label)
	}
	return sourceLines
}

type sourceListStyle struct {
	view *sourceView
}

func (sourceListStyle) ItemHeightDependsOnWidth() bool { return false }

func (style sourceListStyle) DefaultItemHeight() int {
	if list := style.view.list; list != nil {
		return list.IntFrom96DPI(30)
	}
	return 30
}

func (style sourceListStyle) ItemHeight(int, int) int { return style.DefaultItemHeight() }

func (style sourceListStyle) StyleItem(item *walk.ListItemStyle) {
	view := style.view
	index := item.Index()
	model, ok := view.list.Model().([]string)
	if !ok || index < 0 || index >= len(model) {
		return
	}
	fill := field
	item.TextColor = textColor
	if index == view.list.CurrentIndex() {
		fill, item.TextColor = raised, accent
	}
	brush, err := walk.NewSolidColorBrush(fill)
	if err != nil {
		return
	}
	defer brush.Dispose()
	bounds := item.BoundsPixels()
	_ = item.Canvas().FillRectanglePixels(brush, bounds)
	pad := view.list.IntFrom96DPI(9)
	bounds.X += pad
	bounds.Width -= 2 * pad
	_ = item.DrawText(model[index], bounds, walk.TextVCenter|walk.TextSingleLine|walk.TextEndEllipsis|walk.TextNoPrefix)
}
