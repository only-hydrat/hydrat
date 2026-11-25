package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/lxn/walk"
	ui "github.com/lxn/walk/declarative"
	"github.com/only-hydrat/hydrat/internal/i18n"
	"golang.org/x/sys/windows"
)

const languageFile = "language"

var languageChoices = []string{"", "ru", "en", "zh-CN"}
var interfaceLanguage = "ru"

func tr(source string) string {
	return i18n.Text(interfaceLanguage, source)
}

func windowsLanguage() string {
	kernel := windows.NewLazySystemDLL("kernel32.dll")
	lang, _, _ := kernel.NewProc("GetUserDefaultUILanguage").Call()
	switch lang & 0x03ff {
	case 0x04:
		return "zh-CN"
	case 0x09:
		return "en"
	default:
		return "ru"
	}
}

func savedLanguage(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, languageFile))
	if err != nil {
		return ""
	}
	value := strings.TrimSpace(string(data))
	if !slices.Contains(languageChoices, value) {
		return ""
	}
	return value
}

func saveLanguage(dir, value string) error {
	file, err := os.CreateTemp(dir, ".language-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, err = file.WriteString(value + "\n")
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(file.Name(), filepath.Join(dir, languageFile))
}

func languagePage(dir string) ui.TabPage {
	var choice *walk.ComboBox
	var notice *walk.TextLabel
	return ui.TabPage{Title: tr("Язык"), Layout: ui.VBox{Spacing: 10}, Children: []ui.Widget{
		card(tr("Язык"),
			ui.ComboBox{
				AssignTo: &choice, Model: []string{tr("Автоматически"), "Русский", "English", "简体中文"},
				CurrentIndex: slices.Index(languageChoices, savedLanguage(dir)),
			},
			ui.TextLabel{AssignTo: &notice, MinSize: ui.Size{Width: 140}},
			ui.PushButton{Text: tr("Сохранить"), MinSize: ui.Size{Height: 36}, OnClicked: func() {
				index := choice.CurrentIndex()
				if index < 0 || index >= len(languageChoices) {
					return
				}
				message := tr("Язык изменится при следующем запуске Hydrat.")
				if err := saveLanguage(dir, languageChoices[index]); err != nil {
					message = tr("Не удалось сохранить язык.")
				}
				_ = notice.SetText(message)
			}},
		),
		ui.VSpacer{},
	}}
}
