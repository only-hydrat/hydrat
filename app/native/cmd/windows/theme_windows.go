package main

import (
	"sync"
	"unsafe"

	"github.com/lxn/walk"
	ui "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
)

// Hydrat's portal colors, paired with the mobile app's mint accent and spacing.
var (
	background = walk.RGB(11, 18, 16)
	panel      = walk.RGB(17, 28, 24)
	raised     = walk.RGB(25, 40, 32)
	field      = walk.RGB(13, 23, 18)
	line       = walk.RGB(68, 91, 77)
	textColor  = walk.RGB(236, 242, 238)
	muted      = walk.RGB(162, 180, 168)
	accent     = walk.RGB(125, 226, 173)
	accentHot  = walk.RGB(154, 234, 192)
	ink        = walk.RGB(16, 39, 25)
	danger     = walk.RGB(255, 154, 154)
	warning    = walk.RGB(237, 204, 136)
)

type pageNavigation struct {
	current int
	buttons []*walk.PushButton
	pages   []*walk.Composite
}

func newPageNavigation(header []ui.Widget, pages ...ui.TabPage) (*pageNavigation, ui.Composite) {
	nav := &pageNavigation{buttons: make([]*walk.PushButton, len(pages)), pages: make([]*walk.Composite, len(pages))}
	buttons := header
	var content []ui.Widget
	for index, page := range pages {
		name := "navigation"
		size := ui.Size{Height: 36}
		if page.Title == "GeoIP / GeoSite" {
			size.Width = 120
		}
		if index == 0 {
			name = "navigation-selected"
		}
		buttons = append(buttons, ui.PushButton{
			AssignTo: &nav.buttons[index], Name: name, Text: page.Title,
			MinSize: size, OnClicked: func() { nav.show(index) },
		})
		content = append(content, ui.Composite{
			AssignTo: &nav.pages[index], Visible: index == 0,
			Layout: page.Layout, Children: page.Children,
		})
	}
	buttons = append(buttons, ui.HSpacer{})
	return nav, ui.Composite{Layout: ui.VBox{MarginsZero: true, Spacing: 12}, Children: append([]ui.Widget{
		ui.Composite{MinSize: ui.Size{Height: 42}, MaxSize: ui.Size{Height: 42},
			Layout: ui.HBox{MarginsZero: true, Spacing: 8, Alignment: ui.AlignHNearVCenter}, Children: buttons},
	}, content...)}
}

func (nav *pageNavigation) show(index int) {
	if index == nav.current {
		return
	}
	nav.pages[nav.current].SetVisible(false)
	nav.buttons[nav.current].SetName("navigation")
	_ = nav.buttons[nav.current].Invalidate()
	nav.current = index
	nav.pages[index].SetVisible(true)
	nav.buttons[index].SetName("navigation-selected")
	_ = nav.buttons[index].Invalidate()
}

func card(title string, children ...ui.Widget) ui.Composite {
	if title != "" {
		children = append([]ui.Widget{ui.Label{Text: title, Font: ui.Font{Family: "Segoe UI", PointSize: 12, Bold: true}}}, children...)
	}
	return ui.Composite{
		Name:     "panel",
		Layout:   ui.VBox{Margins: ui.Margins{Left: 16, Top: 14, Right: 16, Bottom: 14}, Spacing: 10},
		Children: children,
	}
}

func highContrast() bool {
	state := win.HIGHCONTRAST{CbSize: uint32(unsafe.Sizeof(win.HIGHCONTRAST{}))}
	return win.SystemParametersInfo(win.SPI_GETHIGHCONTRAST, state.CbSize, unsafe.Pointer(&state), 0) &&
		state.DwFlags&win.HCF_HIGHCONTRASTON != 0
}

const useImmersiveDarkMode = 20 // DWMWA_USE_IMMERSIVE_DARK_MODE

var themeButtons = sync.OnceValue(newButtonPainter)

func applyTheme(window walk.Form) error {
	if highContrast() {
		return nil
	}
	dark := windows.NewLazySystemDLL("dwmapi.dll").NewProc("DwmSetWindowAttribute")
	if dark.Find() == nil {
		value := int32(1)
		_, _, _ = dark.Call(uintptr(window.Handle()), useImmersiveDarkMode, uintptr(unsafe.Pointer(&value)), unsafe.Sizeof(value))
	}

	brushes := make(map[walk.Color]*walk.SolidColorBrush)
	for _, color := range []walk.Color{background, panel, field} {
		brush, err := walk.NewSolidColorBrush(color)
		if err != nil {
			return err
		}
		window.AddDisposable(brush)
		brushes[color] = brush
	}
	window.SetBackground(brushes[background])
	buttons := themeButtons()
	var apply func(walk.Container, walk.Color) error
	apply = func(container walk.Container, base walk.Color) error {
		for index := 0; index < container.Children().Len(); index++ {
			widget := container.Children().At(index)
			color := base
			switch control := widget.(type) {
			case *walk.Composite:
				if control.Name() == "panel" {
					color = panel
					control.SetBackground(brushes[color])
					roundCard(control)
				}
			case *walk.ScrollView:
				control.SetBackground(brushes[color])
			case *walk.LineEdit:
				control.SetBackground(brushes[field])
			case *walk.TextEdit:
				control.SetBackground(brushes[field])
			case *walk.NumberEdit:
				control.SetBackground(brushes[field])
			case *walk.ListBox:
				control.SetBackground(brushes[field])
			case *walk.PushButton:
				if err := buttons.attach(widget, control.Text, base, false); err != nil {
					return err
				}
			case *walk.CheckBox:
				if err := buttons.attach(widget, control.Text, base, true); err != nil {
					return err
				}
			}
			if foreground, ok := widget.(interface{ SetTextColor(walk.Color) }); ok {
				tone := textColor
				if widget.AsWindowBase().Name() == "muted" {
					tone = muted
				}
				foreground.SetTextColor(tone)
			}
			if child, ok := widget.(walk.Container); ok {
				if err := apply(child, color); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return apply(window, background)
}

type buttonPainter struct {
	setSubclass *windows.LazyProc
	callback    uintptr
	controls    map[win.HWND]*paintedButton
}

type paintedButton struct {
	widget   walk.Widget
	text     func() string
	base     walk.Color
	checkBox bool
	hover    bool
}

func newButtonPainter() *buttonPainter {
	api := windows.NewLazySystemDLL("comctl32.dll")
	set := api.NewProc("SetWindowSubclass")
	next := api.NewProc("DefSubclassProc")
	remove := api.NewProc("RemoveWindowSubclass")
	painter := &buttonPainter{setSubclass: set, controls: make(map[win.HWND]*paintedButton)}
	painter.callback = windows.NewCallback(func(handle, message, wParam, lParam, id, _ uintptr) uintptr {
		hwnd := win.HWND(handle)
		control := painter.controls[hwnd]
		switch message {
		case win.WM_PAINT:
			control.paint(hwnd)
			return 0
		case win.WM_ERASEBKGND:
			return 1
		case win.WM_NCDESTROY:
			_, _, _ = remove.Call(handle, painter.callback, id)
			delete(painter.controls, hwnd)
		case win.WM_MOUSEMOVE:
			if !control.hover {
				control.hover = true
				track := win.TRACKMOUSEEVENT{CbSize: uint32(unsafe.Sizeof(win.TRACKMOUSEEVENT{})), DwFlags: win.TME_LEAVE, HwndTrack: hwnd}
				win.TrackMouseEvent(&track)
				win.InvalidateRect(hwnd, nil, false)
			}
		case win.WM_MOUSELEAVE:
			control.hover = false
			win.InvalidateRect(hwnd, nil, false)
		case win.WM_SETFOCUS, win.WM_KILLFOCUS, win.WM_ENABLE, win.WM_LBUTTONDOWN, win.WM_LBUTTONUP, win.WM_KEYDOWN, win.WM_KEYUP, win.BM_SETCHECK:
			win.InvalidateRect(hwnd, nil, false)
		}
		value, _, _ := next.Call(handle, message, wParam, lParam)
		return value
	})
	return painter
}

func (painter *buttonPainter) attach(widget walk.Widget, text func() string, base walk.Color, checkBox bool) error {
	hwnd := widget.Handle()
	painter.controls[hwnd] = &paintedButton{widget: widget, text: text, base: base, checkBox: checkBox}
	if ok, _, err := painter.setSubclass.Call(uintptr(hwnd), painter.callback, 1, 0); ok == 0 {
		delete(painter.controls, hwnd)
		return err
	}
	return nil
}

var (
	themeGDI      = windows.NewLazySystemDLL("gdi32.dll")
	setBrushColor = themeGDI.NewProc("SetDCBrushColor")
	setPenColor   = themeGDI.NewProc("SetDCPenColor")
	roundRegion   = themeGDI.NewProc("CreateRoundRectRgn")
	themeUser     = windows.NewLazySystemDLL("user32.dll")
	fillRect      = themeUser.NewProc("FillRect")
	setRegion     = themeUser.NewProc("SetWindowRgn")
)

func roundCard(card *walk.Composite) {
	var previous walk.Size
	reshape := func() {
		bounds := card.BoundsPixels()
		size := walk.Size{Width: bounds.Width, Height: bounds.Height}
		if size == previous || size.Width == 0 || size.Height == 0 {
			return
		}
		previous = size
		radius := uintptr(card.IntFrom96DPI(18))
		region, _, _ := roundRegion.Call(0, 0, uintptr(size.Width+1), uintptr(size.Height+1), radius, radius)
		if region != 0 {
			if ok, _, _ := setRegion.Call(uintptr(card.Handle()), region, 1); ok == 0 {
				win.DeleteObject(win.HGDIOBJ(region))
			}
		}
	}
	card.BoundsChanged().Attach(reshape)
	reshape()
}

func (button *paintedButton) paint(hwnd win.HWND) {
	var ps win.PAINTSTRUCT
	dc := win.BeginPaint(hwnd, &ps)
	defer win.EndPaint(hwnd, &ps)
	if dc == 0 {
		return
	}
	var bounds win.RECT
	win.GetClientRect(hwnd, &bounds)
	brush := win.GetStockObject(18) // DC_BRUSH
	pen := win.GetStockObject(19)   // DC_PEN
	oldBrush, oldPen := win.SelectObject(dc, brush), win.SelectObject(dc, pen)
	defer win.SelectObject(dc, oldBrush)
	defer win.SelectObject(dc, oldPen)
	_, _, _ = setBrushColor.Call(uintptr(dc), uintptr(button.base))
	_, _, _ = fillRect.Call(uintptr(dc), uintptr(unsafe.Pointer(&bounds)), uintptr(brush))

	const centered = win.DT_CENTER | win.DT_VCENTER | win.DT_SINGLELINE | win.DT_END_ELLIPSIS | win.DT_NOPREFIX
	foreground := textColor
	focused := win.GetFocus() == hwnd
	enabled := win.IsWindowEnabled(hwnd)
	dpi := int(win.GetDpiForWindow(hwnd))
	scale := func(value int) int32 { return int32(walk.IntFrom96DPI(value, dpi)) }
	if button.checkBox {
		bounds.Left += scale(2)
		boxSize := scale(16)
		top := (bounds.Bottom - boxSize) / 2
		box := win.RECT{Left: bounds.Left, Top: top, Right: bounds.Left + boxSize, Bottom: top + boxSize}
		checked := win.SendMessage(hwnd, win.BM_GETCHECK, 0, 0) == win.BST_CHECKED
		fill, border := field, line
		if checked {
			fill, border = accent, accent
		}
		if focused {
			border = accentHot
		}
		drawRounded(dc, box, fill, border, scale(5))
		if checked {
			_, _, _ = setPenColor.Call(uintptr(dc), uintptr(ink))
			win.MoveToEx(dc, int(box.Left+scale(4)), int(box.Top+scale(8)), nil)
			win.LineTo(dc, box.Left+scale(7), box.Top+scale(11))
			win.LineTo(dc, box.Left+scale(12), box.Top+scale(5))
		}
		bounds.Left = box.Right + scale(8)
		if !enabled {
			foreground = muted
		}
		drawButtonText(hwnd, dc, bounds, button.text(), foreground, centered&^win.DT_CENTER)
		return
	}

	fill, border := raised, line
	switch button.widget.AsWindowBase().Name() {
	case "primary":
		fill, border, foreground = accent, accent, ink
		if button.hover {
			fill, border = accentHot, accentHot
		}
	case "navigation":
		fill, border, foreground = button.base, button.base, muted
		if button.hover {
			fill, border, foreground = raised, raised, textColor
		}
	case "navigation-selected":
		fill, foreground = raised, accent
	case "danger":
		foreground = danger
	}
	if !enabled {
		fill, border, foreground = button.base, line, muted
	}
	if enabled && win.SendMessage(hwnd, win.BM_GETSTATE, 0, 0)&win.BST_PUSHED != 0 {
		border = accentHot
	}
	if focused {
		border = accent
		if fill == accent || fill == accentHot {
			border = ink
		}
	}
	drawRounded(dc, bounds, fill, border, scale(14))
	bounds.Left += scale(6)
	bounds.Right -= scale(6)
	drawButtonText(hwnd, dc, bounds, button.text(), foreground, centered)
}

func drawRounded(dc win.HDC, bounds win.RECT, fill, border walk.Color, radius int32) {
	_, _, _ = setBrushColor.Call(uintptr(dc), uintptr(fill))
	_, _, _ = setPenColor.Call(uintptr(dc), uintptr(border))
	win.RoundRect(dc, bounds.Left, bounds.Top, bounds.Right, bounds.Bottom, radius, radius)
}

func drawButtonText(hwnd win.HWND, dc win.HDC, bounds win.RECT, label string, color walk.Color, format uint32) {
	if font := win.SendMessage(hwnd, win.WM_GETFONT, 0, 0); font != 0 {
		oldFont := win.SelectObject(dc, win.HGDIOBJ(font))
		defer win.SelectObject(dc, oldFont)
	}
	if value, err := windows.UTF16PtrFromString(label); err == nil {
		win.SetBkMode(dc, win.TRANSPARENT)
		win.SetTextColor(dc, win.COLORREF(color))
		win.DrawTextEx(dc, value, -1, &bounds, format, nil)
	}
}
